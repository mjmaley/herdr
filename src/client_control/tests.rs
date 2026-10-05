use super::*;

struct Fixture {
    directory: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        // Unix-domain names have a short platform limit; macOS's per-user
        // std::env::temp_dir() can exhaust it before the 32-byte client ID.
        #[cfg(unix)]
        let base = fs::canonicalize("/tmp").expect("canonical temporary directory");
        #[cfg(windows)]
        let base = std::env::temp_dir();
        let directory = base.join(format!("hc-{}-{}", std::process::id(), &opaque_id()[..8]));
        crate::platform::prepare_client_control_directory(&directory)
            .expect("private test directory");
        Self { directory }
    }

    fn server(
        &self,
        dispatch: impl Fn(ControlEvent) -> bool + Send + Sync + 'static,
    ) -> ControlServer {
        ControlServer::start_in(&self.directory, dispatch).expect("start control server")
    }

    fn connection(&self) -> (OwnedSocket, LocalListener, ControlStream, Connection) {
        let path = self.directory.join(format!("{}.sock", opaque_id()));
        let listener = ipc::bind_private_local_listener(&path).expect("bind private listener");
        let socket = OwnedSocket {
            identity: ipc::socket_file_identity(&path).expect("socket identity"),
            path,
        };
        ipc::restrict_socket_permissions(&socket.path, 0o600).expect("restrict socket");
        listener
            .set_nonblocking(ListenerNonblockingMode::Both)
            .expect("nonblocking listener");
        let client = connect(&socket.path);
        let deadline = Instant::now() + READ_TIMEOUT;
        let stream = loop {
            match listener.accept() {
                Ok(stream) => break stream,
                Err(err) if retryable(&err) => {
                    check_deadline(deadline).expect("accept before deadline");
                    thread::sleep(POLL_INTERVAL);
                }
                Err(err) => panic!("accept: {err}"),
            }
        };
        stream
            .set_nonblocking(true)
            .expect("nonblocking accepted stream");
        let connection = Connection {
            stream: ControlStream::from(stream),
            phase: Phase::Reading(Vec::new()),
            deadline,
        };
        (socket, listener, client, connection)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.directory).expect("remove test directory");
    }
}

fn connect(path: &Path) -> ControlStream {
    let stream = ipc::connect_local_stream(path).expect("connect test client");
    stream
        .set_nonblocking(true)
        .expect("nonblocking test client");
    ControlStream::from(stream)
}

fn write_bytes(stream: &mut ControlStream, bytes: &[u8]) {
    let deadline = Instant::now() + READ_TIMEOUT + WRITE_TIMEOUT;
    let mut offset = 0;
    while offset < bytes.len() {
        check_deadline(deadline).expect("write before deadline");
        match stream.write(&bytes[offset..]) {
            Ok(0) => panic!("test stream closed while writing"),
            Ok(count) => offset += count,
            Err(err) if retryable(&err) => thread::sleep(POLL_INTERVAL),
            Err(err) => panic!("write test request: {err}"),
        }
    }
}

fn read_response(stream: &mut ControlStream) -> io::Result<Value> {
    let deadline = Instant::now() + READ_TIMEOUT + WRITE_TIMEOUT;
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        check_deadline(deadline)?;
        match ipc::poll_local_stream_read_count(stream, &mut buffer) {
            Ok(ipc::LocalStreamReadCount::Data(count)) => {
                if let Some(frame) = append_frame(&mut bytes, &buffer[..count], MAX_RESPONSE_BYTES)?
                {
                    return serde_json::from_slice(&frame).map_err(invalid_data);
                }
            }
            Ok(ipc::LocalStreamReadCount::Pending) => thread::sleep(POLL_INTERVAL),
            Ok(ipc::LocalStreamReadCount::Closed) => {
                return Err(io::ErrorKind::UnexpectedEof.into())
            }
            Err(err) if retryable(&err) => thread::sleep(POLL_INTERVAL),
            Err(err) => return Err(err),
        }
    }
}

fn raw_request(path: &Path, bytes: &[u8]) -> Value {
    let mut stream = connect(path);
    write_bytes(&mut stream, bytes);
    read_response(&mut stream).expect("read control response")
}

fn snapshot_frame(id: &str) -> Vec<u8> {
    encode_frame(
        &json!({"id": id, "method": "client.snapshot", "params": {}}),
        MAX_REQUEST_BYTES,
    )
    .expect("encode snapshot request")
}

fn flush_connection(connection: &mut Connection) {
    let deadline = Instant::now() + WRITE_TIMEOUT;
    while connection.tick(&|_| panic!("unexpected dispatch")) {
        // Unit-level helpers leave the server-side pipe alive for the caller's
        // next read; the production loop instead retains it until disconnect.
        #[cfg(windows)]
        if matches!(connection.phase, Phase::Draining) {
            break;
        }
        check_deadline(deadline).expect("flush before deadline");
        thread::sleep(POLL_INTERVAL);
    }
}

#[test]
fn roundtrip_snapshot_and_focus_use_distinct_private_instances() {
    let fixture = Fixture::new();
    let first = fixture.server(|event| {
        let result = match event.command {
            ControlCommand::Snapshot => json!({"instance": "first"}),
            ControlCommand::Focus {
                machine_id,
                pane_id,
            } => {
                json!({"machine_id": machine_id, "pane_id": pane_id})
            }
        };
        event.reply.send(success(&event.id, result)).is_ok()
    });
    let second = fixture.server(|event| {
        event
            .reply
            .send(success(&event.id, json!({"instance": "second"})))
            .is_ok()
    });
    assert_ne!(first.path(), second.path());
    let first_id = first.path().file_stem().unwrap().to_str().unwrap();
    assert_eq!(first_id.len(), 32);
    assert!(first_id
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    assert_eq!(discover_in(&fixture.directory).unwrap().len(), 2);
    assert_eq!(
        request(first.path(), "client.snapshot", json!({})).unwrap()["result"]["instance"],
        "first"
    );
    assert_eq!(
        request(second.path(), "client.snapshot", json!({})).unwrap()["result"]["instance"],
        "second"
    );
    let response = request(
        first.path(),
        "client.focus",
        json!({"machine_id": "local", "pane_id": "pane-1"}),
    )
    .unwrap();
    assert_eq!(
        response["result"],
        json!({"machine_id": "local", "pane_id": "pane-1"})
    );
    let first_path = first.path().to_owned();
    drop(first);
    assert!(!first_path.exists());
    assert_eq!(
        discover_in(&fixture.directory).unwrap(),
        vec![second.path().to_owned()]
    );
}

#[test]
fn malformed_unknown_and_oversized_requests_never_dispatch() {
    let fixture = Fixture::new();
    let dispatched = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&dispatched);
    let server = fixture.server(move |_| {
        observed.fetch_add(1, Ordering::Relaxed);
        false
    });
    for (bytes, code) in [
        (b"not JSON\n".as_slice(), "invalid_request"),
        (b"[]\n".as_slice(), "invalid_request"),
        (b"{\"id\":\"a\",\"method\":\"missing\",\"params\":{}}\n".as_slice(), "method_not_found"),
        (b"{\"id\":\"a\",\"method\":\"client.focus\",\"params\":{\"machine_id\":\"local\",\"pane_id\":null}}\n".as_slice(), "invalid_params"),
        (b"{\"id\":\"a\",\"method\":\"client.snapshot\",\"params\":{\"unexpected\":1}}\n".as_slice(), "invalid_params"),
    ] {
        assert_eq!(raw_request(server.path(), bytes)["error"]["code"], code);
    }
    let oversized = vec![b'x'; MAX_REQUEST_BYTES + 1];
    assert_eq!(
        raw_request(server.path(), &oversized)["error"]["code"],
        "request_too_large"
    );
    assert_eq!(dispatched.load(Ordering::Relaxed), 0);
}

#[test]
fn closed_dispatch_and_dropped_reply_report_client_unavailable() {
    let fixture = Fixture::new();
    let rejected = fixture.server(|_| false);
    let dropped = fixture.server(|_| true);
    for server in [&rejected, &dropped] {
        assert_eq!(
            request(server.path(), "client.snapshot", json!({})).unwrap()["error"]["code"],
            "client_unavailable"
        );
    }
}

#[test]
fn oversized_response_is_bounded_and_bad_envelope_is_rejected() {
    let fixture = Fixture::new();
    let oversized = fixture.server(|event| {
        event
            .reply
            .send(success(
                &event.id,
                json!({"data": "x".repeat(MAX_RESPONSE_BYTES)}),
            ))
            .is_ok()
    });
    assert_eq!(
        request(oversized.path(), "client.snapshot", json!({})).unwrap()["error"]["code"],
        "response_too_large"
    );
    let wrong_id = fixture.server(|event| event.reply.send(success("wrong-id", json!({}))).is_ok());
    assert_eq!(
        request(wrong_id.path(), "client.snapshot", json!({}))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
    let both = fixture.server(|event| {
        event
            .reply
            .send(json!({"id": event.id, "result": {}, "error": {}}))
            .is_ok()
    });
    assert_eq!(
        request(both.path(), "client.snapshot", json!({}))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(
        encode_frame(
            &json!({"data": "x".repeat(MAX_REQUEST_BYTES)}),
            MAX_REQUEST_BYTES
        )
        .unwrap_err()
        .kind(),
        io::ErrorKind::InvalidData
    );
}

#[test]
fn expiry_cancels_reply_and_write_expiry_drops_connection() {
    let fixture = Fixture::new();
    let (_socket, _listener, mut client, mut connection) = fixture.connection();
    let (sender, receiver) = oneshot::channel();
    connection.phase = Phase::Awaiting {
        id: "expired".into(),
        reply: receiver,
    };
    connection.deadline = Instant::now();
    assert!(connection.tick(&|_| panic!("unexpected dispatch")));
    assert!(sender.is_closed());
    flush_connection(&mut connection);
    let response = read_response(&mut client).unwrap();
    assert_eq!(response["id"], "expired");
    assert_eq!(response["error"]["code"], "timeout");
    connection.deadline = Instant::now();
    assert!(!connection.tick(&|_| panic!("unexpected dispatch")));
}

#[test]
fn incomplete_request_expiry_reports_timeout_without_dispatch() {
    let fixture = Fixture::new();
    let (_socket, _listener, mut client, mut connection) = fixture.connection();
    connection.phase = Phase::Reading(b"{\"id\":".to_vec());
    connection.deadline = Instant::now();
    assert!(connection.tick(&|_| panic!("unexpected dispatch")));
    flush_connection(&mut connection);
    assert_eq!(
        read_response(&mut client).unwrap()["error"]["code"],
        "timeout"
    );
}

#[test]
fn disconnected_peer_cancels_pending_reply() {
    let fixture = Fixture::new();
    let (_socket, _listener, client, mut connection) = fixture.connection();
    let (sender, receiver) = oneshot::channel();
    connection.phase = Phase::Awaiting {
        id: "disconnected".into(),
        reply: receiver,
    };
    drop(client);
    let deadline = Instant::now() + READ_TIMEOUT;
    while connection.tick(&|_| panic!("unexpected dispatch")) {
        check_deadline(deadline).expect("observe disconnect before deadline");
        thread::sleep(POLL_INTERVAL);
    }
    drop(connection);
    assert!(sender.is_closed());
}

#[test]
fn pending_focus_does_not_block_snapshots_and_disconnect_cancels_it() {
    let fixture = Fixture::new();
    let (sender, receiver) = mpsc::channel();
    let server = fixture.server(move |event| match event.command {
        ControlCommand::Snapshot => event
            .reply
            .send(success(&event.id, json!({"live": true})))
            .is_ok(),
        ControlCommand::Focus { .. } => sender.send(event.reply).is_ok(),
    });
    let mut pending = connect(server.path());
    write_bytes(
        &mut pending,
        &encode_frame(
            &json!({"id": "pending", "method": "client.focus", "params": {"machine_id": "local"}}),
            MAX_REQUEST_BYTES,
        )
        .unwrap(),
    );
    let reply = receiver.recv_timeout(READ_TIMEOUT).unwrap();
    assert_eq!(
        request(server.path(), "client.snapshot", json!({})).unwrap()["result"]["live"],
        true
    );
    assert!(!reply.is_closed());
    drop(pending);
    let deadline = Instant::now() + READ_TIMEOUT;
    while !reply.is_closed() {
        check_deadline(deadline).expect("pending request cancels before deadline");
        thread::sleep(POLL_INTERVAL);
    }
}

#[test]
fn connection_cap_rejects_excess_and_drop_closes_all_pending_replies() {
    let fixture = Fixture::new();
    let (sender, receiver) = mpsc::channel();
    let server = fixture.server(move |event| sender.send(event.reply).is_ok());
    let path = server.path().to_owned();
    let mut clients = Vec::new();
    let mut replies = Vec::new();
    for index in 0..MAX_CONNECTIONS {
        let mut client = connect(&path);
        write_bytes(&mut client, &snapshot_frame(&index.to_string()));
        replies.push(receiver.recv_timeout(READ_TIMEOUT).unwrap());
        clients.push(client);
    }
    let mut excess = connect(&path);
    assert!(read_response(&mut excess).is_err_and(|err| ipc::is_connection_closed_error(&err)));
    assert!(receiver.try_recv().is_err());
    drop(server);
    assert!(!path.exists());
    assert!(replies.iter().all(oneshot::Sender::is_closed));
    drop(clients);
}

#[test]
fn frame_bounds_apply_across_chunks_and_ignore_bytes_after_first_newline() {
    let mut bytes = Vec::new();
    assert!(append_frame(&mut bytes, b"ab", 3).unwrap().is_none());
    assert_eq!(
        append_frame(&mut bytes, b"c\nignored", 3).unwrap(),
        Some(b"abc".to_vec())
    );
    assert!(bytes.is_empty());
    append_frame(&mut bytes, b"abc", 3).unwrap();
    assert_eq!(
        append_frame(&mut bytes, b"d", 3).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(
        check_deadline(Instant::now()).unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
}

#[test]
fn discovery_ignores_unrelated_files_and_missing_directory() {
    let fixture = Fixture::new();
    assert!(discover_in(&fixture.directory.join("missing"))
        .unwrap()
        .is_empty());
    fs::write(fixture.directory.join("not-an-id.sock"), b"unrelated").unwrap();
    fs::write(
        fixture.directory.join(format!("{}.txt", opaque_id())),
        b"unrelated",
    )
    .unwrap();
    assert!(discover_in(&fixture.directory).unwrap().is_empty());
}

#[cfg(unix)]
#[test]
fn unix_directory_and_socket_privacy_reject_links_public_paths_and_non_sockets() {
    use std::os::unix::fs::{symlink, MetadataExt as _, PermissionsExt as _};
    let fixture = Fixture::new();
    assert_eq!(
        fs::metadata(&fixture.directory).unwrap().mode() & 0o777,
        0o700
    );
    let server = fixture.server(|_| false);
    let path = server.path().to_owned();
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
    crate::platform::validate_client_control_socket(&path).unwrap();
    let link = fixture.directory.join(format!("{}.sock", opaque_id()));
    symlink(&path, &link).unwrap();
    assert_eq!(
        crate::platform::validate_client_control_socket(&link)
            .unwrap_err()
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    let directory_link = fixture.directory.join("directory-link");
    symlink(&fixture.directory, &directory_link).unwrap();
    assert!(crate::platform::prepare_client_control_directory(&directory_link).is_err());
    assert!(
        crate::platform::prepare_client_control_directory(&directory_link.join("child")).is_err()
    );
    let nested = fixture.directory.join("nested");
    crate::platform::prepare_client_control_directory(&nested).unwrap();
    assert!(
        crate::platform::validate_client_control_directory(&directory_link.join("nested")).is_err()
    );
    fs::set_permissions(&nested, fs::Permissions::from_mode(0o777)).unwrap();
    let private_child = nested.join("private");
    fs::create_dir(&private_child).unwrap();
    fs::set_permissions(&private_child, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(crate::platform::validate_client_control_directory(&private_child).is_err());
    fs::set_permissions(&nested, fs::Permissions::from_mode(0o700)).unwrap();
    let non_socket = fixture.directory.join(format!("{}.sock", opaque_id()));
    fs::write(&non_socket, b"not a socket").unwrap();
    fs::set_permissions(&non_socket, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(crate::platform::validate_client_control_socket(&non_socket).is_err());
    assert_eq!(discover_in(&fixture.directory).unwrap(), vec![path.clone()]);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(crate::platform::validate_client_control_socket(&path).is_err());
    assert!(discover_in(&fixture.directory).unwrap().is_empty());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(&fixture.directory, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        discover_in(&fixture.directory).unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    assert!(crate::platform::prepare_client_control_directory(&fixture.directory).is_err());
    fs::set_permissions(&fixture.directory, fs::Permissions::from_mode(0o700)).unwrap();
}

#[cfg(unix)]
#[test]
fn cleanup_preserves_replacement_socket_and_symlink() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new();
    let server = fixture.server(|_| false);
    let path = server.path().to_owned();
    fs::remove_file(&path).unwrap();
    let replacement = ipc::bind_private_local_listener(&path).unwrap();
    ipc::restrict_socket_permissions(&path, 0o600).unwrap();
    drop(server);
    assert!(path.exists());
    drop(replacement);
    fs::remove_file(&path).unwrap();
    let server = fixture.server(|_| false);
    let path = server.path().to_owned();
    let moved = fixture.directory.join("moved.sock");
    fs::rename(&path, &moved).unwrap();
    symlink(&moved, &path).unwrap();
    drop(server);
    assert!(fs::symlink_metadata(&path).unwrap().is_symlink());
    assert!(moved.exists());
}

#[cfg(unix)]
#[test]
fn unix_foreign_owners_are_rejected_when_chown_is_available() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;
    // Ownership changes require root. Exercise real metadata where available,
    // rather than pretending to manufacture another user's filesystem entry.
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let fixture = Fixture::new();
    let server = fixture.server(|_| false);
    let socket = CString::new(server.path().as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::chown(socket.as_ptr(), 1, u32::MAX) }, 0);
    assert_eq!(
        crate::platform::validate_client_control_socket(server.path())
            .unwrap_err()
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    assert_eq!(unsafe { libc::chown(socket.as_ptr(), 0, u32::MAX) }, 0);
    let directory = CString::new(fixture.directory.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::chown(directory.as_ptr(), 1, u32::MAX) }, 0);
    assert_eq!(
        crate::platform::validate_client_control_directory(&fixture.directory)
            .unwrap_err()
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    assert_eq!(unsafe { libc::chown(directory.as_ptr(), 0, u32::MAX) }, 0);
}

#[cfg(windows)]
fn assert_windows_handle_closed_after_drop(stream: ControlStream) {
    use std::os::windows::io::{AsHandle as _, AsRawHandle as _};
    use windows_sys::Win32::Foundation::{GetHandleInformation, ERROR_INVALID_HANDLE};

    let ipc::LocalStream::NamedPipe(pipe) = &*stream;
    let handle = pipe.as_handle().as_raw_handle();
    drop(stream);
    let mut flags = 0;
    // Probe immediately, before creating any replacement handle, to detect a
    // dirty handle retained by interprocess's background linger pool.
    assert_eq!(unsafe { GetHandleInformation(handle, &mut flags) }, 0);
    assert_eq!(
        io::Error::last_os_error().raw_os_error(),
        Some(ERROR_INVALID_HANDLE as i32)
    );
}

#[cfg(windows)]
#[test]
fn windows_completed_response_remains_readable_during_bounded_drain() {
    let fixture = Fixture::new();
    let (_socket, _listener, mut client, mut connection) = fixture.connection();
    connection.respond("drain", success("drain", json!({"readable": true})));
    flush_connection(&mut connection);
    assert!(matches!(connection.phase, Phase::Draining));
    assert!(connection.tick(&|_| panic!("unexpected dispatch")));
    assert_eq!(
        read_response(&mut client).unwrap()["result"]["readable"],
        true
    );
    drop(client);
    assert!(!connection.tick(&|_| panic!("unexpected dispatch")));
    assert_windows_handle_closed_after_drop(connection.stream);
}

#[cfg(windows)]
#[test]
fn windows_nonreading_completed_response_expires_without_lingering() {
    let fixture = Fixture::new();
    let (_socket, _listener, _client, mut connection) = fixture.connection();
    connection.respond("unread", success("unread", json!({"data": "unread"})));
    flush_connection(&mut connection);
    assert!(matches!(connection.phase, Phase::Draining));
    connection.deadline = Instant::now();
    assert!(!connection.tick(&|_| panic!("unexpected dispatch")));
    // The client intentionally retains its handle and never reads the response.
    // Dropping a normal dirty interprocess stream would leave this handle open.
    assert_windows_handle_closed_after_drop(connection.stream);
}

#[cfg(windows)]
#[test]
fn windows_partial_write_timeout_and_abandoned_caller_close_dirty_handles() {
    let fixture = Fixture::new();
    let (_socket, _listener, _client, mut connection) = fixture.connection();
    let bytes = encode_frame(&success("partial", json!({})), MAX_RESPONSE_BYTES).unwrap();
    // Put a real, incomplete response in the pipe before forcing write expiry.
    assert_eq!(connection.stream.write(&bytes[..1]).unwrap(), 1);
    connection.phase = Phase::Writing { bytes, offset: 1 };
    connection.deadline = Instant::now();
    assert!(!connection.tick(&|_| panic!("unexpected dispatch")));
    assert_windows_handle_closed_after_drop(connection.stream);

    // A caller that abandons a written request must likewise bypass limbo.
    let (_socket, _listener, mut client, other_connection) = fixture.connection();
    write_bytes(&mut client, &snapshot_frame("abandoned"));
    assert_windows_handle_closed_after_drop(client);
    drop(other_connection);
}

#[cfg(windows)]
#[test]
fn windows_shutdown_closes_written_responses_without_waiting_for_readers() {
    let fixture = Fixture::new();
    let (sender, receiver) = mpsc::channel();
    let server = fixture.server(move |event| {
        let sent = event
            .reply
            .send(success(&event.id, json!({"written": true})))
            .is_ok();
        sender.send(()).unwrap();
        sent
    });
    let mut client = connect(server.path());
    write_bytes(&mut client, &snapshot_frame("shutdown"));
    receiver.recv_timeout(READ_TIMEOUT).unwrap();
    // Observe available response bytes without consuming them before shutdown.
    use std::os::windows::io::{AsHandle as _, AsRawHandle as _};
    let deadline = Instant::now() + WRITE_TIMEOUT;
    let ipc::LocalStream::NamedPipe(pipe) = &*client;
    loop {
        let mut available = 0;
        let ok = unsafe {
            windows_sys::Win32::System::Pipes::PeekNamedPipe(
                pipe.as_handle().as_raw_handle(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut available,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(ok, 0);
        if available > 0 {
            break;
        }
        check_deadline(deadline).expect("response written before deadline");
        thread::sleep(POLL_INTERVAL);
    }
    drop(server);
    // A lingering dirty server stream would keep its peer open indefinitely.
    let mut probe = [0u8; 1];
    assert!(matches!(
        ipc::poll_local_stream_read_count(&mut client, &mut probe),
        Ok(ipc::LocalStreamReadCount::Closed)
    ));
}
