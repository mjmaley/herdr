//! Independent, user-private JSON control for one full TUI instance.
//!
//! This is presentation control, not the server API or the frozen client codec.
//! A dedicated polling thread owns all socket IO; the TUI only receives events.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use interprocess::local_socket::{
    traits::Listener as _, traits::Stream as _, ListenerNonblockingMode,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::oneshot;

#[cfg(unix)]
use crate::ipc::LocalStream as ControlStream;
use crate::ipc::{self, LocalListener, SocketFileIdentity};
#[cfg(windows)]
use crate::platform::ClientControlStream as ControlStream;

const MAX_CONNECTIONS: usize = 8;
const MAX_REQUEST_BYTES: usize = 64 * 1024;
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(2);
const WRITE_TIMEOUT: Duration = Duration::from_secs(2);
const SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(3);
const FOCUS_TIMEOUT: Duration = Duration::from_secs(60);
const POLL_INTERVAL: Duration = Duration::from_millis(2);
const IDLE_POLL_INTERVAL: Duration = Duration::from_millis(20);

pub(crate) enum ControlCommand {
    Snapshot,
    Focus {
        machine_id: String,
        pane_id: Option<String>,
    },
}

pub(crate) struct ControlEvent {
    pub id: String,
    pub command: ControlCommand,
    pub reply: oneshot::Sender<Value>,
}

pub(crate) fn success(id: &str, result: Value) -> Value {
    json!({"id": id, "result": result})
}

pub(crate) fn error(id: &str, code: &str, message: impl Into<String>) -> Value {
    json!({"id": id, "error": {"code": code, "message": message.into()}})
}

struct OwnedSocket {
    path: PathBuf,
    identity: SocketFileIdentity,
}

impl Drop for OwnedSocket {
    fn drop(&mut self) {
        // Existing shared IPC cleanup compares inode/marker identity. Also avoid
        // following a replacement symlink to an inode that we used to own.
        match fs::symlink_metadata(&self.path) {
            Ok(metadata) if metadata.is_symlink() => return,
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => return,
            Err(err) => {
                tracing::warn!(error = %err, "failed to inspect owned client control socket");
                return;
            }
        }
        if let Err(err) = ipc::remove_socket_file_if_owned(&self.path, &self.identity) {
            tracing::warn!(error = %err, "failed to remove owned client control socket");
        }
    }
}

pub(crate) struct ControlServer {
    socket: OwnedSocket,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl ControlServer {
    pub(crate) fn start(
        dispatch: impl Fn(ControlEvent) -> bool + Send + Sync + 'static,
    ) -> io::Result<Self> {
        Self::start_in(&control_dir(), dispatch)
    }

    fn start_in(
        directory: &Path,
        dispatch: impl Fn(ControlEvent) -> bool + Send + Sync + 'static,
    ) -> io::Result<Self> {
        crate::platform::prepare_client_control_directory(directory)?;
        // Never reclaim an existing name, even if it looks stale. Every instance
        // gets its own identity and can remove only the socket it bound.
        let path = directory.join(format!("{}.sock", opaque_id()));
        let listener = ipc::bind_private_local_listener(&path)?;
        let socket = OwnedSocket {
            identity: ipc::socket_file_identity(&path)?,
            path,
        };
        ipc::restrict_socket_permissions(&socket.path, 0o600)?;
        crate::platform::validate_client_control_socket(&socket.path)?;
        listener.set_nonblocking(ListenerNonblockingMode::Both)?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread = thread::Builder::new()
            .name("client-control".into())
            .spawn(move || serve(listener, thread_stop, dispatch))?;
        Ok(Self {
            socket,
            stop,
            thread: Some(thread),
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.socket.path
    }
}

impl Drop for ControlServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn control_dir() -> PathBuf {
    crate::config::state_dir().join("client").join("control")
}

fn opaque_id() -> String {
    static NEXT_ID: AtomicUsize = AtomicUsize::new(0);
    let mut hash = Sha256::new();
    hash.update(std::process::id().to_le_bytes());
    hash.update(NEXT_ID.fetch_add(1, Ordering::Relaxed).to_le_bytes());
    hash.update(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .to_le_bytes(),
    );
    let digest = hash.finalize();
    let mut prefix = [0u8; 16];
    prefix.copy_from_slice(&digest[..16]);
    format!("{:032x}", u128::from_le_bytes(prefix))
}

pub(crate) fn discover() -> io::Result<Vec<PathBuf>> {
    discover_in(&control_dir())
}

fn discover_in(directory: &Path) -> io::Result<Vec<PathBuf>> {
    match crate::platform::validate_client_control_directory(directory) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err),
    }
    let mut paths = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let Some(id) = path.file_stem().and_then(|stem| stem.to_str()) else {
            continue;
        };
        if path.extension().and_then(|extension| extension.to_str()) != Some("sock")
            || id.len() != 32
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            continue;
        }
        match crate::platform::validate_client_control_socket(&path) {
            Ok(()) => paths.push(path),
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(_) => {} // Non-sockets, symlinks, and foreign files are never candidates.
        }
    }
    paths.sort();
    Ok(paths)
}

/// One bounded exchange. API rejections remain JSON values, not IO errors.
pub(crate) fn request(path: &Path, method: &str, params: Value) -> io::Result<Value> {
    static ACTIVE_REQUESTS: AtomicUsize = AtomicUsize::new(0);
    if ACTIVE_REQUESTS
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
            (count < MAX_CONNECTIONS).then_some(count + 1)
        })
        .is_err()
    {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "too many client control requests",
        ));
    }
    struct RequestPermit;
    impl Drop for RequestPermit {
        fn drop(&mut self) {
            ACTIVE_REQUESTS.fetch_sub(1, Ordering::AcqRel);
        }
    }
    let permit = RequestPermit;
    let id = opaque_id();
    let frame = encode_frame(
        &json!({"id": id, "method": method, "params": params}),
        MAX_REQUEST_BYTES,
    )?;
    let timeout = command_timeout(method) + READ_TIMEOUT + WRITE_TIMEOUT;
    let deadline = Instant::now() + timeout;
    let path = path.to_owned();
    let (sender, receiver) = mpsc::sync_channel(1);
    // Connecting to a full OS listen queue can itself block. Contain that IO
    // outside the caller, including on Windows, with a bounded outstanding count.
    thread::Builder::new()
        .name("client-control-request".into())
        .spawn(move || {
            let _permit = permit;
            let result = exchange(&path, &id, &frame, deadline);
            let _ = sender.send(result);
        })?;
    receiver.recv_timeout(timeout).map_err(|err| match err {
        mpsc::RecvTimeoutError::Timeout => {
            io::Error::new(io::ErrorKind::TimedOut, "client control request timed out")
        }
        mpsc::RecvTimeoutError::Disconnected => io::Error::new(
            io::ErrorKind::BrokenPipe,
            "client control request worker closed",
        ),
    })?
}

fn exchange(path: &Path, id: &str, frame: &[u8], deadline: Instant) -> io::Result<Value> {
    crate::platform::validate_client_control_socket(path)?;
    let stream = ipc::connect_local_stream(path)?;
    #[cfg(windows)]
    crate::platform::validate_client_control_peer(&stream)?;
    let mut stream = ControlStream::from(stream);
    stream.set_nonblocking(true)?;
    let mut offset = 0;
    while offset < frame.len() {
        check_deadline(deadline)?;
        match stream.write(&frame[offset..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "client control socket closed",
                ))
            }
            Ok(written) => offset += written,
            Err(err) if retryable(&err) => thread::sleep(POLL_INTERVAL),
            Err(err) => return Err(err),
        }
    }
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        check_deadline(deadline)?;
        match ipc::poll_local_stream_read_count(&mut stream, &mut buffer) {
            Ok(ipc::LocalStreamReadCount::Data(count)) => {
                if let Some(frame) = append_frame(&mut bytes, &buffer[..count], MAX_RESPONSE_BYTES)?
                {
                    let value: Value = serde_json::from_slice(&frame).map_err(invalid_data)?;
                    if value.get("id").and_then(Value::as_str) != Some(id)
                        || (value.get("result").is_some() == value.get("error").is_some())
                        || !value.is_object()
                    {
                        return Err(invalid_data("invalid client control response envelope"));
                    }
                    return Ok(value);
                }
            }
            Ok(ipc::LocalStreamReadCount::Pending) => thread::sleep(POLL_INTERVAL),
            Ok(ipc::LocalStreamReadCount::Closed) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "client control response closed before newline",
                ))
            }
            Err(err) if retryable(&err) => thread::sleep(POLL_INTERVAL),
            Err(err) => return Err(err),
        }
    }
}

fn command_timeout(method: &str) -> Duration {
    if method == "client.focus" {
        FOCUS_TIMEOUT
    } else {
        SNAPSHOT_TIMEOUT
    }
}

fn retryable(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

fn check_deadline(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "client control deadline exceeded",
        ))
    } else {
        Ok(())
    }
}

fn invalid_data(message: impl ToString) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}

fn append_frame(bytes: &mut Vec<u8>, chunk: &[u8], limit: usize) -> io::Result<Option<Vec<u8>>> {
    let newline = chunk.iter().position(|&byte| byte == b'\n');
    let length = newline.unwrap_or(chunk.len());
    if bytes.len().saturating_add(length) > limit {
        return Err(invalid_data("client control frame is too large"));
    }
    bytes.extend_from_slice(&chunk[..length]);
    Ok(newline.map(|_| std::mem::take(bytes)))
}

struct FrameWriter {
    bytes: Vec<u8>,
    limit: usize,
}

impl Write for FrameWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.bytes.len().saturating_add(bytes.len()) > self.limit {
            return Err(invalid_data("client control frame is too large"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn encode_frame(value: &Value, limit: usize) -> io::Result<Vec<u8>> {
    let mut writer = FrameWriter {
        bytes: Vec::new(),
        limit,
    };
    serde_json::to_writer(&mut writer, value).map_err(invalid_data)?;
    writer.bytes.push(b'\n');
    Ok(writer.bytes)
}

fn parse_request(frame: &[u8]) -> Result<(String, ControlCommand), Value> {
    let value: Value = serde_json::from_slice(frame)
        .map_err(|_| error("", "invalid_request", "request must be valid JSON"))?;
    let id = value.get("id").and_then(Value::as_str).unwrap_or("");
    let Some(object) = value.as_object() else {
        return Err(error(id, "invalid_request", "request must be an object"));
    };
    if id.is_empty()
        || id.len() > 256
        || object
            .keys()
            .any(|key| !matches!(key.as_str(), "id" | "method" | "params"))
    {
        return Err(error(
            id,
            "invalid_request",
            "request requires a nonempty string id (at most 256 bytes), method, and params",
        ));
    }
    let Some(method) = value.get("method").and_then(Value::as_str) else {
        return Err(error(id, "invalid_request", "method must be a string"));
    };
    if !matches!(method, "client.snapshot" | "client.focus") {
        return Err(error(
            id,
            "method_not_found",
            "unknown client control method",
        ));
    }
    let Some(params) = value.get("params").and_then(Value::as_object) else {
        return Err(error(id, "invalid_params", "params must be an object"));
    };
    let command = match method {
        "client.snapshot" if params.is_empty() => ControlCommand::Snapshot,
        "client.snapshot" => {
            return Err(error(
                id,
                "invalid_params",
                "client.snapshot accepts no parameters",
            ))
        }
        _ => {
            if params
                .keys()
                .any(|key| !matches!(key.as_str(), "machine_id" | "pane_id"))
            {
                return Err(error(
                    id,
                    "invalid_params",
                    "unknown client.focus parameter",
                ));
            }
            let Some(machine_id) = params.get("machine_id").and_then(Value::as_str) else {
                return Err(error(id, "invalid_params", "machine_id must be a string"));
            };
            let pane_id = match params.get("pane_id") {
                None => None,
                Some(Value::String(pane)) => Some(pane.clone()),
                Some(_) => {
                    return Err(error(
                        id,
                        "invalid_params",
                        "pane_id must be a string when supplied",
                    ))
                }
            };
            ControlCommand::Focus {
                machine_id: machine_id.to_owned(),
                pane_id,
            }
        }
    };
    Ok((id.to_owned(), command))
}

enum Phase {
    Reading(Vec<u8>),
    Awaiting {
        id: String,
        reply: oneshot::Receiver<Value>,
    },
    Writing {
        bytes: Vec<u8>,
        offset: usize,
    },
    // Windows must keep the pipe open while a cooperative peer reads, without
    // moving its handle into interprocess's unbounded FlushFileBuffers workers.
    #[cfg(windows)]
    Draining,
}

struct Connection {
    stream: ControlStream,
    phase: Phase,
    deadline: Instant,
}

impl Connection {
    fn respond(&mut self, id: &str, response: Value) {
        let bytes = encode_frame(&response, MAX_RESPONSE_BYTES).unwrap_or_else(|_| {
            // This fixed error is far below the frame limit and is always valid JSON.
            format!(
                "{}\n",
                error(
                    id,
                    "response_too_large",
                    "client control response exceeds limit"
                )
            )
            .into_bytes()
        });
        self.phase = Phase::Writing { bytes, offset: 0 };
        self.deadline = Instant::now() + WRITE_TIMEOUT;
    }

    /// Returns false when the connection should be dropped. Each tick performs
    /// at most one read or write; a slow peer cannot monopolize the listener.
    fn tick(&mut self, dispatch: &impl Fn(ControlEvent) -> bool) -> bool {
        if Instant::now() >= self.deadline {
            let id = match &self.phase {
                Phase::Reading(_) => String::new(),
                Phase::Awaiting { id, .. } => id.clone(),
                Phase::Writing { .. } => return false,
                #[cfg(windows)]
                Phase::Draining => return false,
            };
            self.respond(
                &id,
                error(&id, "timeout", "client control request timed out"),
            );
            return true;
        }
        match &mut self.phase {
            Phase::Reading(bytes) => {
                let mut buffer = [0u8; 8192];
                match ipc::poll_local_stream_read_count(&mut self.stream, &mut buffer) {
                    Ok(ipc::LocalStreamReadCount::Data(count)) => {
                        match append_frame(bytes, &buffer[..count], MAX_REQUEST_BYTES) {
                            Ok(Some(frame)) => match parse_request(&frame) {
                                Ok((id, command)) => {
                                    let timeout = match &command {
                                        ControlCommand::Snapshot => SNAPSHOT_TIMEOUT,
                                        ControlCommand::Focus { .. } => FOCUS_TIMEOUT,
                                    };
                                    let (sender, receiver) = oneshot::channel();
                                    if dispatch(ControlEvent {
                                        id: id.clone(),
                                        command,
                                        reply: sender,
                                    }) {
                                        self.phase = Phase::Awaiting {
                                            id,
                                            reply: receiver,
                                        };
                                        self.deadline = Instant::now() + timeout;
                                    } else {
                                        self.respond(
                                            &id,
                                            error(
                                                &id,
                                                "client_unavailable",
                                                "TUI event delivery failed",
                                            ),
                                        );
                                    }
                                }
                                Err(response) => self.respond("", response),
                            },
                            Ok(None) => {}
                            Err(_) => self.respond(
                                "",
                                error(
                                    "",
                                    "request_too_large",
                                    "client control request exceeds limit",
                                ),
                            ),
                        }
                    }
                    Ok(ipc::LocalStreamReadCount::Pending) => {}
                    Ok(ipc::LocalStreamReadCount::Closed) => return false,
                    Err(err) if retryable(&err) => {}
                    Err(_) => return false,
                }
            }
            Phase::Awaiting { id, reply } => {
                let id = id.clone();
                // The protocol has exactly one request per connection. Closing
                // or sending additional bytes cancels the TUI's reply receiver
                // rather than keeping a disconnected focus alive until expiry.
                let mut probe = [0u8; 1];
                match ipc::poll_local_stream_read_count(&mut self.stream, &mut probe) {
                    Ok(ipc::LocalStreamReadCount::Pending) => {}
                    Err(err) if retryable(&err) => {}
                    _ => return false,
                }
                match reply.try_recv() {
                    Ok(response) => self.respond(&id, response),
                    Err(oneshot::error::TryRecvError::Empty) => {}
                    Err(oneshot::error::TryRecvError::Closed) => {
                        self.respond(
                            &id,
                            error(
                                &id,
                                "client_unavailable",
                                "TUI closed without completing the request",
                            ),
                        );
                    }
                }
            }
            Phase::Writing { bytes, offset } => match self.stream.write(&bytes[*offset..]) {
                Ok(0) => return false,
                Ok(written) => {
                    *offset += written;
                    if *offset == bytes.len() {
                        #[cfg(unix)]
                        return false;
                        #[cfg(windows)]
                        {
                            self.phase = Phase::Draining;
                            self.deadline = Instant::now() + WRITE_TIMEOUT;
                        }
                    }
                }
                Err(err) if retryable(&err) => {}
                Err(_) => return false,
            },
            #[cfg(windows)]
            Phase::Draining => return self.stream.response_pending(),
        }
        true
    }
}

fn serve(listener: LocalListener, stop: Arc<AtomicBool>, dispatch: impl Fn(ControlEvent) -> bool) {
    let mut connections: Vec<Connection> = Vec::with_capacity(MAX_CONNECTIONS);
    while !stop.load(Ordering::Acquire) {
        // Bound accept work as well as retained connections, even under a flood.
        for _ in 0..MAX_CONNECTIONS {
            match listener.accept() {
                Ok(stream) if connections.len() < MAX_CONNECTIONS => {
                    let stream = ControlStream::from(stream);
                    if let Err(err) = stream.set_nonblocking(true) {
                        tracing::warn!(error = %err, "failed to configure client control connection");
                        continue;
                    }
                    connections.push(Connection {
                        stream,
                        phase: Phase::Reading(Vec::new()),
                        deadline: Instant::now() + READ_TIMEOUT,
                    });
                }
                Ok(_) => {} // Capacity is exhausted: close, never enqueue unbounded work.
                Err(err) if retryable(&err) => break,
                Err(err) => {
                    tracing::warn!(error = %err, "client control listener failed");
                    return;
                }
            }
        }
        connections.retain_mut(|connection| connection.tick(&dispatch));
        thread::sleep(if connections.is_empty() {
            IDLE_POLL_INTERVAL
        } else {
            POLL_INTERVAL
        });
    }
}

#[cfg(test)]
mod tests;
