//! Windows-only lifecycle for the private, one-exchange control transport.

use std::ops::{Deref, DerefMut};
use std::os::windows::io::OwnedHandle;

use crate::ipc::{self, LocalStream};

/// Never hands a dirty pipe to interprocess's unbounded background linger pool.
///
/// In interprocess 2.4.2, converting the unsplit named-pipe local stream to an
/// `OwnedHandle` transfers its handle using `ManuallyDrop`, bypassing
/// `RawPipeStream::drop` and its call to `linger_pool` entirely. Dropping that
/// handle closes synchronously, without calling FlushFileBuffers.
/// The control server retains completed writes until the peer disconnects or
/// its bounded drain deadline expires, so cooperative readers keep their data.
/// Every other exit (including partial writes and shutdown) closes immediately.
pub(crate) struct ClientControlStream {
    stream: Option<LocalStream>,
}

impl From<LocalStream> for ClientControlStream {
    fn from(stream: LocalStream) -> Self {
        Self {
            stream: Some(stream),
        }
    }
}

impl Deref for ClientControlStream {
    type Target = LocalStream;

    fn deref(&self) -> &Self::Target {
        self.stream
            .as_ref()
            .expect("control stream is present until drop")
    }
}

impl DerefMut for ClientControlStream {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.stream
            .as_mut()
            .expect("control stream is present until drop")
    }
}

impl ClientControlStream {
    /// A cooperative caller closes after reading its response. Retain the pipe
    /// while that reader is live, but never flush or wait in this polling step.
    pub(crate) fn response_pending(&mut self) -> bool {
        let mut probe = [0u8; 1];
        match ipc::poll_local_stream_read_count(self, &mut probe) {
            Ok(ipc::LocalStreamReadCount::Pending) => true,
            Err(err) => matches!(
                err.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
            ),
            // Extra bytes violate the one-request contract; closing/error also
            // needs no drain. The regular connection cap includes this phase.
            _ => false,
        }
    }
}

impl Drop for ClientControlStream {
    fn drop(&mut self) {
        if let Some(LocalStream::NamedPipe(pipe)) = self.stream.take() {
            drop(OwnedHandle::from(pipe));
        }
    }
}
