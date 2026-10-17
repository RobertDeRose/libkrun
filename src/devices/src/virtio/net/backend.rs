use std::io;
use std::os::fd::RawFd;

#[allow(dead_code)]
#[derive(Debug)]
pub enum ConnectError {
    InvalidAddress(nix::Error),
    CreateSocket(nix::Error),
    Binding(nix::Error),
    SendingMagic(nix::Error),
    // Tap backend errors.
    OpenNetTun(nix::Error),
    TunSetIff(io::Error),
    TunSetVnetHdrSz(io::Error),
    TunSetOffload(io::Error),
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum ReadError {
    /// Nothing was written
    NothingRead,
    /// Another internal error occurred
    Internal(nix::Error),
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum WriteError {
    /// Nothing was written, you can drop the frame or try to resend it later
    NothingWritten,
    /// Part of the buffer was written, the write has to be finished using try_finish_write
    PartialWrite,
    /// Passt doesnt seem to be running (received EPIPE)
    ProcessNotRunning,
    /// Another internal error occurred
    Internal(nix::Error),
}

pub trait NetBackend {
    fn read_frame(&mut self, buf: &mut [u8]) -> Result<usize, ReadError>;
    fn write_frame(&mut self, hdr_len: usize, buf: &mut [u8]) -> Result<(), WriteError>;
    fn has_unfinished_write(&self) -> bool;
    fn try_finish_write(&mut self, hdr_len: usize, buf: &[u8]) -> Result<(), WriteError>;
    fn flush_writes(&mut self) -> Result<(), WriteError> {
        Ok(())
    }
    fn raw_socket_fd(&self) -> RawFd;

    /// True when write_frame_iov sends frames straight from guest memory and
    /// write_frame/flush_writes are not used for TX.
    fn supports_iov_write(&self) -> bool {
        false
    }

    /// Write one frame from `iovs` (header already excluded). NothingWritten
    /// means the backend is full and the frame must be retried later.
    fn write_frame_iov(&mut self, _iovs: &[libc::iovec], _frame_len: usize) -> Result<(), WriteError> {
        Err(WriteError::Internal(nix::Error::ENOTSUP))
    }

    /// Delay in microseconds before retrying after NothingWritten.
    /// Returns 0 if no delay-based retry is needed (e.g. on Linux where
    /// EAGAIN + EPOLLET handles retries via writable events).
    #[allow(dead_code)]
    fn write_retry_delay_us(&self) -> u64 {
        0
    }
}
