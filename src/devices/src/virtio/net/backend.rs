use std::io;
use std::os::fd::RawFd;
use vm_memory::{GuestAddress, GuestMemoryError, GuestMemoryMmap};

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
    /// Guest memory could not be read while preparing a frame.
    GuestMemory(GuestMemoryError),
    /// Another internal error occurred
    Internal(nix::Error),
}

pub trait NetBackend {
    fn read_frame(&mut self, buf: &mut [u8]) -> Result<usize, ReadError>;
    fn write_frame(&mut self, hdr_len: usize, buf: &mut [u8]) -> Result<(), WriteError>;
    /// Queue a frame directly from guest memory when the backend can consume
    /// descriptor fragments without first materializing a contiguous frame.
    ///
    /// Returns `Ok(true)` when the frame was consumed, or `Ok(false)` to let
    /// the worker use the normal contiguous-frame fallback.
    fn write_frame_from_guest(
        &mut self,
        _hdr_len: usize,
        _mem: &GuestMemoryMmap,
        _iovec: &[(GuestAddress, usize)],
    ) -> Result<bool, WriteError> {
        Ok(false)
    }
    fn has_unfinished_write(&self) -> bool;
    fn try_finish_write(&mut self, hdr_len: usize, buf: &[u8]) -> Result<(), WriteError>;
    fn flush_writes(&mut self) -> Result<(), WriteError> {
        Ok(())
    }
    fn raw_socket_fd(&self) -> RawFd;

    /// Delay in microseconds before retrying after NothingWritten.
    /// Returns 0 if no delay-based retry is needed (e.g. on Linux where
    /// EAGAIN + EPOLLET handles retries via writable events).
    #[allow(dead_code)]
    fn write_retry_delay_us(&self) -> u64 {
        0
    }
}
