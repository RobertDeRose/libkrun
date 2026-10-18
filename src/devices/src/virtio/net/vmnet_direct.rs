use std::os::fd::RawFd;

use super::backend::{NetBackend, ReadError, WriteError};
use super::device::VmnetDirectTx;

/// Backend for the extra TX queues of a multiqueue native vmnet device: it
/// writes frames straight to vmnet and has no socket, so it never receives.
pub struct VmnetDirect(pub VmnetDirectTx);

impl NetBackend for VmnetDirect {
    fn read_frame(&mut self, _buf: &mut [u8]) -> Result<usize, ReadError> {
        Err(ReadError::NothingRead)
    }

    fn write_frame(&mut self, _hdr_len: usize, _buf: &mut [u8]) -> Result<(), WriteError> {
        Err(WriteError::Internal(nix::Error::ENOTSUP))
    }

    fn has_unfinished_write(&self) -> bool {
        false
    }

    fn try_finish_write(&mut self, _hdr_len: usize, _buf: &[u8]) -> Result<(), WriteError> {
        Ok(())
    }

    fn raw_socket_fd(&self) -> RawFd {
        -1
    }

    fn supports_iov_write(&self) -> bool {
        true
    }

    fn supports_batch_write(&self) -> bool {
        true
    }

    fn write_frame_iov(&mut self, iovs: &[libc::iovec], frame_len: usize) -> Result<(), WriteError> {
        self.0.write(iovs, frame_len)
    }

    fn write_frames(&mut self, packets: &[super::device::VmPktDesc]) -> Result<usize, WriteError> {
        self.0.write_frames(packets)
    }

    fn write_retry_delay_us(&self) -> u64 {
        50
    }
}
