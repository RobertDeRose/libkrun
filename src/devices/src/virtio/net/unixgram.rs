use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::sys::socket::{
    bind, connect, getsockopt, recv, send, setsockopt, socket, sockopt, AddressFamily, MsgFlags,
    SockFlag, SockType, UnixAddr,
};
use nix::unistd::unlink;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
#[cfg(target_os = "macos")]
use std::ptr;
use std::path::PathBuf;
use std::process;
use std::sync::atomic::{AtomicU32, Ordering};

use super::backend::{ConnectError, NetBackend, ReadError, WriteError};
use super::{write_virtio_net_hdr, MAX_BUFFER_SIZE, VNET_HDR_LEN};

const VFKIT_MAGIC: [u8; 4] = *b"VFKT";

/// Per-process counter to generate unique local unixgram socket filenames.
///
/// The local socket is placed in the same directory as the peer using a short
/// PID+counter name. The peer filename always contains the machine name, so it
/// is longer than our fixed-format name for any reasonably-named machine, keeping
/// the local path within macOS's 104-byte unix socket limit.
static NET_SOCK_COUNTER: AtomicU32 = AtomicU32::new(0);

const DEFAULT_SOCKET_BUF_SIZE: usize = 7 * 1024 * 1024;

// On macOS, with UNIX datagram sockets the send buffer is not used for queuing;
// it determines the maximum frame size.
// https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/uipc_usrreq.c#L953
#[cfg(target_os = "macos")]
const SOCKET_SNDBUF: usize = MAX_BUFFER_SIZE - VNET_HDR_LEN;

#[cfg(not(target_os = "macos"))]
const SOCKET_SNDBUF: usize = DEFAULT_SOCKET_BUF_SIZE;

const SOCKET_RCVBUF: usize = DEFAULT_SOCKET_BUF_SIZE;

// The native vmnet backend uses a private socketpair. Batch only that private
// transport; krun_add_net_unixgram() retains its one-frame-per-datagram ABI.
const VMNET_BATCH_MAGIC: [u8; 8] = *b"KRUNVMN1";
const VMNET_BATCH_MAX_FRAMES: usize = 32;
const VMNET_BATCH_HEADER_LEN: usize = 12;
const VMNET_BATCH_FRAME_HEADER_LEN: usize = 4;
const VMNET_BATCH_MAX_DATAGRAM: usize = 60 * 1024;
#[cfg(target_os = "macos")]
const VMNET_RAW_SEND_BATCH: usize = 2;

#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Clone, Copy)]
struct MsgHdrX {
    msg_name: *mut libc::c_void,
    msg_namelen: libc::socklen_t,
    msg_iov: *mut libc::iovec,
    msg_iovlen: libc::c_int,
    msg_control: *mut libc::c_void,
    msg_controllen: libc::socklen_t,
    msg_flags: libc::c_int,
    msg_datalen: usize,
}

#[cfg(target_os = "macos")]
extern "C" {
    fn sendmsg_x(
        socket: libc::c_int,
        messages: *mut MsgHdrX,
        count: libc::c_uint,
        flags: libc::c_int,
    ) -> libc::ssize_t;
}

pub struct Unixgram {
    fd: OwnedFd,
    retries: u64,
    batched: bool,
    tx_batch: Vec<u8>,
    tx_count: usize,
    #[cfg(target_os = "macos")]
    tx_raw_datagrams: [Vec<u8>; VMNET_RAW_SEND_BATCH],
    #[cfg(target_os = "macos")]
    tx_raw_count: usize,
    rx_datagram: Vec<u8>,
    rx_offsets: [usize; VMNET_BATCH_MAX_FRAMES],
    rx_lengths: [usize; VMNET_BATCH_MAX_FRAMES],
    rx_count: usize,
    rx_index: usize,
}

impl Unixgram {
    /// Create the backend with a pre-established connection to the userspace network proxy.
    pub fn new(fd: OwnedFd) -> Self {
        Self::with_batching(fd, false)
    }

    /// Create the backend for libkrun's private native-vmnet socketpair.
    #[cfg(target_os = "macos")]
    pub fn new_batched(fd: OwnedFd) -> Self {
        Self::with_batching(fd, true)
    }

    fn with_batching(fd: OwnedFd, batched: bool) -> Self {
        // Ensure the socket is in non-blocking mode.
        match fcntl(&fd, FcntlArg::F_GETFL) {
            Ok(flags) => match OFlag::from_bits(flags) {
                Some(flags) => {
                    if let Err(e) = fcntl(&fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)) {
                        warn!("error switching to non-blocking: id={fd:?}, err={e}");
                    }
                }
                None => error!("invalid fd flags id={fd:?}"),
            },
            Err(e) => error!("couldn't obtain fd flags id={fd:?}, err={e}"),
        };

        #[cfg(target_os = "macos")]
        {
            // nix doesn't provide an abstraction for SO_NOSIGPIPE, fall back to libc.
            let option_value: libc::c_int = 1;
            unsafe {
                libc::setsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_NOSIGPIPE,
                    &option_value as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&option_value) as libc::socklen_t,
                )
            };
        }

        let mut tx_batch = Vec::with_capacity(VMNET_BATCH_MAX_DATAGRAM);
        tx_batch.resize(VMNET_BATCH_HEADER_LEN, 0);
        #[cfg(target_os = "macos")]
        let tx_raw_datagrams = if batched {
            [
                Vec::with_capacity(SOCKET_SNDBUF),
                Vec::with_capacity(SOCKET_SNDBUF),
            ]
        } else {
            [Vec::new(), Vec::new()]
        };
        Self {
            fd,
            retries: 0,
            batched,
            tx_batch,
            tx_count: 0,
            #[cfg(target_os = "macos")]
            tx_raw_datagrams,
            #[cfg(target_os = "macos")]
            tx_raw_count: 0,
            rx_datagram: vec![0; MAX_BUFFER_SIZE],
            rx_offsets: [0; VMNET_BATCH_MAX_FRAMES],
            rx_lengths: [0; VMNET_BATCH_MAX_FRAMES],
            rx_count: 0,
            rx_index: 0,
        }
    }

    /// Create the backend opening a connection to the userspace network proxy.
    pub fn open(path: PathBuf, send_vfkit_magic: bool) -> Result<Self, ConnectError> {
        // We cannot create a non-blocking socket on macOS here. This is done later in new().
        let fd = socket(
            AddressFamily::Unix,
            SockType::Datagram,
            SockFlag::empty(),
            None,
        )
        .map_err(ConnectError::CreateSocket)?;
        let peer_addr = UnixAddr::new(&path).map_err(ConnectError::InvalidAddress)?;
        let socket_name = format!(
            "krun-net-{}-{}.sock",
            process::id(),
            NET_SOCK_COUNTER.fetch_add(1, Ordering::Relaxed),
        );
        let local_path = std::env::temp_dir().join(&socket_name);
        let local_addr = UnixAddr::new(&local_path).map_err(ConnectError::InvalidAddress)?;
        if let Some(path) = local_addr.path() {
            _ = unlink(path);
        }
        bind(fd.as_raw_fd(), &local_addr).map_err(ConnectError::Binding)?;

        // Connect so we don't need to use the peer address again. This also
        // allows the server to remove the socket after the connection.
        connect(fd.as_raw_fd(), &peer_addr).map_err(ConnectError::Binding)?;

        if send_vfkit_magic {
            send(fd.as_raw_fd(), &VFKIT_MAGIC, MsgFlags::empty())
                .map_err(ConnectError::SendingMagic)?;
        }

        if let Err(e) = setsockopt(&fd, sockopt::SndBuf, &SOCKET_SNDBUF) {
            log::warn!("Failed to set SO_SNDBUF: {e}");
        }
        if let Err(e) = setsockopt(&fd, sockopt::RcvBuf, &SOCKET_RCVBUF) {
            log::warn!("Failed to set SO_RCVBUF: {e}");
        }

        log::debug!(
            "network proxy socket (fd {fd:?}) buffer sizes: SndBuf={:?} RcvBuf={:?}",
            getsockopt(&fd, sockopt::SndBuf),
            getsockopt(&fd, sockopt::RcvBuf)
        );

        Ok(Self::new(fd))
    }

    fn clear_tx_batch(&mut self) {
        self.tx_batch.truncate(VMNET_BATCH_HEADER_LEN);
        self.tx_count = 0;
    }

    fn finish_send(
        &mut self,
        result: Result<usize, nix::Error>,
        expected: usize,
    ) -> Result<(), WriteError> {
        match result {
            Ok(ret) if ret == expected => {
                if self.retries > 0 {
                    info!(
                        "write_frame: ENOBUFS resolved after {} retries",
                        self.retries
                    );
                    self.retries = 0;
                }
                Ok(())
            }
            Ok(_) => Err(WriteError::PartialWrite),
            // macOS returns ENOBUFS when the kernel socket buffer is full,
            // rather than blocking or returning EAGAIN on non-blocking sockets.
            Err(nix::Error::ENOBUFS) => {
                if self.retries == 0 {
                    info!("write_frame: ENOBUFS");
                }
                self.retries += 1;
                Err(WriteError::NothingWritten)
            }
            #[allow(unreachable_patterns)]
            Err(nix::Error::EAGAIN | nix::Error::EWOULDBLOCK) => {
                Err(WriteError::NothingWritten)
            }
            Err(e) => Err(WriteError::Internal(e)),
        }
    }

    fn send_datagram(&mut self, data: &[u8]) -> Result<(), WriteError> {
        let result = send(self.fd.as_raw_fd(), data, MsgFlags::empty());
        self.finish_send(result, data.len())
    }

    #[cfg(target_os = "macos")]
    fn send_raw_datagrams(&self) -> Result<usize, nix::Error> {
        let mut iovs = [
            libc::iovec {
                iov_base: ptr::null_mut(),
                iov_len: 0,
            };
            VMNET_RAW_SEND_BATCH
        ];
        let empty = MsgHdrX {
            msg_name: ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: ptr::null_mut(),
            msg_iovlen: 0,
            msg_control: ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
            msg_datalen: 0,
        };
        let mut messages = [empty; VMNET_RAW_SEND_BATCH];

        for i in 0..self.tx_raw_count {
            iovs[i].iov_base = self.tx_raw_datagrams[i].as_ptr() as *mut libc::c_void;
            iovs[i].iov_len = self.tx_raw_datagrams[i].len();
            messages[i].msg_iov = &mut iovs[i];
            messages[i].msg_iovlen = 1;
            messages[i].msg_datalen = self.tx_raw_datagrams[i].len();
        }

        loop {
            let sent = unsafe {
                sendmsg_x(
                    self.fd.as_raw_fd(),
                    messages.as_mut_ptr(),
                    self.tx_raw_count as libc::c_uint,
                    libc::MSG_DONTWAIT,
                )
            };
            if sent >= 0 {
                return Ok(sent as usize);
            }
            let error = nix::errno::Errno::last();
            if error != nix::errno::Errno::EINTR {
                return Err(error);
            }
        }
    }

    #[cfg(target_os = "macos")]
    fn consume_sent_raw_datagrams(&mut self, sent: usize) {
        let count = self.tx_raw_count;
        if sent == 0 || sent > count {
            return;
        }
        for i in 0..count - sent {
            self.tx_raw_datagrams.swap(i, i + sent);
        }
        for datagram in &mut self.tx_raw_datagrams[count - sent..count] {
            datagram.clear();
        }
        self.tx_raw_count -= sent;
    }

    #[cfg(target_os = "macos")]
    fn flush_raw_datagrams(&mut self) -> Result<(), WriteError> {
        if self.tx_raw_count == 0 {
            return Ok(());
        }

        let expected = self.tx_raw_count;
        match self.send_raw_datagrams() {
            Ok(sent) if sent == expected => {
                self.consume_sent_raw_datagrams(sent);
                if self.retries > 0 {
                    info!(
                        "write_frame: ENOBUFS resolved after {} retries",
                        self.retries
                    );
                    self.retries = 0;
                }
                Ok(())
            }
            Ok(sent) if sent < expected => {
                self.consume_sent_raw_datagrams(sent);
                Err(WriteError::NothingWritten)
            }
            Ok(_) => Err(WriteError::PartialWrite),
            Err(nix::Error::ENOBUFS) => {
                if self.retries == 0 {
                    info!("write_frame: ENOBUFS");
                }
                self.retries += 1;
                Err(WriteError::NothingWritten)
            }
            #[allow(unreachable_patterns)]
            Err(nix::Error::EAGAIN | nix::Error::EWOULDBLOCK) => {
                Err(WriteError::NothingWritten)
            }
            Err(e) => Err(WriteError::Internal(e)),
        }
    }

    #[cfg(target_os = "macos")]
    fn queue_raw_datagram(&mut self, frame: &[u8]) -> Result<(), WriteError> {
        if self.tx_raw_count == VMNET_RAW_SEND_BATCH {
            self.flush_raw_datagrams()?;
        }
        let datagram = &mut self.tx_raw_datagrams[self.tx_raw_count];
        datagram.clear();
        datagram.extend_from_slice(frame);
        self.tx_raw_count += 1;
        Ok(())
    }

    fn flush_batch(&mut self) -> Result<(), WriteError> {
        if self.tx_count == 0 {
            return Ok(());
        }

        self.tx_batch[..8].copy_from_slice(&VMNET_BATCH_MAGIC);
        self.tx_batch[8..10].copy_from_slice(&(self.tx_count as u16).to_be_bytes());
        self.tx_batch[10..12].fill(0);
        let length = self.tx_batch.len();
        let result = send(self.fd.as_raw_fd(), &self.tx_batch, MsgFlags::empty());
        let result = self.finish_send(result, length);

        if result.is_ok() {
            self.clear_tx_batch();
        }
        result
    }

    fn queue_batch_frame(&mut self, frame: &[u8]) -> Result<(), WriteError> {
        // Preserve support for unusually large frames: a raw datagram has no
        // batch-envelope overhead and matches the historical transport. Batch
        // datagrams are always <= VMNET_BATCH_MAX_DATAGRAM, so the receiver can
        // distinguish this fallback without inspecting Ethernet bytes.
        if frame.len() + VMNET_BATCH_HEADER_LEN + VMNET_BATCH_FRAME_HEADER_LEN
            > VMNET_BATCH_MAX_DATAGRAM
        {
            self.flush_batch()?;
            #[cfg(target_os = "macos")]
            return self.queue_raw_datagram(frame);
            #[cfg(not(target_os = "macos"))]
            return self.send_datagram(frame);
        }

        #[cfg(target_os = "macos")]
        self.flush_raw_datagrams()?;
        if self.tx_count == VMNET_BATCH_MAX_FRAMES
            || self.tx_batch.len() + VMNET_BATCH_FRAME_HEADER_LEN + frame.len()
                > VMNET_BATCH_MAX_DATAGRAM
        {
            self.flush_batch()?;
        }

        self.tx_batch
            .extend_from_slice(&(frame.len() as u32).to_be_bytes());
        self.tx_batch.extend_from_slice(frame);
        self.tx_count += 1;
        Ok(())
    }

    fn parse_rx_batch(&mut self, length: usize) -> bool {
        if length > VMNET_BATCH_MAX_DATAGRAM
            || length < VMNET_BATCH_HEADER_LEN + VMNET_BATCH_FRAME_HEADER_LEN
            || self.rx_datagram[..8] != VMNET_BATCH_MAGIC
        {
            return false;
        }
        let count = u16::from_be_bytes([self.rx_datagram[8], self.rx_datagram[9]]) as usize;
        if count == 0
            || count > VMNET_BATCH_MAX_FRAMES
            || self.rx_datagram[10] != 0
            || self.rx_datagram[11] != 0
        {
            return false;
        }

        let mut offset = VMNET_BATCH_HEADER_LEN;
        for i in 0..count {
            if offset + VMNET_BATCH_FRAME_HEADER_LEN > length {
                return false;
            }
            let frame_length = u32::from_be_bytes([
                self.rx_datagram[offset],
                self.rx_datagram[offset + 1],
                self.rx_datagram[offset + 2],
                self.rx_datagram[offset + 3],
            ]) as usize;
            offset += VMNET_BATCH_FRAME_HEADER_LEN;
            if frame_length == 0 || offset + frame_length > length {
                return false;
            }
            self.rx_offsets[i] = offset;
            self.rx_lengths[i] = frame_length;
            offset += frame_length;
        }
        if offset != length {
            return false;
        }
        self.rx_count = count;
        self.rx_index = 0;
        true
    }

    fn copy_next_rx_frame(&mut self, buf: &mut [u8]) -> Result<usize, ReadError> {
        let hdr_len = write_virtio_net_hdr(buf);
        let index = self.rx_index;
        let frame_length = self.rx_lengths[index];
        if frame_length > buf.len() - hdr_len {
            self.rx_count = 0;
            self.rx_index = 0;
            return Err(ReadError::Internal(nix::Error::EMSGSIZE));
        }
        let offset = self.rx_offsets[index];
        buf[hdr_len..hdr_len + frame_length]
            .copy_from_slice(&self.rx_datagram[offset..offset + frame_length]);
        self.rx_index += 1;
        if self.rx_index == self.rx_count {
            self.rx_count = 0;
            self.rx_index = 0;
        }
        Ok(hdr_len + frame_length)
    }
}

impl NetBackend for Unixgram {
    /// Try to read a frame from the proxy. If no bytes are available reports ReadError::NothingRead.
    fn read_frame(&mut self, buf: &mut [u8]) -> Result<usize, ReadError> {
        if self.batched && self.rx_index < self.rx_count {
            return self.copy_next_rx_frame(buf);
        }

        if self.batched {
            let frame_length = match recv(
                self.fd.as_raw_fd(),
                self.rx_datagram.as_mut_slice(),
                MsgFlags::empty(),
            ) {
                Ok(f) => f,
                #[allow(unreachable_patterns)]
                Err(nix::Error::EAGAIN | nix::Error::EWOULDBLOCK) => {
                    return Err(ReadError::NothingRead)
                }
                Err(e) => return Err(ReadError::Internal(e)),
            };
            if self.parse_rx_batch(frame_length) {
                return self.copy_next_rx_frame(buf);
            }
            let hdr_len = write_virtio_net_hdr(buf);
            if frame_length > buf.len() - hdr_len {
                return Err(ReadError::Internal(nix::Error::EMSGSIZE));
            }
            buf[hdr_len..hdr_len + frame_length]
                .copy_from_slice(&self.rx_datagram[..frame_length]);
            debug!("Read eth frame from proxy: {frame_length} bytes");
            return Ok(hdr_len + frame_length);
        }

        let hdr_len = write_virtio_net_hdr(buf);
        let frame_length = match recv(self.fd.as_raw_fd(), &mut buf[hdr_len..], MsgFlags::empty()) {
            Ok(f) => f,
            #[allow(unreachable_patterns)]
            Err(nix::Error::EAGAIN | nix::Error::EWOULDBLOCK) => {
                return Err(ReadError::NothingRead)
            }
            Err(e) => return Err(ReadError::Internal(e)),
        };
        debug!("Read eth frame from proxy: {frame_length} bytes");
        Ok(hdr_len + frame_length)
    }

    /// Try to write a frame to the proxy.
    fn write_frame(&mut self, hdr_len: usize, buf: &mut [u8]) -> Result<(), WriteError> {
        if self.batched {
            return self.queue_batch_frame(&buf[hdr_len..]);
        }
        let result = self.send_datagram(&buf[hdr_len..]);
        if result.is_ok() {
            debug!("Written eth frame to proxy: {} bytes", buf.len() - hdr_len);
        }
        result
    }

    fn has_unfinished_write(&self) -> bool {
        if !self.batched {
            return false;
        }
        #[cfg(target_os = "macos")]
        {
            self.tx_count > 0 || self.tx_raw_count > 0
        }
        #[cfg(not(target_os = "macos"))]
        {
            self.tx_count > 0
        }
    }

    fn try_finish_write(&mut self, _hdr_len: usize, _buf: &[u8]) -> Result<(), WriteError> {
        if self.batched {
            self.flush_batch()?;
            #[cfg(target_os = "macos")]
            self.flush_raw_datagrams()?;
        }
        Ok(())
    }

    fn flush_writes(&mut self) -> Result<(), WriteError> {
        if self.batched {
            self.flush_batch()?;
            #[cfg(target_os = "macos")]
            self.flush_raw_datagrams()?;
        }
        Ok(())
    }

    fn raw_socket_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    #[cfg(target_os = "macos")]
    fn write_retry_delay_us(&self) -> u64 {
        50
    }
}
