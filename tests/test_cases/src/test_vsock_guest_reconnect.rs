use macros::{guest, host};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

pub struct TestVsockGuestReconnect;

const HOST_PORT: u32 = 1234;

fn stream_set_timeouts(stream: &mut UnixStream) {
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
}

#[host]
mod host {
    use super::*;

    use crate::common::setup_fs_and_enter;
    use crate::{krun_call, krun_call_u32};
    use crate::{Test, TestSetup};
    use krun_sys::*;
    use std::ffi::CString;
    use std::os::unix::net::UnixListener;
    use std::os::unix::prelude::OsStrExt;
    use std::thread;

    fn server(listener: UnixListener) {
        for _ in 0..2 {
            let (mut stream, _addr) = listener.accept().unwrap();
            stream_set_timeouts(&mut stream);
            stream.write_all(b"ping!").unwrap();

            let mut reply = [0u8; 5];
            stream.read_exact(&mut reply).unwrap();
            assert_eq!(&reply, b"pong!");

            let mut eof = [0u8; 1];
            assert_eq!(stream.read(&mut eof).unwrap(), 0);
        }
    }

    impl Test for TestVsockGuestReconnect {
        fn timeout_secs(&self) -> u64 {
            20
        }

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            let sock_path = test_setup.tmp_dir.join("test.sock");
            let sock_path_cstr = CString::new(sock_path.as_os_str().as_bytes())?;
            let listener = UnixListener::bind(&sock_path).unwrap();
            thread::spawn(move || server(listener));

            unsafe {
                krun_call!(krun_set_log_level(KRUN_LOG_LEVEL_TRACE))?;
                let ctx = krun_call_u32!(krun_create_ctx())?;
                krun_call!(krun_add_vsock_port(
                    ctx,
                    HOST_PORT,
                    sock_path_cstr.as_ptr()
                ))?;
                krun_call!(krun_set_vm_config(ctx, 1, 1024))?;
                setup_fs_and_enter(ctx, test_setup)?;
            }
            Ok(())
        }
    }
}

#[guest]
mod guest {
    use super::*;
    use crate::Test;

    use nix::libc::{VMADDR_CID_ANY, VMADDR_CID_HOST};
    use nix::sys::socket::{bind, connect, socket, AddressFamily, SockFlag, SockType, VsockAddr};
    use std::os::fd::AsRawFd;
    use std::thread;

    const GUEST_PORT: u32 = 2345;
    const REAPER_WAIT: Duration = Duration::from_secs(7);

    fn exchange() {
        let sock = socket(
            AddressFamily::Vsock,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )
        .unwrap();
        bind(
            sock.as_raw_fd(),
            &VsockAddr::new(VMADDR_CID_ANY, GUEST_PORT),
        )
        .unwrap();
        connect(
            sock.as_raw_fd(),
            &VsockAddr::new(VMADDR_CID_HOST, HOST_PORT),
        )
        .unwrap();

        let mut stream = UnixStream::from(sock);
        stream_set_timeouts(&mut stream);

        let mut request = [0u8; 5];
        stream.read_exact(&mut request).unwrap();
        assert_eq!(&request, b"ping!");
        stream.write_all(b"pong!").unwrap();
    }

    impl Test for TestVsockGuestReconnect {
        fn in_guest(self: Box<Self>) {
            exchange();
            thread::sleep(REAPER_WAIT);
            exchange();
            println!("OK");
        }
    }
}
