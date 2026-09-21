use macros::{guest, host};
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

pub struct TestVsockHostDial;

const VSOCK_PORT: u32 = 43210;

fn stream_set_timeouts(stream: &UnixStream) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    Ok(())
}

fn stream_expect(stream: &mut UnixStream, expected: &[u8]) -> io::Result<()> {
    let mut buf = vec![0; expected.len()];
    stream.read_exact(&mut buf)?;
    if buf != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected {expected:?}, got {buf:?}"),
        ));
    }
    Ok(())
}

#[host]
mod host {
    use super::*;
    use crate::common::setup_fs_and_enter;
    use crate::{krun_call, krun_call_u32, Test, TestOutcome, TestSetup};
    use anyhow::{bail, Context};
    use krun_sys::*;
    use nix::libc;
    use std::fs;
    use std::os::fd::FromRawFd;
    use std::path::Path;
    use std::thread;
    use std::time::Instant;

    const UNUSED_VSOCK_PORT: u32 = 43211;

    fn dial_once(ctx: u32, port: u32) -> io::Result<UnixStream> {
        let fd = unsafe { krun_vsock_connect(ctx, port) };
        if fd < 0 {
            return Err(io::Error::from_raw_os_error(-fd));
        }
        Ok(unsafe { UnixStream::from_raw_fd(fd) })
    }

    fn dial_when_ready(ctx: u32, port: u32) -> anyhow::Result<UnixStream> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match dial_once(ctx, port) {
                Ok(stream) => return Ok(stream),
                Err(error)
                    if matches!(
                        error.raw_os_error(),
                        Some(libc::ENOENT)
                            | Some(libc::ENODEV)
                            | Some(libc::ECONNREFUSED)
                    ) && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(error) => return Err(error).context("initial host-to-guest vsock dial"),
            }
        }
    }

    fn validate_dial(ctx: u32, status_path: &Path) -> anyhow::Result<()> {
        let mut first = dial_when_ready(ctx, VSOCK_PORT)?;
        stream_set_timeouts(&first)?;
        first.write_all(b"host-one")?;
        stream_expect(&mut first, b"guest-one")?;
        drop(first);

        match dial_once(ctx, UNUSED_VSOCK_PORT) {
            Ok(_) => bail!("dial to unused guest port unexpectedly succeeded"),
            Err(error) if error.raw_os_error() == Some(libc::ECONNREFUSED) => {}
            Err(error) => bail!("dial to unused guest port returned {error}"),
        }

        let mut second = dial_once(ctx, VSOCK_PORT).context("second host-to-guest vsock dial")?;
        stream_set_timeouts(&second)?;
        second.write_all(b"host-two")?;
        stream_expect(&mut second, b"guest-two")?;
        second.write_all(b"done!")?;
        stream_expect(&mut second, b"ready!")?;

        fs::write(status_path, "OK\n").context("write host validation status")?;
        second.write_all(b"exit!")?;
        Ok(())
    }

    impl Test for TestVsockHostDial {
        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            unsafe {
                krun_call!(krun_set_log_level(KRUN_LOG_LEVEL_TRACE))?;
                let ctx = krun_call_u32!(krun_create_ctx())?;
                krun_call!(krun_set_vm_config(ctx, 1, 1024))?;

                let status_path = test_setup.tmp_dir.join("host-status.txt");
                thread::spawn(move || {
                    if let Err(error) = validate_dial(ctx, &status_path) {
                        let _ = fs::write(&status_path, format!("ERROR: {error:#}\n"));
                    }
                });

                setup_fs_and_enter(ctx, test_setup)?;
            }
            Ok(())
        }

        fn check(self: Box<Self>, stdout: Vec<u8>, test_setup: TestSetup) -> TestOutcome {
            let guest_output = String::from_utf8_lossy(&stdout);
            let status_path = test_setup.tmp_dir.join("host-status.txt");
            match fs::read_to_string(&status_path) {
                Ok(status) if status != "OK\n" => {
                    return TestOutcome::Fail(format!(
                        "host validation failed: {status}guest stdout: {guest_output:?}"
                    ));
                }
                Err(error) => {
                    return TestOutcome::Fail(format!(
                        "host validation status missing at {}: {error}; guest stdout: {guest_output:?}",
                        status_path.display()
                    ));
                }
                Ok(_) => {}
            }

            if guest_output != "OK\n" {
                return TestOutcome::Fail(format!(
                    "guest expected exactly {:?}, got {:?}",
                    "OK\\n", guest_output
                ));
            }

            TestOutcome::Pass
        }
    }
}

#[guest]
mod guest {
    use super::*;
    use crate::Test;
    use nix::errno::Errno;
    use nix::libc::VMADDR_CID_ANY;
    use nix::sys::socket::{
        accept, bind, listen, socket, AddressFamily, Backlog, SockFlag, SockType, VsockAddr,
    };
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::thread;
    use std::time::Instant;

    fn accept_with_timeout(listener: &OwnedFd) -> UnixStream {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match accept(listener.as_raw_fd()) {
                Ok(fd) => return unsafe { UnixStream::from_raw_fd(fd) },
                Err(Errno::EAGAIN) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(error) => panic!("vsock accept failed: {error}"),
            }
        }
    }

    impl Test for TestVsockHostDial {
        fn in_guest(self: Box<Self>) {
            let listener = socket(
                AddressFamily::Vsock,
                SockType::Stream,
                SockFlag::SOCK_NONBLOCK,
                None,
            )
            .unwrap();
            bind(
                listener.as_raw_fd(),
                &VsockAddr::new(VMADDR_CID_ANY, VSOCK_PORT),
            )
            .unwrap();
            listen(&listener, Backlog::new(4).unwrap()).unwrap();

            let mut first = accept_with_timeout(&listener);
            stream_set_timeouts(&first).unwrap();
            stream_expect(&mut first, b"host-one").unwrap();
            first.write_all(b"guest-one").unwrap();
            drop(first);

            let mut second = accept_with_timeout(&listener);
            stream_set_timeouts(&second).unwrap();
            stream_expect(&mut second, b"host-two").unwrap();
            second.write_all(b"guest-two").unwrap();
            stream_expect(&mut second, b"done!").unwrap();
            second.write_all(b"ready!").unwrap();
            stream_expect(&mut second, b"exit!").unwrap();

            println!("OK");
        }
    }
}
