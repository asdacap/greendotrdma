//! `greendotctl pipe [socket]`: relay stdio to the daemon's unix socket — the
//! SSH forced command through which the Kubernetes CSI controller drives the
//! daemon. gRPC/h2 runs end-to-end over the SSH channel; the daemon authorizes
//! *this* process's uid via SO_PEERCRED (the SSH login user, a member of the
//! `greendot` group), so the socket is never exposed on the network and the
//! typed allowlist stays the only privileged surface. Installed as
//! `command="greendotctl pipe",restrict` in the CSI user's authorized_keys,
//! the key can do nothing else.

use anyhow::{Context, Result};
use std::fs::File;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::fd::FromRawFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

pub fn run(socket: Option<PathBuf>) -> Result<()> {
    let path = socket.unwrap_or_else(|| greendot_proto::config::Config::default().helper_socket);
    let stream =
        UnixStream::connect(&path).with_context(|| format!("connecting {}", path.display()))?;

    // One thread per direction, over the RAW stdio fds: `std::io::Stdout` is
    // a LineWriter, which would buffer h2 frames (binary, rarely newline-
    // terminated) indefinitely and deadlock the handshake. Stdin EOF
    // half-closes the socket so the daemon sees a clean shutdown; when the
    // daemon closes, the stdout copy below ends and the process exits
    // (taking the stdin thread with it — it may be parked in a read that
    // never returns).
    let mut stdin = unsafe { File::from_raw_fd(0) };
    let mut stdout = unsafe { File::from_raw_fd(1) };
    let mut sock_in = stream.try_clone().context("cloning socket")?;
    std::thread::spawn(move || {
        let _ = relay(&mut stdin, &mut sock_in);
        let _ = sock_in.shutdown(Shutdown::Write);
    });
    let mut sock_out = stream;
    let _ = relay(&mut sock_out, &mut stdout);
    Ok(())
}

/// A plain read/write loop — deliberately NOT `std::io::copy`, whose
/// pipe↔socket specialization uses `splice(2)`, which can sleep holding the
/// pipe's mutex; sshd (our peer on the stdio pipes when running as a forced
/// command) then wedges in D-state on that mutex and no byte ever flows.
fn relay(from: &mut impl Read, to: &mut impl Write) -> std::io::Result<()> {
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = from.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        to.write_all(&buf[..n])?;
    }
}
