//! NVMe-oF target configuration via the nvmet configfs tree.
//!
//! All operations are idempotent (create tolerates "already exists", delete
//! tolerates "not found") so the reconciler can simply replay desired state.
//! Functions take the configfs root as a parameter; tests run them against a
//! plain tempdir, which shares the relevant semantics (mkdir/rmdir/write/
//! symlink).

use greendot_proto::{DevicePath, ErrKind, Nqn, Response, Transport};
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

fn subsys_dir(root: &Path, nqn: &Nqn) -> PathBuf {
    root.join("subsystems").join(nqn.as_str())
}

fn port_dir(root: &Path, id: u16) -> PathBuf {
    root.join("ports").join(id.to_string())
}

/// configfs attribute write. `create(true)` so the same code works on the
/// tempdir test trees (configfs attribute files always exist).
fn write_attr(dir: &Path, attr: &str, value: &str) -> io::Result<()> {
    std::fs::write(dir.join(attr), value)
}

fn mkdir_ok_exists(dir: &Path) -> io::Result<()> {
    match std::fs::create_dir_all(dir) {
        Err(e) if e.kind() != io::ErrorKind::AlreadyExists => Err(e),
        _ => Ok(()),
    }
}

fn remove_ok_missing(result: io::Result<()>) -> io::Result<()> {
    match result {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// configfs object dirs rmdir cleanly (the kernel owns the attribute files);
/// the tempdir test trees contain real files, so fall back to a recursive
/// remove when the plain rmdir reports "not empty".
fn rmdir_object(dir: &Path) -> io::Result<()> {
    match std::fs::remove_dir(dir) {
        Err(e) if e.kind() == io::ErrorKind::DirectoryNotEmpty => std::fs::remove_dir_all(dir),
        other => other,
    }
}

fn sys_err(what: &str, e: io::Error) -> Response {
    Response::err(ErrKind::Sys, format!("{what}: {e}"))
}

fn done(what: &str, result: io::Result<()>) -> Response {
    match result {
        Ok(()) => Response::Ok,
        Err(e) => sys_err(what, e),
    }
}

pub fn subsys_create(root: &Path, nqn: &Nqn, allow_any_host: bool) -> Response {
    let dir = subsys_dir(root, nqn);
    let result = mkdir_ok_exists(&dir).and_then(|()| {
        write_attr(
            &dir,
            "attr_allow_any_host",
            if allow_any_host { "1" } else { "0" },
        )
    });
    done(&format!("creating subsystem {nqn}"), result)
}

pub fn subsys_delete(root: &Path, nqn: &Nqn) -> Response {
    let dir = subsys_dir(root, nqn);
    let result = (|| {
        if let Ok(namespaces) = std::fs::read_dir(dir.join("namespaces")) {
            for ns in namespaces.flatten() {
                remove_ok_missing(rmdir_object(&ns.path()))?;
            }
        }
        remove_ok_missing(rmdir_object(&dir))
    })();
    done(&format!("deleting subsystem {nqn}"), result)
}

pub fn namespace_set(
    root: &Path,
    nqn: &Nqn,
    nsid: u32,
    device_path: &DevicePath,
    enable: bool,
) -> Response {
    let dir = subsys_dir(root, nqn)
        .join("namespaces")
        .join(nsid.to_string());
    let result = (|| {
        mkdir_ok_exists(&dir)?;
        if enable {
            // device_path is immutable while enabled; the 0-1 cycle makes
            // this idempotent and lets the device be swapped.
            write_attr(&dir, "enable", "0")?;
            write_attr(&dir, "device_path", device_path.as_str())?;
        }
        write_attr(&dir, "enable", if enable { "1" } else { "0" })
    })();
    done(&format!("configuring namespace {nsid} of {nqn}"), result)
}

pub fn namespace_delete(root: &Path, nqn: &Nqn, nsid: u32) -> Response {
    let dir = subsys_dir(root, nqn)
        .join("namespaces")
        .join(nsid.to_string());
    done(
        &format!("deleting namespace {nsid} of {nqn}"),
        remove_ok_missing(rmdir_object(&dir)),
    )
}

pub fn port_create(
    root: &Path,
    id: u16,
    trtype: Transport,
    traddr: IpAddr,
    trsvcid: u16,
) -> Response {
    let dir = port_dir(root, id);
    let result = (|| {
        mkdir_ok_exists(&dir)?;
        if matches!(trtype, Transport::Rdma | Transport::Tcp) {
            write_attr(
                &dir,
                "addr_adrfam",
                if traddr.is_ipv4() { "ipv4" } else { "ipv6" },
            )?;
            write_attr(&dir, "addr_traddr", &traddr.to_string())?;
            write_attr(&dir, "addr_trsvcid", &trsvcid.to_string())?;
        }
        write_attr(&dir, "addr_trtype", trtype.as_str())
    })();
    done(&format!("creating port {id}"), result)
}

pub fn port_delete(root: &Path, id: u16) -> Response {
    let dir = port_dir(root, id);
    let result = (|| {
        if let Ok(links) = std::fs::read_dir(dir.join("subsystems")) {
            for link in links.flatten() {
                remove_ok_missing(std::fs::remove_file(link.path()))?;
            }
        }
        remove_ok_missing(rmdir_object(&dir))
    })();
    done(&format!("deleting port {id}"), result)
}

/// Symlink that tolerates "already exists" and creates the parent dir when
/// missing (it always exists on real configfs; the tempdir test trees need it).
fn symlink_ok_exists(original: &Path, link: &Path) -> io::Result<()> {
    if let Some(parent) = link.parent() {
        mkdir_ok_exists(parent)?;
    }
    match std::os::unix::fs::symlink(original, link) {
        Err(e) if e.kind() != io::ErrorKind::AlreadyExists => Err(e),
        _ => Ok(()),
    }
}

pub fn port_link(root: &Path, port: u16, nqn: &Nqn) -> Response {
    let link = port_dir(root, port).join("subsystems").join(nqn.as_str());
    let result = symlink_ok_exists(&subsys_dir(root, nqn), &link);
    // This is where nvmet actually binds the transport listener; an RDMA
    // port that cannot bind fails right here.
    done(&format!("linking {nqn} to port {port}"), result)
}

pub fn port_unlink(root: &Path, port: u16, nqn: &Nqn) -> Response {
    let link = port_dir(root, port).join("subsystems").join(nqn.as_str());
    done(
        &format!("unlinking {nqn} from port {port}"),
        remove_ok_missing(std::fs::remove_file(&link)),
    )
}

pub fn host_allow(root: &Path, nqn: &Nqn, host_nqn: &Nqn) -> Response {
    let host_dir = root.join("hosts").join(host_nqn.as_str());
    let link = subsys_dir(root, nqn)
        .join("allowed_hosts")
        .join(host_nqn.as_str());
    let result = mkdir_ok_exists(&host_dir).and_then(|()| symlink_ok_exists(&host_dir, &link));
    done(&format!("allowing host {host_nqn} on {nqn}"), result)
}

pub fn host_remove(root: &Path, nqn: &Nqn, host_nqn: &Nqn) -> Response {
    let link = subsys_dir(root, nqn)
        .join("allowed_hosts")
        .join(host_nqn.as_str());
    done(
        &format!("removing host {host_nqn} from {nqn}"),
        remove_ok_missing(std::fs::remove_file(&link)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nqn(s: &str) -> Nqn {
        Nqn::new(s).unwrap()
    }

    fn read(root: &Path, rel: &str) -> String {
        std::fs::read_to_string(root.join(rel)).unwrap()
    }

    #[test]
    fn full_subsystem_lifecycle_on_a_fake_configfs_tree() {
        let tmp = std::env::temp_dir().join(format!("gd-nvmet{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let root = tmp.as_path();
        let n = nqn("nqn.2026-06.io.greendot:vm1");
        let dev = DevicePath::new("/dev/zvol/tank/vm1").unwrap();

        // Create everything (twice — idempotency is part of the contract).
        for _ in 0..2 {
            assert_eq!(subsys_create(root, &n, false), Response::Ok);
            assert_eq!(namespace_set(root, &n, 1, &dev, true), Response::Ok);
            assert_eq!(
                port_create(root, 1, Transport::Rdma, "10.0.0.5".parse().unwrap(), 4420),
                Response::Ok
            );
            assert_eq!(
                port_create(root, 3, Transport::Loop, "0.0.0.0".parse().unwrap(), 0),
                Response::Ok
            );
            assert_eq!(port_link(root, 1, &n), Response::Ok);
            assert_eq!(
                host_allow(root, &n, &nqn("nqn.2014-08.org.nvmexpress:host1")),
                Response::Ok
            );
        }

        assert_eq!(
            read(
                root,
                "subsystems/nqn.2026-06.io.greendot:vm1/attr_allow_any_host"
            ),
            "0"
        );
        assert_eq!(
            read(
                root,
                "subsystems/nqn.2026-06.io.greendot:vm1/namespaces/1/device_path"
            ),
            "/dev/zvol/tank/vm1"
        );
        assert_eq!(
            read(
                root,
                "subsystems/nqn.2026-06.io.greendot:vm1/namespaces/1/enable"
            ),
            "1"
        );
        assert_eq!(read(root, "ports/1/addr_trtype"), "rdma");
        assert_eq!(read(root, "ports/1/addr_adrfam"), "ipv4");
        assert_eq!(read(root, "ports/1/addr_traddr"), "10.0.0.5");
        assert_eq!(read(root, "ports/1/addr_trsvcid"), "4420");
        assert_eq!(read(root, "ports/3/addr_trtype"), "loop");
        assert!(
            !tmp.join("ports/3/addr_traddr").exists(),
            "loop ports have no address"
        );
        let link = tmp.join("ports/1/subsystems/nqn.2026-06.io.greendot:vm1");
        assert_eq!(
            std::fs::read_link(&link).unwrap(),
            tmp.join("subsystems/nqn.2026-06.io.greendot:vm1")
        );
        assert!(tmp.join("subsystems/nqn.2026-06.io.greendot:vm1/allowed_hosts/nqn.2014-08.org.nvmexpress:host1").exists());

        // Disable namespace keeps device_path but flips enable.
        assert_eq!(namespace_set(root, &n, 1, &dev, false), Response::Ok);
        assert_eq!(
            read(
                root,
                "subsystems/nqn.2026-06.io.greendot:vm1/namespaces/1/enable"
            ),
            "0"
        );

        // Tear down (twice — deletes tolerate absence).
        for _ in 0..2 {
            assert_eq!(
                host_remove(root, &n, &nqn("nqn.2014-08.org.nvmexpress:host1")),
                Response::Ok
            );
            assert_eq!(port_unlink(root, 1, &n), Response::Ok);
            assert_eq!(port_delete(root, 1), Response::Ok);
            assert_eq!(subsys_delete(root, &n), Response::Ok);
        }
        assert!(!tmp.join("subsystems/nqn.2026-06.io.greendot:vm1").exists());
        assert!(!tmp.join("ports/1").exists());

        // port_delete also clears leftover links so rmdir succeeds.
        assert_eq!(subsys_create(root, &n, true), Response::Ok);
        assert_eq!(
            port_create(root, 2, Transport::Tcp, "::1".parse().unwrap(), 4420),
            Response::Ok
        );
        assert_eq!(read(root, "ports/2/addr_adrfam"), "ipv6");
        assert_eq!(port_link(root, 2, &n), Response::Ok);
        assert_eq!(port_delete(root, 2), Response::Ok);
        assert!(!tmp.join("ports/2").exists());

        std::fs::remove_dir_all(&tmp).unwrap();
    }
}
