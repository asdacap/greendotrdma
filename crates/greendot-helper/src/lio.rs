//! iSCSI target configuration via the LIO configfs tree
//! (/sys/kernel/config/target). Same philosophy as nvmet.rs: idempotent
//! creates/deletes, root path injected, tempdir-testable.

use greendot_proto::{BackstoreName, ChapCreds, DevicePath, ErrKind, Iqn, Response};
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

fn backstore_dir(root: &Path, name: &BackstoreName) -> PathBuf {
    root.join("core/iblock_0").join(name.as_str())
}

fn tpg_dir(root: &Path, iqn: &Iqn) -> PathBuf {
    root.join("iscsi").join(iqn.as_str()).join("tpgt_1")
}

fn portal_dirname(addr: IpAddr, port: u16) -> String {
    match addr {
        IpAddr::V4(v4) => format!("{v4}:{port}"),
        IpAddr::V6(v6) => format!("[{v6}]:{port}"),
    }
}

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

/// See nvmet.rs: configfs object dirs rmdir cleanly, tempdir trees need the
/// recursive fallback.
fn rmdir_object(dir: &Path) -> io::Result<()> {
    match std::fs::remove_dir(dir) {
        Err(e) if e.kind() == io::ErrorKind::DirectoryNotEmpty => std::fs::remove_dir_all(dir),
        other => other,
    }
}

/// Removes the symlinks inside a configfs object dir, then the dir itself.
/// (LUNs and mapped-LUN dirs hold a symlink that must go first.)
fn rmdir_with_links(dir: &Path) -> io::Result<()> {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if entry.path().is_symlink() {
                remove_ok_missing(std::fs::remove_file(entry.path()))?;
            }
        }
    }
    remove_ok_missing(rmdir_object(dir))
}

fn done(what: &str, result: io::Result<()>) -> Response {
    match result {
        Ok(()) => Response::Ok,
        Err(e) => Response::err(ErrKind::Sys, format!("{what}: {e}")),
    }
}

pub fn backstore_create(root: &Path, name: &BackstoreName, device_path: &DevicePath) -> Response {
    let dir = backstore_dir(root, name);
    let result = (|| {
        mkdir_ok_exists(&dir)?;
        write_attr(&dir, "control", &format!("udev_path={device_path}"))?;
        write_attr(&dir, "enable", "1")
    })();
    done(&format!("creating backstore {name}"), result)
}

pub fn backstore_delete(root: &Path, name: &BackstoreName) -> Response {
    done(
        &format!("deleting backstore {name}"),
        remove_ok_missing(rmdir_object(&backstore_dir(root, name))),
    )
}

pub fn target_create(root: &Path, iqn: &Iqn) -> Response {
    done(
        &format!("creating target {iqn}"),
        mkdir_ok_exists(&tpg_dir(root, iqn)),
    )
}

pub fn target_delete(root: &Path, iqn: &Iqn) -> Response {
    let tpg = tpg_dir(root, iqn);
    let result = (|| {
        for sub in ["np", "acls", "lun"] {
            if let Ok(entries) = std::fs::read_dir(tpg.join(sub)) {
                for entry in entries.flatten() {
                    if sub == "acls" {
                        // mapped-lun dirs inside the ACL go first
                        if let Ok(mapped) = std::fs::read_dir(entry.path()) {
                            for m in mapped.flatten() {
                                if m.path().is_dir() {
                                    rmdir_with_links(&m.path())?;
                                }
                            }
                        }
                    }
                    rmdir_with_links(&entry.path())?;
                }
            }
        }
        remove_ok_missing(rmdir_object(&tpg))?;
        remove_ok_missing(rmdir_object(&root.join("iscsi").join(iqn.as_str())))
    })();
    done(&format!("deleting target {iqn}"), result)
}

pub fn lun_map(root: &Path, iqn: &Iqn, lun: u32, backstore: &BackstoreName) -> Response {
    let lun_dir = tpg_dir(root, iqn).join("lun").join(format!("lun_{lun}"));
    let result = (|| {
        mkdir_ok_exists(&lun_dir)?;
        let link = lun_dir.join(backstore.as_str());
        match std::os::unix::fs::symlink(backstore_dir(root, backstore), &link) {
            Err(e) if e.kind() != io::ErrorKind::AlreadyExists => Err(e),
            _ => Ok(()),
        }
    })();
    done(&format!("mapping LUN {lun} of {iqn}"), result)
}

pub fn portal_set(root: &Path, iqn: &Iqn, addr: IpAddr, port: u16, iser: bool) -> Response {
    let np = tpg_dir(root, iqn)
        .join("np")
        .join(portal_dirname(addr, port));
    let result = (|| {
        mkdir_ok_exists(&np)?;
        if iser {
            // This write fails unless RDMA (ib_isert) can serve the address —
            // the iSCSI equivalent of nvmet's link-time bind.
            write_attr(&np, "iser", "1")?;
        }
        Ok(())
    })();
    done(
        &format!("creating portal {}:{port} for {iqn}", addr),
        result,
    )
}

pub fn portal_delete(root: &Path, iqn: &Iqn, addr: IpAddr, port: u16) -> Response {
    let np = tpg_dir(root, iqn)
        .join("np")
        .join(portal_dirname(addr, port));
    done(
        &format!("deleting portal {addr}:{port} of {iqn}"),
        remove_ok_missing(rmdir_object(&np)),
    )
}

pub fn acl_add(root: &Path, iqn: &Iqn, initiator: &Iqn) -> Response {
    let acl = tpg_dir(root, iqn).join("acls").join(initiator.as_str());
    let result = (|| {
        mkdir_ok_exists(&acl)?;
        // Map TPG LUN 0 into the ACL (we always export exactly LUN 0).
        let mapped = acl.join("lun_0");
        mkdir_ok_exists(&mapped)?;
        match std::os::unix::fs::symlink(tpg_dir(root, iqn).join("lun/lun_0"), mapped.join("lun_0"))
        {
            Err(e) if e.kind() != io::ErrorKind::AlreadyExists => Err(e),
            _ => Ok(()),
        }
    })();
    done(&format!("allowing initiator {initiator} on {iqn}"), result)
}

pub fn acl_remove(root: &Path, iqn: &Iqn, initiator: &Iqn) -> Response {
    let acl = tpg_dir(root, iqn).join("acls").join(initiator.as_str());
    let result = (|| {
        if acl.exists() {
            rmdir_with_links(&acl.join("lun_0"))?;
        }
        remove_ok_missing(rmdir_object(&acl))
    })();
    done(
        &format!("removing initiator {initiator} from {iqn}"),
        result,
    )
}

fn chap_value_ok(s: &str) -> bool {
    (1..=255).contains(&s.len()) && s.chars().all(|c| c.is_ascii_graphic())
}

pub fn tpg_set(
    root: &Path,
    iqn: &Iqn,
    enabled: bool,
    demo_mode: bool,
    auth: Option<&ChapCreds>,
) -> Response {
    let tpg = tpg_dir(root, iqn);
    if let Some(creds) = auth
        && !(chap_value_ok(&creds.username) && chap_value_ok(&creds.password.0))
    {
        return Response::err(
            ErrKind::Validation,
            "CHAP credentials must be 1-255 printable ASCII characters",
        );
    }
    let result = (|| {
        mkdir_ok_exists(&tpg.join("attrib"))?;
        mkdir_ok_exists(&tpg.join("auth"))?;
        write_attr(
            &tpg.join("attrib"),
            "generate_node_acls",
            if demo_mode { "1" } else { "0" },
        )?;
        write_attr(
            &tpg.join("attrib"),
            "cache_dynamic_acls",
            if demo_mode { "1" } else { "0" },
        )?;
        match auth {
            Some(creds) => {
                write_attr(&tpg.join("auth"), "userid", &creds.username)?;
                write_attr(&tpg.join("auth"), "password", &creds.password.0)?;
                write_attr(&tpg.join("attrib"), "authentication", "1")?;
            }
            None => write_attr(&tpg.join("attrib"), "authentication", "0")?,
        }
        write_attr(&tpg, "enable", if enabled { "1" } else { "0" })
    })();
    done(&format!("configuring TPG of {iqn}"), result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use greendot_proto::Secret;

    fn read(root: &Path, rel: &str) -> String {
        std::fs::read_to_string(root.join(rel)).unwrap()
    }

    #[test]
    fn full_iscsi_lifecycle_on_a_fake_configfs_tree() {
        let tmp = std::env::temp_dir().join(format!("gd-lio{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let root = tmp.as_path();
        let iqn = Iqn::new("iqn.2026-06.io.greendot:vm1").unwrap();
        let initiator = Iqn::new("iqn.1993-08.org.debian:01:abc").unwrap();
        let bs = BackstoreName::new("vm1").unwrap();
        let dev = DevicePath::new("/dev/zvol/tank/vm1").unwrap();
        let v4: IpAddr = "10.0.0.5".parse().unwrap();
        let v6: IpAddr = "::1".parse().unwrap();

        // Create everything twice (idempotency).
        for _ in 0..2 {
            assert_eq!(backstore_create(root, &bs, &dev), Response::Ok);
            assert_eq!(target_create(root, &iqn), Response::Ok);
            assert_eq!(lun_map(root, &iqn, 0, &bs), Response::Ok);
            assert_eq!(portal_set(root, &iqn, v4, 3260, true), Response::Ok);
            assert_eq!(portal_set(root, &iqn, v6, 3260, false), Response::Ok);
            assert_eq!(acl_add(root, &iqn, &initiator), Response::Ok);
            assert_eq!(tpg_set(root, &iqn, true, false, None), Response::Ok);
        }

        let tpg = "iscsi/iqn.2026-06.io.greendot:vm1/tpgt_1";
        assert_eq!(
            read(root, "core/iblock_0/vm1/control"),
            "udev_path=/dev/zvol/tank/vm1"
        );
        assert_eq!(read(root, "core/iblock_0/vm1/enable"), "1");
        assert!(tmp.join(format!("{tpg}/lun/lun_0/vm1")).is_symlink());
        assert_eq!(read(root, &format!("{tpg}/np/10.0.0.5:3260/iser")), "1");
        assert!(tmp.join(format!("{tpg}/np/[::1]:3260")).is_dir());
        assert!(
            !tmp.join(format!("{tpg}/np/[::1]:3260/iser")).exists(),
            "plain portal has no iser write"
        );
        assert!(
            tmp.join(format!(
                "{tpg}/acls/iqn.1993-08.org.debian:01:abc/lun_0/lun_0"
            ))
            .is_symlink()
        );
        assert_eq!(read(root, &format!("{tpg}/attrib/generate_node_acls")), "0");
        assert_eq!(read(root, &format!("{tpg}/attrib/authentication")), "0");
        assert_eq!(read(root, &format!("{tpg}/enable")), "1");

        // CHAP + demo mode variants.
        let creds = ChapCreds {
            username: "user1".into(),
            password: Secret("s3cret!".into()),
        };
        assert_eq!(tpg_set(root, &iqn, true, true, Some(&creds)), Response::Ok);
        assert_eq!(read(root, &format!("{tpg}/auth/userid")), "user1");
        assert_eq!(read(root, &format!("{tpg}/attrib/authentication")), "1");
        assert_eq!(read(root, &format!("{tpg}/attrib/generate_node_acls")), "1");
        let bad = ChapCreds {
            username: "user 1".into(),
            password: Secret("x".into()),
        };
        assert!(matches!(
            tpg_set(root, &iqn, true, false, Some(&bad)),
            Response::Err {
                kind: ErrKind::Validation,
                ..
            }
        ));

        // Teardown twice (tolerates absence), then everything is gone.
        for _ in 0..2 {
            assert_eq!(acl_remove(root, &iqn, &initiator), Response::Ok);
            assert_eq!(portal_delete(root, &iqn, v4, 3260), Response::Ok);
            assert_eq!(target_delete(root, &iqn), Response::Ok);
            assert_eq!(backstore_delete(root, &bs), Response::Ok);
        }
        assert!(!tmp.join("iscsi/iqn.2026-06.io.greendot:vm1").exists());
        assert!(!tmp.join("core/iblock_0/vm1").exists());

        std::fs::remove_dir_all(&tmp).unwrap();
    }
}
