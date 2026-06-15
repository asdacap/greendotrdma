//! Installing missing CLIs via the OS package manager, as a task. Detects the
//! distro from `/etc/os-release` and spawns the matching install command, or
//! refuses with a manual-install hint on a distro we don't know how to drive.

use crate::cmd::TaskSpec;
use greendot_proto::{OsInfo, PackageName, PkgFamily};

/// Build the install task for `packages` on the detected OS:
/// - empty list → `Ok(None)` (nothing to install);
/// - Debian/Ubuntu → `apt-get install -y <packages>` (noninteractive);
/// - any other distro → `Err(hint)`, surfaced to the user as a failed task.
pub fn install(packages: &[PackageName], os: &OsInfo) -> Result<Option<TaskSpec>, String> {
    if packages.is_empty() {
        return Ok(None);
    }
    let names: Vec<String> = packages.iter().map(ToString::to_string).collect();
    match os.family {
        PkgFamily::Debian => {
            let mut args = vec!["install".to_string(), "-y".to_string()];
            args.extend(names);
            Ok(Some(
                TaskSpec::new("apt-get", args).env("DEBIAN_FRONTEND", "noninteractive"),
            ))
        }
        PkgFamily::Unsupported => Err(format!(
            "automatic install is only supported on Debian/Ubuntu (detected: {}); \
             install these packages with your distribution's package manager: {}",
            os.pretty,
            names.join(" ")
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(family: PkgFamily) -> OsInfo {
        OsInfo {
            family,
            pretty: "Test OS 1".into(),
        }
    }

    #[test]
    fn debian_builds_apt_get_task() {
        let pkgs = [
            PackageName::new("nvmetcli").unwrap(),
            PackageName::new("targetcli-fb").unwrap(),
        ];
        let spec = install(&pkgs, &os(PkgFamily::Debian)).unwrap().unwrap();
        assert_eq!(spec.command, "apt-get");
        assert_eq!(
            spec.args,
            ["install", "-y", "nvmetcli", "targetcli-fb"]
                .map(String::from)
                .to_vec()
        );
        assert_eq!(
            spec.env,
            vec![("DEBIAN_FRONTEND".into(), "noninteractive".into())]
        );
    }

    #[test]
    fn empty_is_noop_and_unsupported_errors_with_hint() {
        // Nothing to install is a no-op on any OS.
        assert!(install(&[], &os(PkgFamily::Debian)).unwrap().is_none());
        assert!(install(&[], &os(PkgFamily::Unsupported)).unwrap().is_none());
        // An unsupported distro refuses, naming the packages and the OS.
        let pkgs = [PackageName::new("nvme-cli").unwrap()];
        let err = install(&pkgs, &os(PkgFamily::Unsupported)).unwrap_err();
        assert!(err.contains("nvme-cli"), "{err}");
        assert!(err.contains("Test OS 1"), "{err}");
    }
}
