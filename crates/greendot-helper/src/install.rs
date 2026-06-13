//! Installing missing CLIs via `apt-get`, as a task.

use crate::cmd::TaskSpec;
use greendot_proto::PackageName;

/// `apt-get install -y <packages>` (noninteractive). Empty list => None.
pub fn install(packages: &[PackageName]) -> Option<TaskSpec> {
    if packages.is_empty() {
        return None;
    }
    let mut args = vec!["install".to_string(), "-y".to_string()];
    args.extend(packages.iter().map(|p| p.to_string()));
    Some(TaskSpec::new("apt-get", args).env("DEBIAN_FRONTEND", "noninteractive"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apt_get_install_args() {
        let pkgs = [
            PackageName::new("nvmetcli").unwrap(),
            PackageName::new("targetcli-fb").unwrap(),
        ];
        let spec = install(&pkgs).unwrap();
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
        assert!(install(&[]).is_none());
    }
}
