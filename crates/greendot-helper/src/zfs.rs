//! ZFS mutations as `zfs` CLI tasks. Reads happen unprivileged in greendot-web.

use crate::cmd::TaskSpec;
use greendot_proto::{DatasetName, SnapName};

fn spec(args: Vec<String>) -> TaskSpec {
    TaskSpec::new("zfs", args)
}

fn s(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|p| p.to_string()).collect()
}

pub fn zvol_create(
    dataset: &DatasetName,
    size: u64,
    volblocksize: Option<u32>,
    sparse: bool,
) -> TaskSpec {
    let mut args = s(&["create"]);
    if sparse {
        args.push("-s".into());
    }
    if let Some(vbs) = volblocksize {
        args.extend(s(&["-o", &format!("volblocksize={vbs}")]));
    }
    args.extend(s(&["-V", &size.to_string(), dataset.as_str()]));
    spec(args)
}

pub fn zvol_delete(dataset: &DatasetName) -> TaskSpec {
    spec(s(&["destroy", dataset.as_str()]))
}

pub fn zvol_resize(dataset: &DatasetName, new_size: u64) -> TaskSpec {
    spec(s(&[
        "set",
        &format!("volsize={new_size}"),
        dataset.as_str(),
    ]))
}

pub fn snapshot_create(dataset: &DatasetName, snap: &SnapName) -> TaskSpec {
    spec(s(&["snapshot", &format!("{dataset}@{snap}")]))
}

pub fn snapshot_destroy(dataset: &DatasetName, snap: &SnapName) -> TaskSpec {
    spec(s(&["destroy", &format!("{dataset}@{snap}")]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn ds(s: &str) -> DatasetName {
        DatasetName::new(s).unwrap()
    }

    #[rstest]
    #[case::plain(None, false, &["create", "-V", "10737418240", "tank/vm1"])]
    #[case::sparse(None, true, &["create", "-s", "-V", "10737418240", "tank/vm1"])]
    #[case::volblocksize(Some(16384), false,
        &["create", "-o", "volblocksize=16384", "-V", "10737418240", "tank/vm1"])]
    fn zvol_create_args(
        #[case] volblocksize: Option<u32>,
        #[case] sparse: bool,
        #[case] expected: &[&str],
    ) {
        let spec = zvol_create(&ds("tank/vm1"), 10 << 30, volblocksize, sparse);
        assert_eq!(spec.command, "zfs");
        assert_eq!(
            spec.args,
            expected.iter().map(|s| s.to_string()).collect::<Vec<_>>()
        );
        assert_eq!(spec.stdin, None);
    }

    #[test]
    fn other_ops_args() {
        assert_eq!(
            zvol_delete(&ds("tank/vm1")).args,
            s(&["destroy", "tank/vm1"])
        );
        assert_eq!(
            zvol_resize(&ds("tank/vm1"), 20 << 30).args,
            s(&["set", "volsize=21474836480", "tank/vm1"])
        );
        assert_eq!(
            snapshot_create(&ds("tank/vm1"), &SnapName::new("s1").unwrap()).args,
            s(&["snapshot", "tank/vm1@s1"])
        );
        assert_eq!(
            snapshot_destroy(&ds("tank/vm1"), &SnapName::new("s1").unwrap()).args,
            s(&["destroy", "tank/vm1@s1"])
        );
    }
}
