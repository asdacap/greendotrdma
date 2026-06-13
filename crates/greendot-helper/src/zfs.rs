//! ZFS mutations. Reads happen unprivileged in greendot-web.

use crate::cmd::{Runner, run_checked};
use greendot_proto::{DatasetName, Response, SnapName};

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

pub fn zvol_create(
    runner: &dyn Runner,
    dataset: &DatasetName,
    size: u64,
    volblocksize: Option<u32>,
    sparse: bool,
) -> Response {
    let mut cmd = argv(&["zfs", "create"]);
    if sparse {
        cmd.push("-s".into());
    }
    if let Some(vbs) = volblocksize {
        cmd.extend(argv(&["-o", &format!("volblocksize={vbs}")]));
    }
    cmd.extend(argv(&["-V", &size.to_string(), dataset.as_str()]));
    run_checked(runner, &cmd)
}

pub fn zvol_delete(runner: &dyn Runner, dataset: &DatasetName) -> Response {
    run_checked(runner, &argv(&["zfs", "destroy", dataset.as_str()]))
}

pub fn zvol_resize(runner: &dyn Runner, dataset: &DatasetName, new_size: u64) -> Response {
    run_checked(
        runner,
        &argv(&[
            "zfs",
            "set",
            &format!("volsize={new_size}"),
            dataset.as_str(),
        ]),
    )
}

pub fn snapshot_create(runner: &dyn Runner, dataset: &DatasetName, snap: &SnapName) -> Response {
    run_checked(
        runner,
        &argv(&["zfs", "snapshot", &format!("{dataset}@{snap}")]),
    )
}

pub fn snapshot_destroy(runner: &dyn Runner, dataset: &DatasetName, snap: &SnapName) -> Response {
    run_checked(
        runner,
        &argv(&["zfs", "destroy", &format!("{dataset}@{snap}")]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::test::Recorder;
    use greendot_proto::ErrKind;
    use rstest::rstest;

    fn ds(s: &str) -> DatasetName {
        DatasetName::new(s).unwrap()
    }

    #[rstest]
    #[case::plain(None, false, &["zfs", "create", "-V", "10737418240", "tank/vm1"])]
    #[case::sparse(None, true, &["zfs", "create", "-s", "-V", "10737418240", "tank/vm1"])]
    #[case::volblocksize(Some(16384), false,
        &["zfs", "create", "-o", "volblocksize=16384", "-V", "10737418240", "tank/vm1"])]
    fn zvol_create_argv(
        #[case] volblocksize: Option<u32>,
        #[case] sparse: bool,
        #[case] expected: &[&str],
    ) {
        let recorder = Recorder::default();
        let resp = zvol_create(&recorder, &ds("tank/vm1"), 10 << 30, volblocksize, sparse);
        assert_eq!(resp, Response::Ok);
        assert_eq!(
            recorder.calls(),
            vec![expected.iter().map(|s| s.to_string()).collect::<Vec<_>>()]
        );
    }

    #[test]
    fn other_ops_argv_and_failure_mapping() {
        let recorder = Recorder::default();
        zvol_delete(&recorder, &ds("tank/vm1"));
        zvol_resize(&recorder, &ds("tank/vm1"), 20 << 30);
        snapshot_create(&recorder, &ds("tank/vm1"), &SnapName::new("s1").unwrap());
        snapshot_destroy(&recorder, &ds("tank/vm1"), &SnapName::new("s1").unwrap());
        let want: Vec<Vec<String>> = [
            vec!["zfs", "destroy", "tank/vm1"],
            vec!["zfs", "set", "volsize=21474836480", "tank/vm1"],
            vec!["zfs", "snapshot", "tank/vm1@s1"],
            vec!["zfs", "destroy", "tank/vm1@s1"],
        ]
        .iter()
        .map(|v| v.iter().map(|s| s.to_string()).collect())
        .collect();
        assert_eq!(recorder.calls(), want);

        // Non-zero exit becomes CmdFailed with stderr attached.
        let failing = Recorder {
            fail_with: Some((1, "dataset is busy")),
            ..Default::default()
        };
        let resp = zvol_delete(&failing, &ds("tank/vm1"));
        match resp {
            Response::Err {
                kind: ErrKind::CmdFailed,
                message,
            } => {
                assert!(message.contains("dataset is busy"), "{message}")
            }
            other => panic!("expected CmdFailed, got {other:?}"),
        }
    }
}
