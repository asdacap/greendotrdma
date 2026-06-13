//! GPT partitioning via sfdisk (util-linux). sfdisk re-reads the partition
//! table itself after changes, so no extra ioctl handling is needed.

use crate::cmd::{Runner, run_checked, run_checked_stdin};
use greendot_proto::{BlockDev, PartLabel, Response};

fn dev(disk: &BlockDev) -> String {
    format!("/dev/{disk}")
}

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

/// Writes a brand-new empty GPT — destroys the existing table.
pub fn table_create(runner: &dyn Runner, disk: &BlockDev) -> Response {
    run_checked_stdin(runner, &argv(&["sfdisk", &dev(disk)]), "label: gpt\n")
}

pub fn partition_create(
    runner: &dyn Runner,
    disk: &BlockDev,
    start_sector: Option<u64>,
    size_sectors: Option<u64>,
    label: &PartLabel,
) -> Response {
    let mut fields = Vec::new();
    if let Some(start) = start_sector {
        fields.push(format!("start={start}"));
    }
    if let Some(size) = size_sectors {
        fields.push(format!("size={size}"));
    }
    fields.push(format!("name={label}"));
    let script = format!("{}\n", fields.join(", "));
    run_checked_stdin(runner, &argv(&["sfdisk", "--append", &dev(disk)]), &script)
}

pub fn partition_delete(runner: &dyn Runner, disk: &BlockDev, number: u32) -> Response {
    run_checked(
        runner,
        &argv(&["sfdisk", "--delete", &dev(disk), &number.to_string()]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::test::Recorder;
    use rstest::rstest;

    fn disk() -> BlockDev {
        BlockDev::new("sdb").unwrap()
    }

    #[rstest]
    #[case::full_spec(Some(2048), Some(2097152), "start=2048, size=2097152, name=data\n")]
    #[case::size_only(None, Some(2097152), "size=2097152, name=data\n")]
    #[case::rest_of_disk(None, None, "name=data\n")]
    fn partition_create_script(
        #[case] start: Option<u64>,
        #[case] size: Option<u64>,
        #[case] script: &str,
    ) {
        let recorder = Recorder::default();
        let label = PartLabel::new("data").unwrap();
        assert_eq!(
            partition_create(&recorder, &disk(), start, size, &label),
            Response::Ok
        );
        assert_eq!(
            recorder.full_calls(),
            vec![(
                ["sfdisk", "--append", "/dev/sdb"]
                    .map(String::from)
                    .to_vec(),
                Some(script.to_owned())
            )]
        );
    }

    #[test]
    fn table_create_and_delete_argv() {
        let recorder = Recorder::default();
        assert_eq!(table_create(&recorder, &disk()), Response::Ok);
        assert_eq!(partition_delete(&recorder, &disk(), 3), Response::Ok);
        assert_eq!(
            recorder.full_calls(),
            vec![
                (
                    ["sfdisk", "/dev/sdb"].map(String::from).to_vec(),
                    Some("label: gpt\n".into())
                ),
                (
                    ["sfdisk", "--delete", "/dev/sdb", "3"]
                        .map(String::from)
                        .to_vec(),
                    None
                ),
            ]
        );
    }
}
