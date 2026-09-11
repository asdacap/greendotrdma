//! Durable attachment-generation fences. All entry points run under mutate_lock.
//! Tombstones are retained: an arbitrarily delayed RPC must never resurrect a UID.
use crate::nvmet;
use greendot_proto::{SubStatus, Task, ops, pb};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

pub const STATE_ROOT: &str = "/var/lib/greendotrdma/csi";

#[derive(Default, Serialize, Deserialize)]
struct State {
    owner: Option<Owner>,
    fenced: BTreeSet<String>,
}
#[derive(Clone, Serialize, Deserialize)]
struct Owner {
    host: String,
    attachment: String,
}

fn load(root: &Path, nqn: &str) -> io::Result<State> {
    match fs::read(root.join(nqn)) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(io::Error::other),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(State::default()),
        Err(e) => Err(e),
    }
}
fn save(root: &Path, nqn: &str, state: &State) -> io::Result<()> {
    fs::create_dir_all(root)?;
    if let Some(parent) = root.parent() {
        File::open(parent)?.sync_all()?;
    }
    let temporary = root.join(format!("{nqn}.tmp"));
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temporary)?;
    serde_json::to_writer(&mut file, state).map_err(io::Error::other)?;
    file.flush()?;
    file.sync_all()?;
    fs::rename(&temporary, root.join(nqn))?;
    File::open(root)?.sync_all()
}

pub fn attachment(root: &Path, nqn: &str) -> pb::CsiAttachmentReply {
    match load(root, nqn) {
        Ok(state) => match state.owner {
            Some(owner) => pb::CsiAttachmentReply {
                hostnqn: owner.host,
                attachment_id: owner.attachment,
                error: String::new(),
            },
            None => pb::CsiAttachmentReply::default(),
        },
        Err(e) => pb::CsiAttachmentReply {
            error: e.to_string(),
            ..Default::default()
        },
    }
}

// Legacy mutation RPCs cannot bypass a recorded generation fence, even after detach.
pub fn legacy_allowed(root: &Path, nqn: &str, task: &mut Task) -> bool {
    match fs::symlink_metadata(root.join(nqn)) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => true,
        _ => {
            task.begin_subtask("Check attachment protocol").fail(
                "attachment conflict: generation-fenced export requires CsiPublish/CsiUnpublish",
            );
            false
        }
    }
}
pub fn delete_allowed(root: &Path, nqn: &str, task: &mut Task) -> bool {
    match load(root, nqn) {
        Ok(state) if state.owner.is_none() => true,
        Ok(_) => {
            task.begin_subtask("Check attachment owner")
                .fail("attachment conflict: volume is still owned");
            false
        }
        Err(e) => {
            task.begin_subtask("Read attachment owner")
                .fail(e.to_string());
            false
        }
    }
}

fn hosts(root: &Path, nqn: &str) -> io::Result<Vec<String>> {
    match fs::read_dir(root.join("subsystems").join(nqn).join("allowed_hosts")) {
        Ok(entries) => entries
            .map(|entry| entry.map(|e| e.file_name().to_string_lossy().into_owned()))
            .collect(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(vec![]),
        Err(e) => Err(e),
    }
}

pub fn publish(
    root: &Path,
    state_root: &Path,
    op: &ops::CsiPublish,
    task: &mut Task,
) -> io::Result<()> {
    let result = (|| {
        let nqn = op.export.nqn.as_str();
        let mut state = load(state_root, nqn)?;
        if state.fenced.contains(&op.attachment_id) {
            return Err(io::Error::other(
                "attachment conflict: attachment generation is fenced",
            ));
        }
        if let Some(owner) = &state.owner {
            if owner.attachment != op.attachment_id || owner.host != op.hostnqn.as_str() {
                return Err(io::Error::other(
                    "attachment conflict: volume has another owner",
                ));
            }
        }
        let existing_hosts = hosts(root, nqn)?;
        if state.owner.is_none()
            && root.join("subsystems").join(nqn).exists()
            && existing_hosts != vec![op.hostnqn.to_string()]
        {
            return Err(io::Error::other(
                "attachment conflict: legacy export has no sole matching owner",
            ));
        }
        if existing_hosts
            .iter()
            .any(|host| host != op.hostnqn.as_str())
        {
            return Err(io::Error::other(
                "attachment conflict: export grants another host",
            ));
        }
        state.owner = Some(Owner {
            host: op.hostnqn.to_string(),
            attachment: op.attachment_id.clone(),
        });
        // Durable intent precedes export/grant. A failed apply is retryable by this UID only.
        save(state_root, nqn, &state)
    })();
    if let Err(e) = result {
        task.begin_subtask("Claim attachment generation")
            .fail(e.to_string());
        return Ok(());
    }
    task.begin_subtask("Claim attachment generation")
        .complete(SubStatus::Success);
    if nvmet::csi_apply_checked(root, &op.export, task)? == SubStatus::Failed {
        return Ok(());
    }
    nvmet::csi_host_grant(root, &op.export.nqn, &op.hostnqn, task)
}

pub fn unpublish(
    root: &Path,
    state_root: &Path,
    op: &ops::CsiUnpublish,
    task: &mut Task,
) -> io::Result<()> {
    let mut state = match load(state_root, op.nqn.as_str()) {
        Ok(state) => state,
        Err(e) => {
            task.begin_subtask("Read attachment generation")
                .fail(e.to_string());
            return Ok(());
        }
    };
    let owned = state.owner.as_ref().is_some_and(|owner| {
        owner.attachment == op.attachment_id && owner.host == op.hostnqn.as_str()
    });
    // A UID must never be reused with another host.
    if state.owner.as_ref().is_some_and(|owner| {
        owner.attachment == op.attachment_id && owner.host != op.hostnqn.as_str()
    }) {
        task.begin_subtask("Check attachment generation")
            .fail("attachment conflict: host does not match owner");
        return Ok(());
    }
    // Legacy adoption on detach is permitted only for the sole matching ACL host.
    let legacy = if state.owner.is_none() {
        match hosts(root, op.nqn.as_str()) {
            Ok(hosts) => hosts == vec![op.hostnqn.to_string()],
            Err(e) => {
                task.begin_subtask("Read legacy owner").fail(e.to_string());
                return Ok(());
            }
        }
    } else {
        false
    };
    state.fenced.insert(op.attachment_id.clone());
    if legacy {
        state.owner = Some(Owner {
            host: op.hostnqn.to_string(),
            attachment: op.attachment_id.clone(),
        });
    }
    if let Err(e) = save(state_root, op.nqn.as_str(), &state) {
        task.begin_subtask("Persist attachment fence")
            .fail(e.to_string());
        return Ok(());
    }
    task.begin_subtask("Persist attachment fence")
        .complete(SubStatus::Success);
    if !owned && !legacy {
        task.skipped_subtask("Attachment no longer owns export");
        return Ok(());
    }
    // Delete first severs the listener/controllers. Retain the owner on any failure,
    // blocking transfers until a retry has completed the fence.
    if nvmet::csi_delete_checked(root, &op.nqn, task)? == SubStatus::Failed {
        return Ok(());
    }
    state.owner = None;
    if let Err(e) = save(state_root, op.nqn.as_str(), &state) {
        task.begin_subtask("Complete attachment fence")
            .fail(e.to_string());
    } else {
        task.begin_subtask("Complete attachment fence")
            .complete(SubStatus::Success);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::test::Collector;
    use greendot_proto::{CsiNqn, DevicePath, Nqn, NsUuid, TaskEvent, Transport};

    fn run(f: impl FnOnce(&mut Task) -> io::Result<()>) -> SubStatus {
        let mut collector = Collector::default();
        let mut task = Task::new(&mut collector);
        f(&mut task).unwrap();
        task.complete().unwrap();
        match collector.events.last().unwrap() {
            TaskEvent::Finished { status, .. } => *status,
            _ => panic!("missing finish"),
        }
    }
    #[test]
    fn durable_generations_fence_stale_requests_and_preserve_new_owners() {
        for scenario in ["normal", "reboot", "interrupted-fence", "legacy", "corrupt"] {
            let directory = std::env::temp_dir().join(format!(
                "gd-csi-generations-{}-{scenario}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&directory);
            let root = directory.join("configfs");
            let state_root = directory.join("state");
            fs::create_dir_all(&root).unwrap();
            let mut op = ops::CsiPublish {
                export: ops::CsiNvmeApply {
                    nqn: CsiNqn::new("nqn.2026-06.io.greendot.csi:tank:volume").unwrap(),
                    device_path: DevicePath::new("/dev/zvol/tank/volume").unwrap(),
                    device_uuid: NsUuid::new("58668891-c3e4-45d0-b90e-824525c16080").unwrap(),
                    traddr: "10.0.0.5".parse().unwrap(),
                    trsvcid: 4421,
                    transport: Transport::Tcp,
                },
                hostnqn: Nqn::new("nqn.2014-08.org.nvmexpress:host1").unwrap(),
                attachment_id: "old".into(),
            };
            let nqn = op.export.nqn.clone();
            if scenario == "legacy" {
                assert_eq!(
                    run(|task| nvmet::csi_apply(&root, &op.export, task)),
                    SubStatus::Success
                );
                assert_eq!(
                    run(|task| publish(&root, &state_root, &op, task)),
                    SubStatus::Failed
                );
                assert_eq!(
                    run(|task| nvmet::csi_apply(&root, &op.export, task)),
                    SubStatus::Success
                );
                assert_eq!(
                    run(|task| nvmet::csi_host_grant(&root, &nqn, &op.hostnqn, task)),
                    SubStatus::Success
                );
            }
            assert_eq!(
                run(|task| publish(&root, &state_root, &op, task)),
                SubStatus::Success,
                "{scenario}"
            );
            assert_eq!(
                run(|task| publish(&root, &state_root, &op, task)),
                SubStatus::Success
            );
            let old = op.clone();
            op.attachment_id = "new".into();
            op.hostnqn = Nqn::new("nqn.2014-08.org.nvmexpress:host2").unwrap();
            assert_eq!(
                run(|task| publish(&root, &state_root, &op, task)),
                SubStatus::Failed
            );
            assert_eq!(
                hosts(&root, nqn.as_str()).unwrap(),
                vec![old.hostnqn.to_string()]
            );
            if scenario == "reboot" {
                fs::remove_dir_all(&root).unwrap();
                fs::create_dir_all(&root).unwrap();
                assert_eq!(
                    run(|task| publish(&root, &state_root, &old, task)),
                    SubStatus::Success
                );
            }
            if scenario == "corrupt" {
                fs::write(state_root.join(nqn.as_str()), b"{").unwrap();
                assert_eq!(
                    run(|task| publish(&root, &state_root, &op, task)),
                    SubStatus::Failed
                );
                assert!(!attachment(&state_root, nqn.as_str()).error.is_empty());
                fs::remove_dir_all(&directory).unwrap();
                continue;
            }
            let detach = ops::CsiUnpublish {
                nqn: nqn.clone(),
                hostnqn: old.hostnqn.clone(),
                attachment_id: old.attachment_id.clone(),
            };
            if scenario == "interrupted-fence" {
                let mut state = load(&state_root, nqn.as_str()).unwrap();
                state.fenced.insert("old".into());
                save(&state_root, nqn.as_str(), &state).unwrap();
                assert_eq!(
                    run(|task| publish(&root, &state_root, &old, task)),
                    SubStatus::Failed
                );
                assert_eq!(
                    run(|task| publish(&root, &state_root, &op, task)),
                    SubStatus::Failed
                );
            }
            assert_ne!(
                run(|task| unpublish(&root, &state_root, &detach, task)),
                SubStatus::Failed
            );
            assert_eq!(
                run(|task| publish(&root, &state_root, &old, task)),
                SubStatus::Failed
            );
            assert_eq!(
                run(|task| publish(&root, &state_root, &op, task)),
                SubStatus::Success
            );
            assert_ne!(
                run(|task| unpublish(&root, &state_root, &detach, task)),
                SubStatus::Failed
            );
            assert_eq!(attachment(&state_root, nqn.as_str()).attachment_id, "new");
            assert_eq!(
                hosts(&root, nqn.as_str()).unwrap(),
                vec![op.hostnqn.to_string()]
            );
            assert_eq!(
                run(|task| {
                    assert!(!legacy_allowed(&state_root, nqn.as_str(), task));
                    Ok(())
                }),
                SubStatus::Failed
            );
            fs::remove_dir_all(&directory).unwrap();
        }
    }
}
