//! Periodic ZFS snapshots with retention. The scheduler runs in this
//! process; the actual `zfs snapshot`/`destroy` goes through the helper.

use crate::routes::AppState;
use crate::state::SnapshotPolicy;
use chrono::{DateTime, Utc};
use greendot_proto::{DatasetName, Request, SnapName};

/// Whether a policy is due: its cron has an occurrence after `last_run`
/// that is not in the future. Invalid cron expressions are never due.
pub fn due(cron: &str, last_run: i64, now: i64) -> bool {
    let Ok(parsed) = cron.parse::<croner::Cron>() else {
        return false;
    };
    let Some(last) = DateTime::<Utc>::from_timestamp(last_run, 0) else {
        return false;
    };
    parsed
        .find_next_occurrence(&last, false)
        .is_ok_and(|next| next.timestamp() <= now)
}

/// Snapshot names (full `dataset@snap`) that retention should destroy.
/// `snaps` is (full name, creation unix-time) of this policy's dataset.
/// Deletion criteria are OR-combined; the newest snapshot always survives;
/// with neither limit set nothing is destroyed.
pub fn to_destroy(
    snaps: &[(String, i64)],
    prefix: &str,
    keep_last: Option<u32>,
    keep_days: Option<u32>,
    now: i64,
) -> Vec<String> {
    if keep_last.is_none() && keep_days.is_none() {
        return Vec::new();
    }
    let auto_prefix = format!("{prefix}-");
    let mut mine: Vec<&(String, i64)> = snaps
        .iter()
        .filter(|(name, _)| {
            name.split_once('@')
                .is_some_and(|(_, s)| s.starts_with(&auto_prefix))
        })
        .collect();
    mine.sort_by_key(|(_, created)| std::cmp::Reverse(*created)); // newest first
    let mut doomed: Vec<String> = mine
        .iter()
        .enumerate()
        .skip(1) // the newest snapshot always survives
        .filter(|(rank, (_, created))| {
            keep_last.is_some_and(|k| *rank >= k as usize)
                || keep_days.is_some_and(|d| now - created >= i64::from(d) * 86400)
        })
        .map(|(_, (name, _))| name.clone())
        .collect();
    doomed.sort();
    doomed
}

fn snapshot_name(prefix: &str, now: DateTime<Utc>) -> String {
    format!("{prefix}-{}", now.format("%Y%m%d-%H%M%S"))
}

/// One scheduler pass; called every 30s and unit-testable per policy via
/// the pure functions above.
async fn run_policy(state: &AppState, policy: &SnapshotPolicy, now: DateTime<Utc>) {
    // Update last_run *before* firing so a crash loop cannot double-fire.
    if let Err(e) = state.db.set_policy_last_run(policy.id, now.timestamp()) {
        tracing::error!(error = %e, "updating policy last_run failed");
        return;
    }
    let (Ok(dataset), Ok(snap)) = (
        DatasetName::new(policy.dataset.clone()),
        SnapName::new(snapshot_name(&policy.prefix, now)),
    ) else {
        tracing::error!(policy = policy.id, "invalid dataset or snapshot name");
        return;
    };
    let req = Request::SnapshotCreate {
        dataset: dataset.clone(),
        snap: snap.clone(),
    };
    let title = format!("scheduled snapshot {dataset}@{snap}");
    match crate::task_runner::run(state, req, "snapshot-create", &title).await {
        Ok(o) if o.ok => {}
        outcome => {
            tracing::error!(?outcome, dataset = %dataset, "scheduled snapshot failed");
            return;
        }
    }
    retention(state, policy, now).await;
}

async fn retention(state: &AppState, policy: &SnapshotPolicy, now: DateTime<Utc>) {
    let all = match crate::actual::zfs::snapshots().await {
        Ok(Some(snaps)) => snaps,
        // ZFS not installed — nothing to retain.
        Ok(None) => return,
        Err(e) => {
            tracing::error!(error = %e, "listing snapshots for retention failed");
            return;
        }
    };
    let dataset_prefix = format!("{}@", policy.dataset);
    let mine: Vec<(String, i64)> = all
        .into_iter()
        .filter(|s| s.name.starts_with(&dataset_prefix))
        .map(|s| (s.name, s.creation))
        .collect();
    for full in to_destroy(
        &mine,
        &policy.prefix,
        policy.keep_last,
        policy.keep_days,
        now.timestamp(),
    ) {
        let Some((ds, snap)) = full.split_once('@') else {
            continue;
        };
        let (Ok(dataset), Ok(snap)) = (DatasetName::new(ds), SnapName::new(snap)) else {
            continue;
        };
        tracing::info!(snapshot = %full, "retention destroying");
        let req = Request::SnapshotDestroy { dataset, snap };
        if let Err(e) = crate::task_runner::run(
            state,
            req,
            "snapshot-retention",
            &format!("retention destroy {full}"),
        )
        .await
        {
            tracing::error!(error = %e, snapshot = %full, "retention destroy failed");
        }
    }
}

/// The background task: ticks every 30 s, fires due policies.
pub async fn scheduler(state: std::sync::Arc<AppState>) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
    loop {
        tick.tick().await;
        let now = Utc::now();
        let policies = match state.db.list_policies() {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(error = %e, "listing snapshot policies failed");
                continue;
            }
        };
        for policy in policies.iter().filter(|p| p.enabled) {
            if due(&policy.cron, policy.last_run, now.timestamp()) {
                run_policy(&state, policy, now).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// 2026-06-13 00:00:00 UTC.
    const T0: i64 = 1781308800;
    const HOUR: i64 = 3600;
    const DAY: i64 = 86400;

    #[rstest]
    // Hourly cron, last run just after the top of the hour: due again only
    // after the next top of the hour.
    #[case::hourly_not_yet("0 * * * *", T0 + 60, T0 + 30 * 60, false)]
    #[case::hourly_due("0 * * * *", T0 + 60, T0 + HOUR + 1, true)]
    // Never ran (last_run = 0): the next occurrence after epoch is long
    // past, so it fires immediately.
    #[case::catch_up("0 2 * * *", 0, T0, true)]
    // Daily at 02:00: due at 02:00:00 sharp.
    #[case::daily_exact("0 2 * * *", T0, T0 + 2 * HOUR, true)]
    #[case::daily_just_before("0 2 * * *", T0, T0 + 2 * HOUR - 1, false)]
    // Weekly cron parses too.
    #[case::weekly("0 3 * * 0", T0, T0 + 7 * DAY, true)]
    // Invalid expressions are never due.
    #[case::invalid_cron("not a cron", 0, T0, false)]
    #[case::empty_cron("", 0, T0, false)]
    fn due_table(
        #[case] cron: &str,
        #[case] last_run: i64,
        #[case] now: i64,
        #[case] expected: bool,
    ) {
        assert_eq!(due(cron, last_run, now), expected, "cron={cron:?}");
    }

    #[rstest]
    // keep_last=2: the two newest survive, older matching ones go.
    #[case::keep_last(Some(2), None, &["tank/a@auto-3", "tank/a@auto-4"], &["tank/a@auto-1", "tank/a@auto-2"])]
    // keep_days=2 at now=T0+4d: snapshots older than 2 days go.
    #[case::keep_days(None, Some(2), &["tank/a@auto-3", "tank/a@auto-4"], &["tank/a@auto-1", "tank/a@auto-2"])]
    // OR-combined: keep_last=3 would spare auto-2, but keep_days=2 kills it.
    #[case::or_combined(Some(3), Some(2), &["tank/a@auto-3", "tank/a@auto-4"], &["tank/a@auto-1", "tank/a@auto-2"])]
    // No limits: nothing is destroyed.
    #[case::no_limits(None, None, &["tank/a@auto-1", "tank/a@auto-2", "tank/a@auto-3", "tank/a@auto-4"], &[])]
    // keep_last=0 still never destroys the newest.
    #[case::newest_survives(Some(0), None, &["tank/a@auto-4"], &["tank/a@auto-1", "tank/a@auto-2", "tank/a@auto-3"])]
    fn retention_table(
        #[case] keep_last: Option<u32>,
        #[case] keep_days: Option<u32>,
        #[case] survivors: &[&str],
        #[case] destroyed: &[&str],
    ) {
        // auto-N created N days after T0; manual snapshot is never touched.
        let mut snaps: Vec<(String, i64)> = (1..=4)
            .map(|n| (format!("tank/a@auto-{n}"), T0 + n * DAY))
            .collect();
        snaps.push(("tank/a@manual-keep".into(), T0));
        let now = T0 + 4 * DAY;
        let result = to_destroy(&snaps, "auto", keep_last, keep_days, now);
        assert_eq!(result, destroyed, "survivors should be {survivors:?}");
    }
}
