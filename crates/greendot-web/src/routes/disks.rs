use super::{AppState, page};
use crate::actual::block;
use crate::auth::CurrentUser;
use crate::fmt::human_bytes;
use askama::Template;
use axum::extract::{Form, State};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Extension, Router};
use greendot_proto::{BlockDev, DevicePath, MountPath, PartLabel, Request};
use serde::Deserialize;
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/disks", get(disks_page))
        .route("/disks/table", post(table_create))
        .route("/disks/part/create", post(part_create))
        .route("/disks/part/delete", post(part_delete))
        .route("/disks/part/shrink", post(part_shrink))
}

pub struct PartRow {
    pub name: String,
    pub number: Option<u32>,
    pub size: String,
    pub label: String,
    pub mountpoint: String,
    pub fstype: String,
    pub shrinkable: bool,
    /// Why shrink is unavailable (empty when `shrinkable`).
    pub shrink_reason: String,
}

pub struct DiskRow {
    pub name: String,
    pub size: String,
    pub model: String,
    pub serial: String,
    /// Approximate unallocated space (disk size minus the partition sizes).
    pub free: String,
    pub no_space: bool,
    pub partitions: Vec<PartRow>,
}

pub struct DisksView {
    pub disks: Vec<DiskRow>,
    pub error: Option<String>,
    pub flash: Option<String>,
    pub form_error: Option<String>,
}

/// Whether (and how) a partition's filesystem can be shrunk in place.
enum Shrink {
    Ext,
    Btrfs,
    Raw,
    No(&'static str),
}

fn shrinkability(fstype: Option<&str>, mounted: bool) -> Shrink {
    match fstype {
        None => Shrink::Raw,
        Some("ext2" | "ext3" | "ext4") if !mounted => Shrink::Ext,
        Some("btrfs") if !mounted => Shrink::Btrfs,
        Some("ext2" | "ext3" | "ext4" | "btrfs") => Shrink::No("mounted — unmount it first"),
        Some("xfs") => Shrink::No("XFS cannot be shrunk"),
        Some("zfs_member") => Shrink::No("part of a ZFS pool"),
        Some("LVM2_member") => Shrink::No("part of an LVM volume group"),
        Some(_) => Shrink::No("this filesystem cannot be shrunk"),
    }
}

fn fs_display(fstype: Option<&str>) -> String {
    match fstype {
        None => "no filesystem".into(),
        Some("zfs_member") => "ZFS".into(),
        Some("LVM2_member") => "LVM".into(),
        Some(f) => f.into(),
    }
}

#[derive(Template)]
#[template(path = "disks.html")]
struct DisksTemplate {
    user: CurrentUser,
    view: DisksView,
}

#[derive(Template)]
#[template(path = "_disks.html")]
struct DisksPartial {
    view: DisksView,
}

async fn gather(flash: Option<String>, form_error: Option<String>) -> DisksView {
    let mut view = DisksView {
        disks: vec![],
        error: None,
        flash,
        form_error,
    };
    match block::disks().await {
        Ok(disks) => {
            view.disks = disks
                .into_iter()
                .map(|d| {
                    let used: u64 = d.partitions.iter().map(|p| p.size).sum();
                    let unallocated = d.size.saturating_sub(used);
                    DiskRow {
                        size: human_bytes(d.size),
                        model: d.model.unwrap_or_default(),
                        serial: d.serial.unwrap_or_default(),
                        free: human_bytes(unallocated),
                        no_space: unallocated < (1 << 20),
                        partitions: d.partitions.into_iter().map(part_row).collect(),
                        name: d.name,
                    }
                })
                .collect();
        }
        Err(e) => view.error = Some(format!("could not list block devices: {e:#}")),
    }
    view
}

fn part_row(p: block::Partition) -> PartRow {
    let mountpoint = p.mountpoint.unwrap_or_default();
    let mounted = !mountpoint.is_empty();
    let fstype = fs_display(p.fstype.as_deref());
    let (shrinkable, shrink_reason) = match shrinkability(p.fstype.as_deref(), mounted) {
        Shrink::No(reason) => (false, reason.to_string()),
        _ => (true, String::new()),
    };
    PartRow {
        number: p.number,
        size: human_bytes(p.size),
        label: p.label.unwrap_or_default(),
        mountpoint,
        fstype,
        shrinkable,
        shrink_reason,
        name: p.name,
    }
}

async fn disks_page(
    State(_): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    page(DisksTemplate {
        user,
        view: gather(None, None).await,
    })
}

async fn run(state: &AppState, req: Request, kind: &str, title: &str, success: String) -> Response {
    let view = match crate::task_runner::run(state, req, kind, title).await {
        Ok(outcome) => {
            let (flash, error) = outcome.message(&success);
            gather(flash, error).await
        }
        Err(e) => gather(None, Some(format!("{e:#}"))).await,
    };
    page(DisksPartial { view })
}

async fn form_failed(message: String) -> Response {
    page(DisksPartial {
        view: gather(None, Some(message)).await,
    })
}

#[derive(Deserialize)]
struct TableForm {
    disk: String,
}

async fn table_create(State(state): State<Arc<AppState>>, Form(form): Form<TableForm>) -> Response {
    let Ok(disk) = BlockDev::new(form.disk.trim()) else {
        return form_failed(format!("invalid disk name {:?}", form.disk)).await;
    };
    let req = Request::PartitionTableCreate { disk: disk.clone() };
    run(
        &state,
        req,
        "gpt-create",
        &format!("new GPT on {disk}"),
        format!("created new GPT on {disk}"),
    )
    .await
}

#[derive(Deserialize)]
struct PartCreateForm {
    disk: String,
    #[serde(default)]
    size: String,
    #[serde(default)]
    unit: String,
    label: String,
}

async fn part_create(
    State(state): State<Arc<AppState>>,
    Form(form): Form<PartCreateForm>,
) -> Response {
    let Ok(disk) = BlockDev::new(form.disk.trim()) else {
        return form_failed(format!("invalid disk name {:?}", form.disk)).await;
    };
    let Ok(label) = PartLabel::new(form.label.trim()) else {
        return form_failed(format!("invalid partition label {:?}", form.label)).await;
    };
    // Empty size means "rest of the disk"; sfdisk works in 512-byte sectors.
    let size_sectors = match form.size.trim() {
        "" => None,
        size => match super::zfs::parse_size(size, &form.unit) {
            Some(bytes) => Some(bytes / 512),
            None => return form_failed("invalid size".into()).await,
        },
    };
    let req = Request::PartitionCreate {
        disk: disk.clone(),
        start_sector: None,
        size_sectors,
        label,
    };
    run(
        &state,
        req,
        "partition-create",
        &format!("create partition on {disk}"),
        format!("created partition on {disk}"),
    )
    .await
}

#[derive(Deserialize)]
struct PartDeleteForm {
    disk: String,
    number: u32,
}

async fn part_delete(
    State(state): State<Arc<AppState>>,
    Form(form): Form<PartDeleteForm>,
) -> Response {
    let Ok(disk) = BlockDev::new(form.disk.trim()) else {
        return form_failed(format!("invalid disk name {:?}", form.disk)).await;
    };
    let req = Request::PartitionDelete {
        disk: disk.clone(),
        number: form.number,
    };
    run(
        &state,
        req,
        "partition-delete",
        &format!("delete partition {} on {disk}", form.number),
        format!("deleted partition {} on {disk}", form.number),
    )
    .await
}

#[derive(Deserialize)]
struct PartShrinkForm {
    disk: String,
    number: u32,
    #[serde(default)]
    size: String,
    #[serde(default)]
    unit: String,
}

/// Runs one shrink step; `Ok(())` on success, `Err(message)` otherwise.
async fn run_step(
    state: &AppState,
    req: Request,
    kind: &'static str,
    title: String,
) -> Result<(), String> {
    match crate::task_runner::run(state, req, kind, &title).await {
        Ok(o) if o.ok => Ok(()),
        Ok(o) => Err(o.error.unwrap_or_else(|| format!("{title} failed"))),
        Err(e) => Err(format!("{e:#}")),
    }
}

async fn finish_shrink(result: Result<(), String>) -> Response {
    let view = match result {
        Ok(()) => gather(Some("partition shrunk".into()), None).await,
        Err(e) => gather(None, Some(e)).await,
    };
    page(DisksPartial { view })
}

/// Shrinks a partition: the filesystem is always resized *before* the partition
/// boundary, so a mid-sequence failure never leaves the fs larger than its
/// partition. The requested size, its shrinkability, and the current size are
/// all re-derived from live `lsblk` here — the form is not trusted.
async fn part_shrink(
    State(state): State<Arc<AppState>>,
    Form(form): Form<PartShrinkForm>,
) -> Response {
    let Ok(disk) = BlockDev::new(form.disk.trim()) else {
        return form_failed(format!("invalid disk name {:?}", form.disk)).await;
    };
    let Some(bytes) = super::zfs::parse_size(&form.size, &form.unit) else {
        return form_failed("invalid size".into()).await;
    };
    // 1 MiB alignment removes any sfdisk start/size rounding ambiguity.
    if !bytes.is_multiple_of(1 << 20) {
        return form_failed("size must be a whole number of MiB".into()).await;
    }
    let disks = match block::disks().await {
        Ok(d) => d,
        Err(e) => return form_failed(format!("could not read disks: {e:#}")).await,
    };
    let Some(part) = disks
        .iter()
        .find(|d| d.name == disk.as_str())
        .and_then(|d| d.partitions.iter().find(|p| p.number == Some(form.number)))
    else {
        return form_failed(format!(
            "partition {} on {disk} no longer exists",
            form.number
        ))
        .await;
    };
    if bytes / 512 >= part.size / 512 {
        return form_failed("new size must be smaller than the current size".into()).await;
    }
    // Capture owned values so the `disks`/`part` borrow doesn't span the awaits.
    let mounted = part.mountpoint.is_some();
    let fstype = part.fstype.clone();
    let part_name = part.name.clone();
    let Ok(device) = DevicePath::new(format!("/dev/{part_name}")) else {
        return form_failed("invalid device path".into()).await;
    };
    let new_sectors = bytes / 512;
    // Shrink the filesystem 1 MiB short of the new partition end for slack.
    let fs_target = bytes - (1 << 20);
    let resize_part = Request::PartitionResize {
        disk: disk.clone(),
        number: form.number,
        size_sectors: new_sectors,
    };
    match shrinkability(fstype.as_deref(), mounted) {
        Shrink::No(reason) => form_failed(format!("cannot shrink {device}: {reason}")).await,
        Shrink::Raw => {
            let r = run_step(
                &state,
                resize_part,
                "partition-resize",
                format!("resize {device}"),
            )
            .await;
            finish_shrink(r).await
        }
        Shrink::Ext => {
            let mut r = run_step(
                &state,
                Request::Fsck {
                    device: device.clone(),
                },
                "fsck",
                format!("check {device}"),
            )
            .await;
            if r.is_ok() {
                r = run_step(
                    &state,
                    Request::ResizeExt {
                        device: device.clone(),
                        new_size_sectors: fs_target / 512,
                    },
                    "resize-fs",
                    format!("shrink filesystem on {device}"),
                )
                .await;
            }
            if r.is_ok() {
                r = run_step(
                    &state,
                    resize_part,
                    "partition-resize",
                    format!("resize {device}"),
                )
                .await;
            }
            finish_shrink(r).await
        }
        Shrink::Btrfs => {
            let Ok(mp) = MountPath::new(format!("/run/greendotrdma/btrfs-resize-{part_name}"))
            else {
                return form_failed("invalid temp mount path".into()).await;
            };
            if let Err(e) = run_step(
                &state,
                Request::BtrfsMount {
                    device: device.clone(),
                    mount_path: mp.clone(),
                },
                "btrfs-mount",
                format!("mount {device}"),
            )
            .await
            {
                return finish_shrink(Err(e)).await;
            }
            if let Err(e) = run_step(
                &state,
                Request::BtrfsResize {
                    mount_path: mp.clone(),
                    new_size: fs_target,
                },
                "btrfs-resize",
                format!("shrink filesystem on {device}"),
            )
            .await
            {
                // Best-effort cleanup; the temp mount otherwise clears on reboot.
                let _ = run_step(
                    &state,
                    Request::Umount {
                        mount_path: mp.clone(),
                    },
                    "umount",
                    "unmount".into(),
                )
                .await;
                return finish_shrink(Err(e)).await;
            }
            // Hard gate: never resize the partition while the fs is still mounted.
            if let Err(e) = run_step(
                &state,
                Request::Umount {
                    mount_path: mp.clone(),
                },
                "umount",
                "unmount".into(),
            )
            .await
            {
                return finish_shrink(Err(format!(
                    "filesystem still mounted, partition not resized: {e}"
                )))
                .await;
            }
            let r = run_step(
                &state,
                resize_part,
                "partition-resize",
                format!("resize {device}"),
            )
            .await;
            finish_shrink(r).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Shrink, fs_display, shrinkability};
    use crate::routes::testutil::{form_post, login, send, test_app};
    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode, header};
    use rstest::rstest;

    #[rstest]
    #[case(None, "no filesystem")]
    #[case(Some("ext4"), "ext4")]
    #[case(Some("zfs_member"), "ZFS")]
    #[case(Some("LVM2_member"), "LVM")]
    fn fs_display_names_special_members(#[case] fstype: Option<&str>, #[case] expected: &str) {
        assert_eq!(fs_display(fstype), expected);
    }

    #[rstest]
    #[case(Some("zfs_member"), "part of a ZFS pool")]
    #[case(Some("LVM2_member"), "part of an LVM volume group")]
    #[case(Some("xfs"), "XFS cannot be shrunk")]
    #[case(Some("reiserfs"), "this filesystem cannot be shrunk")]
    fn shrinkability_blocks_claimed_members(#[case] fstype: Option<&str>, #[case] reason: &str) {
        match shrinkability(fstype, false) {
            Shrink::No(r) => assert_eq!(r, reason),
            _ => panic!("expected Shrink::No for {fstype:?}"),
        }
    }

    #[tokio::test]
    async fn disks_page_and_partition_mutations() {
        let app = test_app();
        let (cookie, csrf) = login(&app).await;
        let auth = |mut req: HttpRequest<Body>| {
            req.headers_mut()
                .insert(header::COOKIE, cookie.parse().unwrap());
            req.headers_mut()
                .insert("x-greendot-csrf", csrf.parse().unwrap());
            req
        };

        let req = auth(HttpRequest::get("/disks").body(Body::empty()).unwrap());
        let (status, _, body) = send(&app, req).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("Disks"), "{body}");

        // Valid create goes through the fake helper; bad input is rejected.
        let req = auth(form_post(
            "/disks/part/create",
            "disk=sdb&size=100&unit=GiB&label=data",
        ));
        let (_, _, body) = send(&app, req).await;
        assert!(body.contains("created partition on sdb"), "{body}");
        let req = auth(form_post(
            "/disks/part/create",
            "disk=..%2Fsda&size=&unit=GiB&label=data",
        ));
        let (_, _, body) = send(&app, req).await;
        assert!(body.contains("invalid disk name"), "{body}");
        let req = auth(form_post("/disks/part/delete", "disk=sdb&number=2"));
        let (_, _, body) = send(&app, req).await;
        assert!(body.contains("deleted partition 2 on sdb"), "{body}");

        // Shrink: form validation rejects bad input before touching the helper.
        let req = auth(form_post(
            "/disks/part/shrink",
            "disk=..%2Fsda&number=1&size=1&unit=GiB",
        ));
        let (_, _, body) = send(&app, req).await;
        assert!(body.contains("invalid disk name"), "{body}");
        let req = auth(form_post(
            "/disks/part/shrink",
            "disk=sdb&number=1&size=&unit=GiB",
        ));
        let (_, _, body) = send(&app, req).await;
        assert!(body.contains("invalid size"), "{body}");
    }
}
