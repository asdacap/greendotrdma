use super::{AppState, page};
use crate::actual::{block, smart, zfs};
use crate::auth::{CurrentUser, nav_redirect};
use crate::fmt::human_bytes;
use crate::metrics::{ChartUnit, chart_svg};
use askama::Template;
use axum::extract::{Form, Path, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Extension, Router};
use greendot_proto::{BlockDev, DevicePath, MountPath, PartLabel, Request};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Cross-device context gathered once per page: SMART health (per whole disk),
/// the ZFS device→pool map, the export-backing device set, and the set of
/// devices a new pool may be built from. Threaded into [`disk_row`]/[`part_row`]
/// so those stay pure (and unit-testable) over fixture maps.
#[derive(Default)]
struct DeviceContext {
    /// Bare disk name → SMART health/temp (whole disks only; partitions have none).
    health: HashMap<String, smart::SmartHealth>,
    /// `/dev/...` path → ZFS pool name.
    members: HashMap<String, String>,
    /// `/dev/...` paths already backing an NVMe-oF/iSCSI export.
    in_use: HashSet<String>,
    /// `/dev/...` paths a new ZFS pool may be created from (same predicate as the
    /// pool-create page), so the "Create ZFS pool" link only appears where the
    /// pool page would actually accept the device.
    poolable: HashSet<String>,
}

async fn device_context(state: &AppState, disks: &[block::Disk]) -> DeviceContext {
    // SMART is per physical device, so only whole disks are probed (not partitions).
    let devs: Vec<BlockDev> = disks
        .iter()
        .filter_map(|d| BlockDev::new(&d.name).ok())
        .collect();
    let in_use: HashSet<String> = state.db.export_device_paths().into_iter().collect();
    let poolable: HashSet<String> = block::available_block_devices(&state.helper, &in_use)
        .await
        .into_iter()
        .filter(|d| {
            d.kind != block::AvailKind::Zvol && d.kind != block::AvailKind::Lv && d.fstype.is_none()
        })
        .map(|d| d.path)
        .collect();
    DeviceContext {
        health: smart::health(&state.helper, &devs).await,
        members: zfs::pool_members().await.ok().flatten().unwrap_or_default(),
        in_use,
        poolable,
    }
}

/// Best-effort "what is this used for" summary, in priority order: mounted →
/// ZFS pool member → LVM PV → export backing → other filesystem → partitioned /
/// available. Pure over the [`DeviceContext`] maps.
fn usage_for(
    device_path: &str,
    mountpoint: Option<&str>,
    fstype: Option<&str>,
    partitions: usize,
    ctx: &DeviceContext,
) -> String {
    if let Some(mp) = mountpoint.filter(|m| !m.is_empty()) {
        return match fstype.filter(|f| !f.is_empty()) {
            Some(fs) => format!("mounted at {mp} ({fs})"),
            None => format!("mounted at {mp}"),
        };
    }
    match fstype {
        Some("zfs_member") => match ctx.members.get(device_path) {
            Some(pool) => format!("ZFS pool: {pool}"),
            None => "ZFS pool member".to_string(),
        },
        Some("LVM2_member") => "LVM physical volume".to_string(),
        Some(fs) if ctx.in_use.contains(device_path) => format!("exported ({fs})"),
        Some(fs) => fs.to_string(),
        None if ctx.in_use.contains(device_path) => "exported (NVMe-oF/iSCSI)".to_string(),
        None if partitions > 0 => format!("partitioned ({partitions} partitions)"),
        None => "available".to_string(),
    }
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/disks", get(disks_page))
        .route("/disks/{disk}", get(disk_detail_page))
        .route("/disks/{disk}/part/{number}", get(part_detail_page))
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
    /// `/dev/<name>` — the create-pool link target.
    pub device_path: String,
    /// What the partition is used for (ZFS/LVM/mount/export/available).
    pub usage: String,
    /// Whether a new ZFS pool may be built from this partition.
    pub poolable: bool,
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
    /// `/dev/<name>` — the create-pool link target.
    pub device_path: String,
    /// SMART status dot class (`dot-green`/`dot-red`/`dot-gray`).
    pub dot_class: &'static str,
    /// Current temperature (`"38 °C"` or `"—"`).
    pub temp: String,
    /// What the disk is used for (ZFS/LVM/mount/partitioned/available).
    pub usage: String,
    /// Whether a new ZFS pool may be built from the whole disk.
    pub poolable: bool,
}

pub struct DisksView {
    pub disks: Vec<DiskRow>,
    pub error: Option<String>,
    pub flash: Option<String>,
    /// The just-dispatched task to link from the flash notice (`/tasks/{id}`).
    pub task_id: Option<i64>,
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

async fn gather(
    state: &AppState,
    flash: Option<String>,
    form_error: Option<String>,
    task_id: Option<i64>,
) -> DisksView {
    let mut view = DisksView {
        disks: vec![],
        error: None,
        flash,
        task_id,
        form_error,
    };
    match block::disks().await {
        Ok(disks) => {
            let ctx = device_context(state, &disks).await;
            view.disks = disks.into_iter().map(|d| disk_row(d, &ctx)).collect();
        }
        Err(e) => view.error = Some(format!("could not list block devices: {e:#}")),
    }
    view
}

fn disk_row(d: block::Disk, ctx: &DeviceContext) -> DiskRow {
    let used: u64 = d.partitions.iter().map(|p| p.size).sum();
    let unallocated = d.size.saturating_sub(used);
    let device_path = format!("/dev/{}", d.name);
    let health = ctx.health.get(&d.name);
    let usage = usage_for(
        &device_path,
        d.mountpoint.as_deref(),
        d.fstype.as_deref(),
        d.partitions.len(),
        ctx,
    );
    DiskRow {
        size: human_bytes(d.size),
        model: d.model.unwrap_or_default(),
        serial: d.serial.unwrap_or_default(),
        free: human_bytes(unallocated),
        no_space: unallocated < (1 << 20),
        dot_class: smart::dot_class(health),
        temp: smart::temp_display(health),
        poolable: ctx.poolable.contains(&device_path),
        usage,
        partitions: d.partitions.into_iter().map(|p| part_row(p, ctx)).collect(),
        device_path,
        name: d.name,
    }
}

fn part_row(p: block::Partition, ctx: &DeviceContext) -> PartRow {
    let device_path = format!("/dev/{}", p.name);
    let usage = usage_for(
        &device_path,
        p.mountpoint.as_deref(),
        p.fstype.as_deref(),
        0,
        ctx,
    );
    let poolable = ctx.poolable.contains(&device_path);
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
        poolable,
        usage,
        device_path,
        name: p.name,
    }
}

async fn disks_page(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    page(DisksTemplate {
        user,
        view: gather(&state, None, None, None).await,
    })
}

// ---- Per-disk page (partition listing + disk-level forms) ----

pub struct DiskDetailView {
    pub name: String,
    /// `None` when the named disk doesn't exist on this host.
    pub disk: Option<DiskRow>,
    /// Live read/write/temperature charts (inline SVG; rendered unescaped).
    pub traffic_read_svg: String,
    pub traffic_write_svg: String,
    pub temp_svg: String,
    /// Full `smartctl -x` dump, shown verbatim.
    pub smart_report: String,
    /// False when smartctl isn't installed (show the dependency hint instead).
    pub smart_installed: bool,
    pub error: Option<String>,
    pub flash: Option<String>,
    /// The just-dispatched task to link from the flash notice (`/tasks/{id}`).
    pub task_id: Option<i64>,
    pub form_error: Option<String>,
}

#[derive(Template)]
#[template(path = "disk_detail.html")]
struct DiskDetailTemplate {
    user: CurrentUser,
    view: DiskDetailView,
}

#[derive(Template)]
#[template(path = "_disk_detail.html")]
struct DiskDetailPartial {
    view: DiskDetailView,
}

async fn gather_disk_detail(
    state: &AppState,
    name: &str,
    flash: Option<String>,
    form_error: Option<String>,
    task_id: Option<i64>,
) -> DiskDetailView {
    let mut view = DiskDetailView {
        name: name.to_owned(),
        disk: None,
        traffic_read_svg: String::new(),
        traffic_write_svg: String::new(),
        temp_svg: String::new(),
        smart_report: String::new(),
        smart_installed: true,
        error: None,
        flash,
        task_id,
        form_error,
    };
    match block::disks().await {
        Ok(disks) => {
            if let Some(d) = disks.into_iter().find(|d| d.name == name) {
                let ctx = device_context(state, std::slice::from_ref(&d)).await;
                let series = |suffix| state.metrics.ring_series(&format!("disk:{name}:{suffix}"));
                view.traffic_read_svg = chart_svg(&series("read_bps"), 600, 120, ChartUnit::Bytes);
                view.traffic_write_svg =
                    chart_svg(&series("write_bps"), 600, 120, ChartUnit::Bytes);
                view.temp_svg = chart_svg(&series("temp_c"), 600, 120, ChartUnit::Celsius);
                if let Ok(dev) = BlockDev::new(name) {
                    let rep = smart::report(&state.helper, &dev).await;
                    view.smart_installed = rep.installed;
                    view.smart_report = if rep.stderr.trim().is_empty() {
                        rep.stdout
                    } else {
                        format!("{}\n{}", rep.stdout, rep.stderr)
                    };
                }
                view.disk = Some(disk_row(d, &ctx));
            }
        }
        Err(e) => view.error = Some(format!("could not list block devices: {e:#}")),
    }
    view
}

async fn disk_detail_page(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
    Path(disk): Path<String>,
) -> Response {
    page(DiskDetailTemplate {
        user,
        view: gather_disk_detail(&state, &disk, None, None, None).await,
    })
}

/// Runs a disk-level request as a recorded task and re-renders the owning disk's
/// detail partial with the outcome.
async fn run(state: &Arc<AppState>, req: Request, kind: &str, title: &str, disk: &str) -> Response {
    let view = match crate::task_runner::start(state, req, kind, title) {
        Ok(id) => {
            gather_disk_detail(
                state,
                disk,
                Some(format!("started {title}")),
                None,
                Some(id),
            )
            .await
        }
        Err(e) => gather_disk_detail(state, disk, None, Some(format!("{e:#}")), None).await,
    };
    page(DiskDetailPartial { view })
}

async fn disk_detail_failed(state: &AppState, disk: &str, message: impl Into<String>) -> Response {
    page(DiskDetailPartial {
        view: gather_disk_detail(state, disk, None, Some(message.into()), None).await,
    })
}

// ---- Per-partition page (shrink + delete) ----

pub struct PartDetailView {
    pub disk: String,
    /// `None` when the partition no longer exists on its disk.
    pub part: Option<PartRow>,
    pub error: Option<String>,
    pub flash: Option<String>,
    /// The just-dispatched task to link from the flash notice (`/tasks/{id}`).
    pub task_id: Option<i64>,
    pub form_error: Option<String>,
}

#[derive(Template)]
#[template(path = "part_detail.html")]
struct PartDetailTemplate {
    user: CurrentUser,
    view: PartDetailView,
}

#[derive(Template)]
#[template(path = "_part_detail.html")]
struct PartDetailPartial {
    view: PartDetailView,
}

async fn gather_part_detail(
    state: &AppState,
    disk: &str,
    number: u32,
    flash: Option<String>,
    form_error: Option<String>,
    task_id: Option<i64>,
) -> PartDetailView {
    let mut view = PartDetailView {
        disk: disk.to_owned(),
        part: None,
        error: None,
        flash,
        task_id,
        form_error,
    };
    match block::disks().await {
        Ok(disks) => {
            if let Some(d) = disks.into_iter().find(|d| d.name == disk) {
                let ctx = device_context(state, std::slice::from_ref(&d)).await;
                view.part = d
                    .partitions
                    .into_iter()
                    .find(|p| p.number == Some(number))
                    .map(|p| part_row(p, &ctx));
            }
        }
        Err(e) => view.error = Some(format!("could not list block devices: {e:#}")),
    }
    view
}

async fn part_detail_page(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
    Path((disk, number)): Path<(String, u32)>,
) -> Response {
    page(PartDetailTemplate {
        user,
        view: gather_part_detail(&state, &disk, number, None, None, None).await,
    })
}

async fn part_detail_failed(
    state: &AppState,
    disk: &str,
    number: u32,
    message: impl Into<String>,
) -> Response {
    page(PartDetailPartial {
        view: gather_part_detail(state, disk, number, None, Some(message.into()), None).await,
    })
}

#[derive(Deserialize)]
struct TableForm {
    disk: String,
}

async fn table_create(State(state): State<Arc<AppState>>, Form(form): Form<TableForm>) -> Response {
    let scope = form.disk.trim().to_owned();
    let Ok(disk) = BlockDev::new(form.disk.trim()) else {
        return disk_detail_failed(&state, &scope, format!("invalid disk name {:?}", form.disk))
            .await;
    };
    let req = Request::PartitionTableCreate { disk: disk.clone() };
    run(
        &state,
        req,
        "gpt-create",
        &format!("new GPT on {disk}"),
        &scope,
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
    let scope = form.disk.trim().to_owned();
    let Ok(disk) = BlockDev::new(form.disk.trim()) else {
        return disk_detail_failed(&state, &scope, format!("invalid disk name {:?}", form.disk))
            .await;
    };
    let Ok(label) = PartLabel::new(form.label.trim()) else {
        return disk_detail_failed(
            &state,
            &scope,
            format!("invalid partition label {:?}", form.label),
        )
        .await;
    };
    // Empty size means "rest of the disk"; sfdisk works in 512-byte sectors.
    let size_sectors = match form.size.trim() {
        "" => None,
        size => match super::zfs::parse_size(size, &form.unit) {
            Some(bytes) => Some(bytes / 512),
            None => return disk_detail_failed(&state, &scope, "invalid size").await,
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
        &scope,
    )
    .await
}

#[derive(Deserialize)]
struct PartDeleteForm {
    disk: String,
    number: u32,
}

/// Deletes a partition (a remove-op): the partition's page no longer applies,
/// so redirect back to the owning disk; a dispatch failure re-renders the
/// partition detail with the error.
async fn part_delete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<PartDeleteForm>,
) -> Response {
    let scope = form.disk.trim().to_owned();
    let Ok(disk) = BlockDev::new(form.disk.trim()) else {
        return part_detail_failed(
            &state,
            &scope,
            form.number,
            format!("invalid disk name {:?}", form.disk),
        )
        .await;
    };
    let req = Request::PartitionDelete {
        disk: disk.clone(),
        number: form.number,
    };
    let title = format!("delete partition {} on {disk}", form.number);
    // Removing the partition means its page no longer applies — go back to the
    // disk; the delete task is viewable on /tasks.
    match crate::task_runner::start(&state, req, "partition-delete", &title) {
        Ok(_) => nav_redirect(&headers, &format!("/disks/{scope}")),
        Err(e) => part_detail_failed(&state, &scope, form.number, format!("{e:#}")).await,
    }
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

async fn finish_shrink(
    state: &AppState,
    disk: &str,
    number: u32,
    result: Result<(), String>,
) -> Response {
    let view = match result {
        Ok(()) => {
            gather_part_detail(
                state,
                disk,
                number,
                Some("partition shrunk".into()),
                None,
                None,
            )
            .await
        }
        Err(e) => gather_part_detail(state, disk, number, None, Some(e), None).await,
    };
    page(PartDetailPartial { view })
}

/// Shrinks a partition: the filesystem is always resized *before* the partition
/// boundary, so a mid-sequence failure never leaves the fs larger than its
/// partition. The requested size, its shrinkability, and the current size are
/// all re-derived from live `lsblk` here — the form is not trusted.
async fn part_shrink(
    State(state): State<Arc<AppState>>,
    Form(form): Form<PartShrinkForm>,
) -> Response {
    let scope = form.disk.trim().to_owned();
    let Ok(disk) = BlockDev::new(form.disk.trim()) else {
        return part_detail_failed(
            &state,
            &scope,
            form.number,
            format!("invalid disk name {:?}", form.disk),
        )
        .await;
    };
    let Some(bytes) = super::zfs::parse_size(&form.size, &form.unit) else {
        return part_detail_failed(&state, &scope, form.number, "invalid size").await;
    };
    // 1 MiB alignment removes any sfdisk start/size rounding ambiguity.
    if !bytes.is_multiple_of(1 << 20) {
        return part_detail_failed(
            &state,
            &scope,
            form.number,
            "size must be a whole number of MiB",
        )
        .await;
    }
    let disks = match block::disks().await {
        Ok(d) => d,
        Err(e) => {
            return part_detail_failed(
                &state,
                &scope,
                form.number,
                format!("could not read disks: {e:#}"),
            )
            .await;
        }
    };
    let Some(part) = disks
        .iter()
        .find(|d| d.name == disk.as_str())
        .and_then(|d| d.partitions.iter().find(|p| p.number == Some(form.number)))
    else {
        return part_detail_failed(
            &state,
            &scope,
            form.number,
            format!("partition {} on {disk} no longer exists", form.number),
        )
        .await;
    };
    if bytes / 512 >= part.size / 512 {
        return part_detail_failed(
            &state,
            &scope,
            form.number,
            "new size must be smaller than the current size",
        )
        .await;
    }
    // Capture owned values so the `disks`/`part` borrow doesn't span the awaits.
    let mounted = part.mountpoint.is_some();
    let fstype = part.fstype.clone();
    let part_name = part.name.clone();
    let Ok(device) = DevicePath::new(format!("/dev/{part_name}")) else {
        return part_detail_failed(&state, &scope, form.number, "invalid device path").await;
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
        Shrink::No(reason) => {
            part_detail_failed(
                &state,
                &scope,
                form.number,
                format!("cannot shrink {device}: {reason}"),
            )
            .await
        }
        Shrink::Raw => {
            let r = run_step(
                &state,
                resize_part,
                "partition-resize",
                format!("resize {device}"),
            )
            .await;
            finish_shrink(&state, &scope, form.number, r).await
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
            finish_shrink(&state, &scope, form.number, r).await
        }
        Shrink::Btrfs => {
            let Ok(mp) = MountPath::new(format!("/run/greendotrdma/btrfs-resize-{part_name}"))
            else {
                return part_detail_failed(&state, &scope, form.number, "invalid temp mount path")
                    .await;
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
                return finish_shrink(&state, &scope, form.number, Err(e)).await;
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
                return finish_shrink(&state, &scope, form.number, Err(e)).await;
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
                return finish_shrink(
                    &state,
                    &scope,
                    form.number,
                    Err(format!(
                        "filesystem still mounted, partition not resized: {e}"
                    )),
                )
                .await;
            }
            let r = run_step(
                &state,
                resize_part,
                "partition-resize",
                format!("resize {device}"),
            )
            .await;
            finish_shrink(&state, &scope, form.number, r).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DeviceContext, Shrink, fs_display, shrinkability, usage_for};
    use crate::routes::testutil::{form_post, login, send, test_app};
    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode, header};
    use rstest::rstest;
    use std::collections::{HashMap, HashSet};

    #[test]
    fn usage_for_covers_priority_branches() {
        let ctx = DeviceContext {
            members: HashMap::from([("/dev/sdb".to_string(), "tank".to_string())]),
            in_use: HashSet::from(["/dev/sdc".to_string()]),
            ..Default::default()
        };
        // mounted wins over everything
        assert_eq!(
            usage_for("/dev/sda1", Some("/boot"), Some("vfat"), 0, &ctx),
            "mounted at /boot (vfat)"
        );
        // ZFS member resolved to its pool name, or a bare fallback when unknown
        assert_eq!(
            usage_for("/dev/sdb", None, Some("zfs_member"), 0, &ctx),
            "ZFS pool: tank"
        );
        assert_eq!(
            usage_for("/dev/sdd", None, Some("zfs_member"), 0, &ctx),
            "ZFS pool member"
        );
        assert_eq!(
            usage_for("/dev/sde", None, Some("LVM2_member"), 0, &ctx),
            "LVM physical volume"
        );
        // raw device backing an export, a partitioned disk, a free disk, other fs
        assert_eq!(
            usage_for("/dev/sdc", None, None, 0, &ctx),
            "exported (NVMe-oF/iSCSI)"
        );
        assert_eq!(
            usage_for("/dev/sdf", None, None, 3, &ctx),
            "partitioned (3 partitions)"
        );
        assert_eq!(usage_for("/dev/sdg", None, None, 0, &ctx), "available");
        assert_eq!(usage_for("/dev/sdh1", None, Some("ext4"), 0, &ctx), "ext4");
    }

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

        // The index is a disk list; the per-disk and per-partition pages render
        // gracefully even when the named disk/partition is absent on this host.
        let req = auth(HttpRequest::get("/disks").body(Body::empty()).unwrap());
        let (status, _, body) = send(&app, req).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("Storage Devices"), "{body}");
        // The per-disk page renders gracefully (the host may have no sdb), and
        // when the disk exists it carries the SMART report + traffic charts.
        let req = auth(HttpRequest::get("/disks/sdb").body(Body::empty()).unwrap());
        let (status, _, body) = send(&app, req).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("sdb") || body.contains("not found"), "{body}");
        if body.contains("SMART report") {
            // Present disk: charts render and the canned SMART dump shows despite
            // smartctl's nonzero exit (fake helper returns ok:false).
            assert!(body.contains("<svg"), "traffic/temp charts render: {body}");
            assert!(body.contains("PASSED"), "smart dump shown verbatim: {body}");
        }
        let req = auth(
            HttpRequest::get("/disks/sdb/part/1")
                .body(Body::empty())
                .unwrap(),
        );
        let (status, _, body) = send(&app, req).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            body.contains("Partition") || body.contains("not found"),
            "{body}"
        );

        // Add-partition is a stay-op: it re-renders the disk detail partial.
        let req = auth(form_post(
            "/disks/part/create",
            "disk=sdb&size=100&unit=GiB&label=data",
        ));
        let (_, _, body) = send(&app, req).await;
        assert!(body.contains("started create partition on sdb"), "{body}");
        let req = auth(form_post(
            "/disks/part/create",
            "disk=..%2Fsda&size=&unit=GiB&label=data",
        ));
        let (_, _, body) = send(&app, req).await;
        assert!(body.contains("invalid disk name"), "{body}");

        // Delete is a remove-op: a non-htmx POST redirects back to the disk page.
        let req = auth(form_post("/disks/part/delete", "disk=sdb&number=2"));
        let (status, headers, _) = send(&app, req).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "non-htmx POST redirects");
        assert_eq!(headers[header::LOCATION], "/disks/sdb");

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
