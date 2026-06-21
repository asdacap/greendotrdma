use super::{AppState, page};
use crate::auth::CurrentUser;
use crate::dot::{
    Criterion, external_iscsi_dot, external_nvme_dot, iscsi_diagnostics, iscsi_dot,
    nvme_diagnostics, nvme_dot,
};
use crate::reconcile::RECONCILE_ERROR_KEY;
use crate::state::{Export, ExportKind, NewExport};
use crate::{actual, reconcile};
use askama::Template;
use axum::extract::{Form, Path, State};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Extension, Router};
use greendot_proto::{DevicePath, DotState, ExportName, Nqn, OUR_IQN_PREFIX, OUR_NQN_PREFIX};
use serde::Deserialize;
use std::collections::HashSet;
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/exports", get(exports_page))
        .route("/exports/create", post(create))
        .route("/exports/toggle", post(toggle))
        .route("/exports/delete", post(delete))
        .route("/exports/{id}/diagnose", get(diagnose_page))
        .route("/partials/exports", get(dots_partial))
}

/// Serialized full reconcile against current desired state. A cheap in-process
/// drift pre-check keeps the steady state (and the 60 s timer) silent; on drift
/// it runs `greendot-cli reconcile` as a recorded, streamable task and surfaces
/// the outcome on the export dots and the settings banner. The web stays the
/// sole writer of the config — the CLI only reads it.
pub async fn reconcile_state(state: &AppState) -> anyhow::Result<()> {
    let _guard = state.reconcile_lock.lock().await;
    let exports = state.db.list_exports()?;
    let listen: std::net::IpAddr = state
        .db
        .get_setting("listen_addr")?
        .and_then(|s| s.parse().ok())
        .unwrap_or(std::net::Ipv4Addr::UNSPECIFIED.into());

    let nvmet_ok = reconcile::nvmet_satisfied(
        &reconcile::render_nvmet(&exports, listen),
        &actual::nvmet::read(&state.nvmet_root),
    );
    let lio_ok = reconcile::lio_satisfied(
        &reconcile::render_lio(&exports, listen),
        &actual::lio::read(&state.lio_root),
    );
    if nvmet_ok && lio_ok {
        return Ok(()); // already realized — emit no task
    }

    let outcome = crate::task_runner::run_local(
        state,
        &state.reconcile_cmd,
        "reconcile",
        "Reconcile exports",
    )
    .await?;
    let err = (!outcome.ok).then(|| outcome.error.unwrap_or_else(|| "reconcile failed".into()));

    // Surface the result on the dots of the protocols that drifted (the task's
    // output carries the detail) and on the settings banner.
    for e in exports.iter().filter(|e| e.enabled) {
        let drifted = match e.kind {
            ExportKind::Nvme => !nvmet_ok,
            ExportKind::Iscsi => !lio_ok,
        };
        state
            .db
            .set_export_error(e.id, drifted.then_some(err.as_deref()).flatten())?;
    }
    state
        .db
        .set_setting(RECONCILE_ERROR_KEY, err.as_deref().unwrap_or_default())?;
    Ok(())
}

pub struct ExportRow {
    pub id: i64,
    pub name: String,
    pub protocol: &'static str,
    pub dot_class: &'static str,
    pub dot_reason: String,
    pub device: String,
    pub transports: String,
    pub hosts: String,
    /// Connected client count for iSCSI (live sessions); `None` for NVMe-oF,
    /// whose RDMA peers can't be attributed per-export on this kernel.
    pub clients: Option<usize>,
    pub enabled: bool,
    /// RDMA was requested but the export isn't fully serving over RDMA — offer
    /// the per-criterion Diagnose page.
    pub diagnose: bool,
    /// Copy-paste commands a client runs to connect, one per network transport.
    pub client: Vec<ClientCmd>,
    /// Present on the box but not managed by greendot (foreign NQN/IQN, e.g.
    /// provisioned by democratic-csi). Rendered read-only with an "External"
    /// badge; its dot reflects only the observed transport.
    pub external: bool,
}

/// CSS class for a dot state. The disabled (gray) case is handled by the caller.
fn dot_class(state: DotState) -> &'static str {
    match state {
        DotState::Green => "dot-green",
        DotState::Yellow => "dot-yellow",
        DotState::Red => "dot-red",
    }
}

/// A labelled client-side connect command shown under each export.
pub struct ClientCmd {
    /// Which transport this connects over, e.g. "RDMA", "TCP", "iSER (RDMA)".
    pub label: String,
    /// The multi-line command block to run: load the fabrics module, connect
    /// (discovery + login for iSCSI), and a `# disconnect:` hint.
    pub cmd: String,
}

/// Builds the client connect command(s) for an export from its own data: the
/// protocol decides the tool (`nvme connect` vs `iscsiadm`), the wanted
/// transports decide how many, and `listen` supplies the target address. Ports
/// mirror the server side in [`crate::reconcile`] — NVMe-oF `TRSVCID` 4420;
/// iSCSI iSER 3260, plain TCP 3261 when iSER is also on else 3260 — kept as
/// literals here so this stays a self-contained, unit-testable helper. The
/// `loop` transport is local-only testing and is omitted. When `listen` is
/// unspecified (the default — the service listens on all interfaces) there is
/// no single reachable IP, so a `<server-ip>` placeholder is rendered.
fn client_instructions(e: &Export, listen: std::net::IpAddr) -> Vec<ClientCmd> {
    let addr = if listen.is_unspecified() {
        "<server-ip>".to_owned()
    } else {
        listen.to_string()
    };
    match e.kind {
        ExportKind::Nvme => {
            let nqn = e.nqn();
            // Each transport needs its own fabrics module loaded first, or the
            // connect fails with "/dev/nvme-fabrics: No such file or directory".
            [
                (e.want_rdma, "rdma", "RDMA", "nvme-rdma"),
                (e.want_tcp, "tcp", "TCP", "nvme-tcp"),
            ]
            .into_iter()
            .filter(|(want, ..)| *want)
            .map(|(_, trtype, label, module)| ClientCmd {
                label: label.to_owned(),
                cmd: format!(
                    "modprobe {module}\n\
                     nvme connect -t {trtype} -a {addr} -s 4420 -n {nqn}\n\
                     # disconnect: nvme disconnect -n {nqn}"
                ),
            })
            .collect()
        }
        ExportKind::Iscsi => {
            let iqn = e.iqn();
            let mut cmds = Vec::new();
            if e.want_rdma {
                cmds.push(ClientCmd {
                    label: "iSER (RDMA)".to_owned(),
                    cmd: format!(
                        "modprobe ib_iser\n\
                         iscsiadm -m discovery -t st -p {addr}:3260 -I iser\n\
                         iscsiadm -m node -T {iqn} -p {addr}:3260 -I iser --login\n\
                         # disconnect: iscsiadm -m node -T {iqn} -p {addr}:3260 -I iser --logout"
                    ),
                });
            }
            if e.want_tcp {
                let port = if e.want_rdma { 3261 } else { 3260 };
                cmds.push(ClientCmd {
                    label: "TCP".to_owned(),
                    cmd: format!(
                        "iscsiadm -m discovery -t st -p {addr}:{port}\n\
                         iscsiadm -m node -T {iqn} -p {addr}:{port} --login\n\
                         # disconnect: iscsiadm -m node -T {iqn} -p {addr}:{port} --logout"
                    ),
                });
            }
            cmds
        }
    }
}

/// Rows for NVMe-oF subsystems present in nvmet but outside greendot's NQN
/// prefix. Their dot reflects only the observed transport (see [`external_nvme_dot`]).
fn foreign_nvme_rows(
    actual: &actual::nvmet::ActualNvmet,
    rdma: &[actual::rdma::RdmaDev],
) -> Vec<ExportRow> {
    actual
        .subsystems
        .iter()
        .filter(|s| !s.nqn.starts_with(OUR_NQN_PREFIX))
        .map(|s| {
            let dot = external_nvme_dot(&s.nqn, actual, rdma);
            let mut transports: Vec<&str> = actual
                .ports
                .iter()
                .filter(|p| p.subsystems.iter().any(|n| n == &s.nqn))
                .map(|p| match p.trtype.as_str() {
                    "rdma" => "RDMA",
                    "tcp" => "TCP",
                    "loop" => "loop",
                    other => other,
                })
                .collect();
            transports.sort_unstable();
            transports.dedup();
            ExportRow {
                id: 0,
                name: s.nqn.clone(),
                protocol: "NVMe-oF",
                dot_class: dot_class(dot.state),
                dot_reason: dot.reason,
                device: join_devices(s.namespaces.iter().map(|n| n.device_path.as_str())),
                transports: transports.join(" + "),
                hosts: if s.allow_any_host {
                    "any host".into()
                } else {
                    format!("{} allowed", s.allowed_hosts.len())
                },
                clients: None,
                enabled: true,
                diagnose: false,
                client: vec![],
                external: true,
            }
        })
        .collect()
}

/// Rows for iSCSI targets present in LIO but outside greendot's IQN prefix.
fn foreign_iscsi_rows(
    actual: &actual::lio::ActualLio,
    sessions: &[actual::lio::IscsiSession],
    rdma: &[actual::rdma::RdmaDev],
) -> Vec<ExportRow> {
    actual
        .targets
        .iter()
        .filter(|t| !t.iqn.starts_with(OUR_IQN_PREFIX))
        .map(|t| {
            let dot = external_iscsi_dot(t, rdma);
            let mut transports: Vec<&str> = Vec::new();
            if t.portals.iter().any(|p| p.iser) {
                transports.push("iSER");
            }
            if t.portals.iter().any(|p| !p.iser) {
                transports.push("TCP");
            }
            let devices = t.luns.iter().filter_map(|lun| {
                actual
                    .backstores
                    .iter()
                    .find(|b| &b.name == lun)
                    .map(|b| b.udev_path.as_str())
            });
            ExportRow {
                id: 0,
                name: t.iqn.clone(),
                protocol: "iSCSI",
                dot_class: dot_class(dot.state),
                dot_reason: dot.reason,
                device: join_devices(devices),
                transports: transports.join(" + "),
                hosts: if t.demo_mode {
                    "any host".into()
                } else {
                    format!("{} allowed", t.acls.len())
                },
                clients: Some(sessions.iter().filter(|s| s.target_iqn == t.iqn).count()),
                enabled: true,
                diagnose: false,
                client: vec![],
                external: true,
            }
        })
        .collect()
}

/// Joins backing-device paths for display, collapsing the empty set to an em dash.
fn join_devices<'a>(devices: impl Iterator<Item = &'a str>) -> String {
    let devices: Vec<&str> = devices.filter(|d| !d.is_empty()).collect();
    if devices.is_empty() {
        "—".to_owned()
    } else {
        devices.join(", ")
    }
}

pub struct ExportsView {
    pub rows: Vec<ExportRow>,
    pub devices: Vec<crate::actual::block::AvailDevice>,
    pub banner: Option<String>,
    pub flash: Option<String>,
    pub form_error: Option<String>,
}

pub async fn gather(
    state: &AppState,
    flash: Option<String>,
    form_error: Option<String>,
) -> ExportsView {
    let mut view = ExportsView {
        rows: vec![],
        devices: vec![],
        banner: None,
        flash,
        form_error,
    };
    let actual_nvmet = actual::nvmet::read(&state.nvmet_root);
    let actual_lio = actual::lio::read(&state.lio_root);
    let iscsi_sessions = actual::lio::sessions(&state.lio_root);
    let rdma = actual::rdma::devices();
    let listen: std::net::IpAddr = state
        .db
        .get_setting("listen_addr")
        .ok()
        .flatten()
        .and_then(|s| s.parse().ok())
        .unwrap_or(std::net::Ipv4Addr::UNSPECIFIED.into());
    let mut in_use: HashSet<String> = HashSet::new();
    match state.db.list_exports() {
        Ok(exports) => {
            in_use.extend(exports.iter().map(|e| e.device_path.clone()));
            view.rows = exports
                .iter()
                .map(|e| {
                    let (dot_class, dot_reason, diagnose) = if !e.enabled {
                        ("dot-gray", "disabled".to_owned(), false)
                    } else {
                        let dot = match e.kind {
                            ExportKind::Nvme => nvme_dot(e, &actual_nvmet, &rdma),
                            ExportKind::Iscsi => iscsi_dot(e, &actual_lio, &rdma),
                        };
                        (
                            dot_class(dot.state),
                            dot.reason,
                            e.want_rdma && dot.state != DotState::Green,
                        )
                    };
                    let mut transports = Vec::new();
                    for (want, label) in [
                        (e.want_rdma, "RDMA"),
                        (e.want_tcp, "TCP"),
                        (e.want_loop, "loop"),
                    ] {
                        if want {
                            transports.push(label);
                        }
                    }
                    let clients = match e.kind {
                        ExportKind::Iscsi => {
                            let iqn = e.iqn();
                            Some(
                                iscsi_sessions
                                    .iter()
                                    .filter(|s| s.target_iqn == iqn.as_str())
                                    .count(),
                            )
                        }
                        ExportKind::Nvme => None,
                    };
                    ExportRow {
                        id: e.id,
                        name: e.name.clone(),
                        protocol: match e.kind {
                            ExportKind::Nvme => "NVMe-oF",
                            ExportKind::Iscsi => "iSCSI",
                        },
                        dot_class,
                        dot_reason,
                        device: e.device_path.clone(),
                        transports: transports.join(" + "),
                        hosts: if e.allow_any_host {
                            "any host".into()
                        } else {
                            format!("{} allowed", e.initiators.len())
                        },
                        clients,
                        enabled: e.enabled,
                        diagnose,
                        client: client_instructions(e, listen),
                        external: false,
                    }
                })
                .collect();
        }
        Err(e) => view.banner = Some(format!("could not read export store: {e:#}")),
    }

    // Foreign exports: subsystems/targets present on the box that greendot didn't
    // create (NQN/IQN outside our prefix — e.g. democratic-csi). We don't manage
    // them, but the dashboard's whole job is to say whether an export is honestly
    // on RDMA, so we observe them read-only with the same dot.
    view.rows.extend(foreign_nvme_rows(&actual_nvmet, &rdma));
    view.rows
        .extend(foreign_iscsi_rows(&actual_lio, &iscsi_sessions, &rdma));
    if let Ok(Some(err)) = state.db.get_setting(RECONCILE_ERROR_KEY)
        && !err.is_empty()
    {
        view.banner = Some(format!("reconcile problem: {err}"));
    }
    view.devices = actual::block::available_block_devices(&state.helper, &in_use).await;
    view
}

#[derive(Template)]
#[template(path = "exports.html")]
struct ExportsTemplate {
    user: CurrentUser,
    view: ExportsView,
}

#[derive(Template)]
#[template(path = "_exports.html")]
struct ExportsPartial {
    view: ExportsView,
}

#[derive(Template)]
#[template(path = "_dots.html")]
struct DotsPartial {
    view: ExportsView,
}

pub struct DiagnoseView {
    pub name: String,
    pub protocol: &'static str,
    pub dot_class: &'static str,
    pub dot_reason: String,
    pub criteria: Vec<Criterion>,
    pub not_found: bool,
}

#[derive(Template)]
#[template(path = "diagnose.html")]
struct DiagnoseTemplate {
    user: CurrentUser,
    view: DiagnoseView,
}

async fn gather_diagnose(state: &AppState, id: i64) -> DiagnoseView {
    let export = state
        .db
        .list_exports()
        .ok()
        .and_then(|exports| exports.into_iter().find(|e| e.id == id));
    let Some(export) = export else {
        return DiagnoseView {
            name: String::new(),
            protocol: "",
            dot_class: "dot-gray",
            dot_reason: String::new(),
            criteria: vec![],
            not_found: true,
        };
    };
    let rdma = actual::rdma::devices();
    // NICs that are RoCE-capable but have RoCE switched off — surfaced when no
    // RDMA device exists, so the checklist explains why and points at Settings.
    let capable_disabled: Vec<String> = actual::nic::interfaces()
        .into_iter()
        .filter(|n| matches!(n.kind, actual::nic::NicRdmaKind::CapableDisabled { .. }))
        .map(|n| n.netdev)
        .collect();
    let (criteria, dot, protocol) = match export.kind {
        ExportKind::Nvme => {
            let nvmet = actual::nvmet::read(&state.nvmet_root);
            (
                nvme_diagnostics(&export, &nvmet, &rdma, &capable_disabled),
                nvme_dot(&export, &nvmet, &rdma),
                "NVMe-oF",
            )
        }
        ExportKind::Iscsi => {
            let lio = actual::lio::read(&state.lio_root);
            (
                iscsi_diagnostics(&export, &lio, &rdma, &capable_disabled),
                iscsi_dot(&export, &lio, &rdma),
                "iSCSI",
            )
        }
    };
    DiagnoseView {
        name: export.name,
        protocol,
        dot_class: dot_class(dot.state),
        dot_reason: dot.reason,
        criteria,
        not_found: false,
    }
}

async fn diagnose_page(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<i64>,
) -> Response {
    page(DiagnoseTemplate {
        user,
        view: gather_diagnose(&state, id).await,
    })
}

async fn exports_page(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    page(ExportsTemplate {
        user,
        view: gather(&state, None, None).await,
    })
}

async fn dots_partial(State(state): State<Arc<AppState>>) -> Response {
    page(DotsPartial {
        view: gather(&state, None, None).await,
    })
}

async fn finish(state: &AppState, result: anyhow::Result<()>, success: String) -> Response {
    let (flash, error) = match result {
        Ok(()) => (Some(success), None),
        Err(e) => (None, Some(format!("{e:#}"))),
    };
    page(ExportsPartial {
        view: gather(state, flash, error).await,
    })
}

#[derive(Deserialize)]
struct CreateForm {
    name: String,
    device: String,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    want_rdma: Option<String>,
    #[serde(default)]
    want_tcp: Option<String>,
    #[serde(default)]
    want_loop: Option<String>,
    #[serde(default)]
    allow_any_host: Option<String>,
    #[serde(default)]
    initiators: String,
}

async fn create(State(state): State<Arc<AppState>>, Form(form): Form<CreateForm>) -> Response {
    let view_err = |msg: String| async {
        page(ExportsPartial {
            view: gather(&state, None, Some(msg)).await,
        })
    };
    let Ok(name) = ExportName::new(form.name.trim()) else {
        return view_err(format!(
            "invalid export name {:?} (lowercase letters, digits, '-', '.')",
            form.name
        ))
        .await;
    };
    let Ok(device) = DevicePath::new(form.device.trim()) else {
        return view_err(format!("invalid device path {:?}", form.device)).await;
    };
    let kind = match form.kind.as_str() {
        "iscsi" => ExportKind::Iscsi,
        _ => ExportKind::Nvme,
    };
    let initiators: Vec<String> = form
        .initiators
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(Into::into)
        .collect();
    let bad = initiators.iter().find(|i| match kind {
        ExportKind::Nvme => Nqn::new((*i).clone()).is_err(),
        ExportKind::Iscsi => greendot_proto::Iqn::new((*i).clone()).is_err(),
    });
    if let Some(bad) = bad {
        return view_err(format!("invalid initiator name {bad:?}")).await;
    }
    let allow_any_host = form.allow_any_host.is_some() || initiators.is_empty();
    if !(form.want_rdma.is_some() || form.want_tcp.is_some() || form.want_loop.is_some()) {
        return view_err("select at least one transport".into()).await;
    }
    let new = NewExport {
        kind,
        name: name.to_string(),
        device_path: device.to_string(),
        want_rdma: form.want_rdma.is_some(),
        want_tcp: form.want_tcp.is_some(),
        want_loop: form.want_loop.is_some(),
        allow_any_host,
        initiators,
    };
    let result = match state.db.insert_export(&new) {
        Ok(_) => reconcile_state(&state).await,
        Err(e) => Err(e),
    };
    finish(&state, result, format!("created export {name}")).await
}

#[derive(Deserialize)]
struct IdForm {
    id: i64,
    #[serde(default)]
    enable: Option<bool>,
}

async fn toggle(State(state): State<Arc<AppState>>, Form(form): Form<IdForm>) -> Response {
    let enable = form.enable.unwrap_or(false);
    let result = match state.db.set_export_enabled(form.id, enable) {
        Ok(()) => reconcile_state(&state).await,
        Err(e) => Err(e),
    };
    finish(
        &state,
        result,
        format!("export {}", if enable { "enabled" } else { "disabled" }),
    )
    .await
}

async fn delete(State(state): State<Arc<AppState>>, Form(form): Form<IdForm>) -> Response {
    let result = match state.db.delete_export(form.id) {
        Ok(()) => reconcile_state(&state).await,
        Err(e) => Err(e),
    };
    finish(&state, result, "export deleted".into()).await
}

#[cfg(test)]
mod tests {
    use crate::routes::testutil::{form_post, login, send, test_app};
    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode, header};

    #[test]
    fn client_instructions_per_protocol_transport_and_address() {
        use crate::state::{Export, ExportKind};
        use std::net::{IpAddr, Ipv4Addr};

        let export = |kind, want_rdma, want_tcp| Export {
            id: 1,
            kind,
            name: "vm1".into(),
            device_path: "/dev/zvol/tank/vm1".into(),
            enabled: true,
            want_rdma,
            want_tcp,
            want_loop: true, // local-only — must never surface as a client command
            allow_any_host: true,
            initiators: vec![],
            last_error: None,
        };
        let addr: IpAddr = Ipv4Addr::new(10, 0, 0, 5).into();

        // NVMe-oF: one block per network transport (loop omitted), each with its
        // fabrics module prerequisite, the connect (derived NQN, port 4420, the
        // concrete listen address), and a disconnect hint.
        let nvme = super::client_instructions(&export(ExportKind::Nvme, true, true), addr);
        assert_eq!(nvme.len(), 2);
        for (cmd, module, trtype) in [
            (&nvme[0].cmd, "nvme-rdma", "rdma"),
            (&nvme[1].cmd, "nvme-tcp", "tcp"),
        ] {
            assert!(cmd.contains(&format!("modprobe {module}")), "{cmd}");
            assert!(
                cmd.contains(&format!(
                    "nvme connect -t {trtype} -a 10.0.0.5 -s 4420 -n nqn.2026-06.io.greendot:vm1"
                )),
                "{cmd}"
            );
            assert!(
                cmd.contains("# disconnect: nvme disconnect -n nqn.2026-06.io.greendot:vm1"),
                "{cmd}"
            );
        }

        // iSCSI: iSER on 3260, plain TCP bumped to 3261 because iSER is also on;
        // each is a discovery + login pair against the derived IQN.
        let iscsi = super::client_instructions(&export(ExportKind::Iscsi, true, true), addr);
        assert_eq!(iscsi.len(), 2);
        assert!(
            iscsi[0].cmd.contains("iqn.2026-06.io.greendot:vm1"),
            "{}",
            iscsi[0].cmd
        );
        assert!(
            iscsi[0].cmd.contains("-p 10.0.0.5:3260 -I iser --login"),
            "{}",
            iscsi[0].cmd
        );
        assert!(
            iscsi[0].cmd.contains("modprobe ib_iser"),
            "{}",
            iscsi[0].cmd
        );
        assert!(
            iscsi[0].cmd.contains("-p 10.0.0.5:3260 -I iser --logout"),
            "{}",
            iscsi[0].cmd
        );
        assert!(
            iscsi[1].cmd.contains("-p 10.0.0.5:3261 --login"),
            "{}",
            iscsi[1].cmd
        );
        // TCP-only iSCSI keeps the standard 3260 port.
        let tcp_only = super::client_instructions(&export(ExportKind::Iscsi, false, true), addr);
        assert_eq!(tcp_only.len(), 1);
        assert!(
            tcp_only[0].cmd.contains("-p 10.0.0.5:3260 --login"),
            "{}",
            tcp_only[0].cmd
        );

        // An unspecified listen address renders the <server-ip> placeholder.
        let unspec = super::client_instructions(
            &export(ExportKind::Nvme, true, false),
            Ipv4Addr::UNSPECIFIED.into(),
        );
        assert!(
            unspec[0].cmd.contains("-a <server-ip> -s 4420"),
            "{}",
            unspec[0].cmd
        );
    }

    #[tokio::test]
    async fn create_toggle_delete_flow_against_fake_helper() {
        let app = test_app();
        let (cookie, csrf) = login(&app).await;
        let auth = |mut req: HttpRequest<Body>| {
            req.headers_mut()
                .insert(header::COOKIE, cookie.parse().unwrap());
            req.headers_mut()
                .insert("x-greendot-csrf", csrf.parse().unwrap());
            req
        };

        // Create: stored, reconciled (fake helper says Ok), red dot because
        // the (empty tempdir) nvmet tree shows nothing configured.
        let req = auth(form_post(
            "/exports/create",
            "name=vm1&device=%2Fdev%2Fzvol%2Ftank%2Fvm1&want_rdma=1&want_tcp=1&initiators=nqn.2014-08.org.nvmexpress%3Ahost1",
        ));
        let (status, _, body) = send(&app, req).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("created export vm1"), "{body}");
        assert!(
            body.contains("dot-red"),
            "nothing actually configured yet: {body}"
        );
        assert!(body.contains("RDMA + TCP"), "{body}");
        // RDMA requested but not yet served → a Diagnose link is offered.
        assert!(body.contains("/exports/1/diagnose"), "{body}");
        // Each export carries a copy-paste client connect command.
        assert!(body.contains("Client instruction"), "{body}");
        assert!(
            body.contains("nvme connect -t rdma") && body.contains("nqn.2026-06.io.greendot:vm1"),
            "{body}"
        );

        // iSCSI export with an IQN initiator works and shows its protocol.
        let req = auth(form_post(
            "/exports/create",
            "kind=iscsi&name=tape&device=%2Fdev%2Fzvol%2Ftank%2Ftape&want_rdma=1&initiators=iqn.1993-08.org.debian%3A01%3Aabc",
        ));
        let (_, _, body) = send(&app, req).await;
        assert!(body.contains("created export tape"), "{body}");
        assert!(body.contains("iSCSI"), "{body}");
        // ...but an NQN-style initiator on an iSCSI export is rejected.
        let req = auth(form_post(
            "/exports/create",
            "kind=iscsi&name=bad&device=%2Fdev%2Fsda&want_tcp=1&initiators=nqn.2014-08.org.nvmexpress%3Ahost1",
        ));
        let (_, _, body) = send(&app, req).await;
        assert!(body.contains("invalid initiator name"), "{body}");

        // Bad device path rejected.
        let req = auth(form_post(
            "/exports/create",
            "name=vm2&device=%2Fetc%2Fshadow&want_tcp=1",
        ));
        let (_, _, body) = send(&app, req).await;
        assert!(body.contains("invalid device path"), "{body}");

        // Dashboard partial shows the export card.
        let req = auth(
            HttpRequest::get("/partials/exports")
                .body(Body::empty())
                .unwrap(),
        );
        let (status, _, body) = send(&app, req).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("vm1"), "{body}");

        // Toggle off → gray dot; delete → gone.
        let (_, _, body) = send(
            &app,
            auth(form_post("/exports/toggle", "id=1&enable=false")),
        )
        .await;
        assert!(body.contains("dot-gray"), "{body}");
        let (_, _, body) = send(&app, auth(form_post("/exports/delete", "id=1"))).await;
        assert!(
            body.contains("tape"),
            "iSCSI export must survive deleting the other: {body}"
        );
        let (_, _, body) = send(&app, auth(form_post("/exports/delete", "id=2"))).await;
        assert!(body.contains("No exports yet"), "{body}");
    }

    #[tokio::test]
    async fn diagnose_page_lists_rdma_criteria() {
        let app = test_app();
        let (cookie, csrf) = login(&app).await;
        let auth = |mut req: HttpRequest<Body>| {
            req.headers_mut()
                .insert(header::COOKIE, cookie.parse().unwrap());
            req.headers_mut()
                .insert("x-greendot-csrf", csrf.parse().unwrap());
            req
        };
        send(
            &app,
            auth(form_post(
                "/exports/create",
                "name=vm1&device=%2Fdev%2Fzvol%2Ftank%2Fvm1&want_rdma=1&want_tcp=1",
            )),
        )
        .await;

        // The checklist renders, with the config rows failing because the
        // (empty tempdir) nvmet tree configures nothing.
        let req = auth(
            HttpRequest::get("/exports/1/diagnose")
                .body(Body::empty())
                .unwrap(),
        );
        let (status, _, body) = send(&app, req).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("RDMA requested"), "{body}");
        assert!(body.contains("Subsystem configured"), "{body}");
        assert!(body.contains("Listen address served"), "{body}");

        // An unknown id is a graceful not-found, not a 500.
        let req = auth(
            HttpRequest::get("/exports/999/diagnose")
                .body(Body::empty())
                .unwrap(),
        );
        let (status, _, body) = send(&app, req).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("Export not found"), "{body}");
    }

    #[tokio::test]
    async fn reconcile_state_drift_gates_records_one_task_and_surfaces_errors() {
        use crate::routes::testutil::{test_state, test_state_with};
        use crate::state::{ExportKind, NewExport};

        let nvme = |name: &str| NewExport {
            kind: ExportKind::Nvme,
            name: name.into(),
            device_path: "/dev/zvol/tank/vm1".into(),
            want_rdma: true,
            want_tcp: false,
            want_loop: false,
            allow_any_host: false,
            initiators: vec![],
        };

        // No exports → already satisfied → no task is recorded.
        let state = test_state();
        super::reconcile_state(&state).await.unwrap();
        assert!(
            state.db.list_tasks(10).unwrap().is_empty(),
            "steady state must emit no task"
        );

        // An enabled export over an empty configfs tree is drift → exactly one
        // recorded "reconcile" task, and success clears the stale export error.
        let id = state.db.insert_export(&nvme("vm1")).unwrap();
        state.db.set_export_error(id, Some("stale")).unwrap();
        super::reconcile_state(&state).await.unwrap();
        let tasks = state.db.list_tasks(10).unwrap();
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].kind, "reconcile");
        assert_eq!(state.db.list_exports().unwrap()[0].last_error, None);

        // A failing reconcile command sets the banner and the export error.
        let state = test_state_with(vec!["false".into()]);
        state.db.insert_export(&nvme("vm1")).unwrap();
        super::reconcile_state(&state).await.unwrap();
        assert!(
            state
                .db
                .get_setting(crate::reconcile::RECONCILE_ERROR_KEY)
                .unwrap()
                .is_some_and(|s| !s.is_empty())
        );
        assert!(state.db.list_exports().unwrap()[0].last_error.is_some());
    }
}
