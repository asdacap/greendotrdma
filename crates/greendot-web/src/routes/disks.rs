use super::{AppState, page};
use crate::actual::block;
use crate::auth::CurrentUser;
use crate::fmt::human_bytes;
use askama::Template;
use axum::extract::{Form, State};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Extension, Router};
use greendot_proto::{BlockDev, PartLabel, Request, Response as HelperResponse};
use serde::Deserialize;
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/disks", get(disks_page))
        .route("/disks/table", post(table_create))
        .route("/disks/part/create", post(part_create))
        .route("/disks/part/delete", post(part_delete))
}

pub struct PartRow {
    pub name: String,
    pub number: Option<u32>,
    pub size: String,
    pub label: String,
    pub mountpoint: String,
}

pub struct DiskRow {
    pub name: String,
    pub size: String,
    pub model: String,
    pub serial: String,
    pub partitions: Vec<PartRow>,
}

pub struct DisksView {
    pub disks: Vec<DiskRow>,
    pub error: Option<String>,
    pub flash: Option<String>,
    pub form_error: Option<String>,
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
                .map(|d| DiskRow {
                    size: human_bytes(d.size),
                    model: d.model.unwrap_or_default(),
                    serial: d.serial.unwrap_or_default(),
                    partitions: d
                        .partitions
                        .into_iter()
                        .map(|p| PartRow {
                            number: p.number,
                            size: human_bytes(p.size),
                            label: p.label.unwrap_or_default(),
                            mountpoint: p.mountpoint.unwrap_or_default(),
                            name: p.name,
                        })
                        .collect(),
                    name: d.name,
                })
                .collect();
        }
        Err(e) => view.error = Some(format!("could not list block devices: {e:#}")),
    }
    view
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

async fn after_mutation(result: anyhow::Result<HelperResponse>, success: String) -> Response {
    let view = match result {
        Ok(HelperResponse::Ok) => gather(Some(success), None).await,
        Ok(HelperResponse::Err { message, .. }) => gather(None, Some(message)).await,
        Ok(other) => gather(None, Some(format!("unexpected helper response: {other:?}"))).await,
        Err(e) => gather(None, Some(format!("helper unavailable: {e:#}"))).await,
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
    after_mutation(
        state.helper.call(req).await,
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
    after_mutation(
        state.helper.call(req).await,
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
    after_mutation(
        state.helper.call(req).await,
        format!("deleted partition {} on {disk}", form.number),
    )
    .await
}

#[cfg(test)]
mod tests {
    use crate::routes::testutil::{form_post, login, send, test_app};
    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode, header};

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
    }
}
