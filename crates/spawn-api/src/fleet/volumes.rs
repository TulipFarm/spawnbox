//! Volumes in a fleet. A volume's file is on one host, its home. The
//! primary sends sandboxes that mount a volume to its home, or first copies
//! volumes no sandbox uses to a host that can take the sandbox.
//!
//! The primary's database is the source of truth. A worker keeps copies of
//! the volumes it has files for, sent before each create or move.

use std::collections::BTreeSet;

use axum::Json;
use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::migrate::{self, json_body, ok_or_error};
use super::primary::Primary;
use crate::db::{self, NodeRow, VolumeRef};
use crate::model::{ApiError, Code};
use crate::server::{App, AppState, parse};

/// The one file in a volume's package.
const FILE: &str = "volume.ext4";

#[derive(Serialize, Deserialize)]
pub struct VolumePush {
    pub volumes: Vec<db::Volume>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Drop {
    id: String,
    /// The volume is deleted, not moved: forget it too.
    #[serde(default)]
    deleted: bool,
}

/// Streams the package of a volume whose file is on this host.
fn export(app: &App, id: &str) -> Result<Body, ApiError> {
    let volume = app
        .db
        .get_volume_by_id(id)?
        .ok_or_else(ApiError::not_found)?;
    let file = app.volumes.file(id);
    if !file.exists() {
        return Err(ApiError::new(
            Code::NotFound,
            format!("volume {} has no file on this host", volume.name),
        ));
    }
    Ok(migrate::stream_package(
        format!("export volume {id}"),
        volume,
        vec![(FILE, file)],
    ))
}

/// Places the file of a volume's package on this host.
async fn import(app: &App, body: Body) -> Result<db::Volume, ApiError> {
    let staged = app.sandboxes.staging_dir().map_err(ApiError::internal)?;
    std::fs::create_dir_all(&staged).map_err(|e| ApiError::internal(format!("staging: {e}")))?;
    let input = migrate::reader(body);
    let dir = staged.clone();
    let read = tokio::task::spawn_blocking(move || {
        migrate::read_package::<db::Volume>(input, &dir, &[FILE], &[FILE], |_| Ok(()))
    })
    .await
    .map_err(|e| ApiError::internal(format!("task failed: {e}")))
    .and_then(|read| read.map_err(|e| ApiError::invalid(format!("{e:#}"))))
    .and_then(|volume| {
        std::fs::rename(staged.join(FILE), app.volumes.file(&volume.id))
            .map_err(|e| ApiError::internal(format!("place volume: {e}")))?;
        Ok(volume)
    });
    let _ = std::fs::remove_dir_all(&staged);
    read
}

/// Removes a volume's file from this host, unless a sandbox here that is
/// not cold uses it.
fn drop_here(app: &App, id: &str, deleted: bool) -> Result<(), ApiError> {
    let users = app.db.volume_holders(id)?;
    if !users.is_empty() {
        return Err(ApiError::new(
            Code::Conflict,
            format!("volume {id} is mounted here"),
        ));
    }
    if deleted {
        let _ = app.db.delete_volume(id, crate::runtime::now_ms())?;
    }
    app.volumes.remove_file(id);
    Ok(())
}

pub async fn put_here(State(app): State<AppState>, body: Bytes) -> Result<Json<Value>, ApiError> {
    let push: VolumePush = parse(&body)?;
    for volume in &push.volumes {
        app.db.put_volume(volume)?;
    }
    Ok(Json(json!({})))
}

pub async fn export_here(State(app): State<AppState>, body: Bytes) -> Response {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct One {
        id: String,
    }
    let result = parse::<One>(&body).and_then(|one| export(&app, &one.id));
    match result {
        Ok(body) => {
            let mut resp = Response::new(body);
            resp.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            );
            resp
        }
        Err(error) => error.into_response(),
    }
}

pub async fn import_here(
    State(app): State<AppState>,
    req: Request,
) -> Result<Json<Value>, ApiError> {
    let volume = import(&app, req.into_body()).await?;
    app.db.put_volume(&volume)?;
    Ok(Json(json!({})))
}

pub async fn drop_here_route(
    State(app): State<AppState>,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    let drop: Drop = parse(&body)?;
    drop_here(&app, &drop.id, drop.deleted)?;
    Ok(Json(json!({})))
}

/// Sends the primary's copy of `volumes` to `node`.
pub async fn push(
    app: &App,
    p: &Primary,
    node: &NodeRow,
    volumes: &[VolumeRef],
) -> Result<(), ApiError> {
    if volumes.is_empty() {
        return Ok(());
    }
    let mut rows = Vec::new();
    for volume in volumes {
        if let Some(row) = app.db.get_volume_by_id(&volume.volume)? {
            rows.push(row);
        }
    }
    let _: Value = p
        .call(node, "/fleet/v1/volumes/put", &VolumePush { volumes: rows })
        .await?;
    Ok(())
}

/// Deletes a volume and removes its file from its home. In a fleet, holds
/// the volume lock so no create or copy uses it meanwhile.
pub async fn delete(app: &App, tenant: &str, name: &str) -> Result<db::Volume, ApiError> {
    let Ok(p) = super::primary::primary(app) else {
        return app.volumes.delete(tenant, name);
    };
    let _lock = p.volume_lock.write().await;
    let volume = app.volumes.delete(tenant, name)?;
    let Some(node) = &volume.node else {
        return Ok(volume);
    };
    let Some(row) = app.db.get_node(node)? else {
        return Ok(volume);
    };
    let dropped: Result<Value, _> = p
        .call(
            &row,
            "/fleet/v1/volumes/drop",
            &json!({ "id": volume.id, "deleted": true }),
        )
        .await;
    if let Err(error) = dropped {
        eprintln!("remove volume {} on {node}: {}", volume.id, error.message);
    }
    Ok(volume)
}

/// Copies an unused volume from its home to `to` (`None`: the primary),
/// then removes it from its home.
pub async fn copy(
    app: &App,
    p: &Primary,
    volume: &db::Volume,
    to: Option<&NodeRow>,
) -> Result<(), ApiError> {
    let backend = volume
        .backend
        .clone()
        .ok_or_else(|| ApiError::internal("an unplaced volume has no file to copy"))?;
    let from = match &volume.node {
        Some(id) => Some(app.db.get_node(id)?.ok_or_else(|| {
            ApiError::new(
                Code::NodeUnreachable,
                format!("the host of volume {:?} was removed", volume.name),
            )
        })?),
        None => None,
    };
    if from.as_ref().map(|n| &n.id) == to.map(|n| &n.id) {
        return Ok(());
    }
    let users = app.db.volume_holders(&volume.id)?;
    if !users.is_empty() {
        let ids: Vec<_> = users.iter().map(|u| u.sandbox.as_str()).collect();
        return Err(ApiError::new(
            Code::Conflict,
            format!(
                "volume {:?} is on another host, mounted in {}",
                volume.name,
                ids.join(", ")
            ),
        ));
    }
    let body = match &from {
        None => export(app, &volume.id)?,
        Some(node) => {
            let resp = p
                .send(
                    node,
                    "/fleet/v1/volumes/export",
                    json_body(&json!({ "id": volume.id })),
                )
                .await?;
            ok_or_error(node, resp).await?.into_body()
        }
    };
    match to {
        None => {
            import(app, body).await?;
        }
        Some(node) => {
            let resp = p.send(node, "/fleet/v1/volumes/import", body).await?;
            ok_or_error(node, resp).await?;
        }
    }
    // The source refuses if a sandbox there began to use it; then the copy
    // is stale, so remove it and keep the old home.
    let dropped = match &from {
        None => drop_here(app, &volume.id, false),
        Some(node) => p
            .call::<_, Value>(node, "/fleet/v1/volumes/drop", &json!({ "id": volume.id }))
            .await
            .map(|_| ()),
    };
    match dropped {
        Err(error) if error.code == Code::Conflict => {
            let undone = match to {
                None => {
                    app.volumes.remove_file(&volume.id);
                    Ok(())
                }
                Some(node) => p
                    .call::<_, Value>(node, "/fleet/v1/volumes/drop", &json!({ "id": volume.id }))
                    .await
                    .map(|_| ()),
            };
            if let Err(e) = undone {
                eprintln!("remove stale copy of volume {}: {}", volume.id, e.message);
            }
            return Err(error);
        }
        Err(error) => eprintln!(
            "remove copied volume {} at its old home: {}",
            volume.id, error.message
        ),
        Ok(()) => {}
    }
    app.db
        .set_volume_home(&volume.id, to.map(|n| n.id.as_str()), &backend)?;
    eprintln!(
        "volume {} copied from {} to {}",
        volume.id,
        from.as_ref().map_or(migrate::PRIMARY, |n| n.id.as_str()),
        to.map_or(migrate::PRIMARY, |n| n.id.as_str()),
    );
    Ok(())
}

/// Hosts that can take the volumes of a draining `node`: the primary and
/// the ready workers that are not draining, most free memory first.
fn targets(app: &App, p: &Primary, node: &str) -> Vec<(Option<NodeRow>, super::Capacity)> {
    let ready: std::collections::HashMap<String, NodeRow> = app
        .db
        .list_nodes()
        .unwrap_or_default()
        .into_iter()
        .filter(|n| n.id != node && n.state == db::node_state::READY && !n.draining)
        .map(|n| (n.id.clone(), n))
        .collect();
    let local = super::local_capacity(app);
    let mut hosts: Vec<(Option<NodeRow>, super::Capacity)> = vec![(None, local)];
    for (id, capacity) in p.capacities() {
        if let Some(row) = ready.get(&id) {
            hosts.push((Some(row.clone()), capacity));
        }
    }
    hosts.sort_by_key(|(_, c)| std::cmp::Reverse(c.memory_available_mib));
    hosts
}

/// Why the volumes of `sandbox` cannot leave draining `node`, if they
/// cannot: no other host has the backend of one that is there.
pub fn stuck(app: &App, p: &Primary, node: &str, sandbox: &db::Sandbox) -> Option<String> {
    let backends: Vec<String> = targets(app, p, node)
        .into_iter()
        .map(|(_, c)| c.backend)
        .collect();
    let volumes: Vec<db::Volume> = sandbox
        .volumes
        .iter()
        .filter_map(|v| app.db.get_volume_by_id(&v.volume).ok().flatten())
        .collect();
    unmovable(&volumes, node, &backends)
}

/// The first of `volumes` homed on `node` that no host with one of
/// `backends` can take.
fn unmovable(volumes: &[db::Volume], node: &str, backends: &[String]) -> Option<String> {
    let row = volumes.iter().find(|row| {
        row.node.as_deref() == Some(node)
            && !backends
                .iter()
                .any(|b| row.backend.as_deref() == Some(b.as_str()))
    })?;
    Some(format!(
        "volume {:?} cannot leave: no other ready host has the {} backend",
        row.name,
        row.backend.as_deref().unwrap_or("same")
    ))
}

/// Copies the volumes that no sandbox holds off a draining `node`, to the
/// host with the same backend and the most free memory. Volumes of cold
/// sandboxes move too. Returns how many moved and how many did not.
pub async fn evacuate(app: &App, p: &Primary, node: &str) -> (u32, u32) {
    let _lock = p.volume_lock.write().await;
    let volumes: Vec<db::Volume> = app
        .db
        .list_volumes(None)
        .unwrap_or_default()
        .into_iter()
        .filter(|v| v.node.as_deref() == Some(node))
        .collect();
    let (mut moved, mut failed) = (0, 0);
    if volumes.is_empty() {
        return (moved, failed);
    }
    let hosts = targets(app, p, node);
    for volume in volumes {
        if !app
            .db
            .volume_holders(&volume.id)
            .unwrap_or_default()
            .is_empty()
        {
            // Its sandbox did not move; the volume stays with it.
            failed += 1;
            continue;
        }
        let to = hosts
            .iter()
            .find(|(_, c)| volume.backend.as_deref() == Some(c.backend.as_str()));
        let copied = match to {
            Some((to, _)) => copy(app, p, &volume, to.as_ref()).await,
            None => Err(ApiError::new(
                Code::NoCapacity,
                "no other host has the volume's backend",
            )),
        };
        match copied {
            Ok(()) => moved += 1,
            Err(error) => {
                eprintln!("drain {node}: volume {}: {}", volume.id, error.message);
                failed += 1;
            }
        }
    }
    (moved, failed)
}

/// Where a sandbox with volumes may go.
#[derive(Clone)]
pub struct Need {
    /// The backend of the volumes that have files.
    pub backend: Option<String>,
    /// The hosts with their files. `None` is the primary.
    pub homes: BTreeSet<Option<String>>,
    /// Volumes with no file yet.
    pub unplaced: Vec<String>,
    pub rows: Vec<db::Volume>,
}

impl Need {
    pub fn of(app: &App, volumes: &[VolumeRef]) -> Result<Self, ApiError> {
        let mut need = Self {
            backend: None,
            homes: BTreeSet::new(),
            unplaced: Vec::new(),
            rows: Vec::new(),
        };
        for volume in volumes {
            let row = app.db.get_volume_by_id(&volume.volume)?.ok_or_else(|| {
                ApiError::new(
                    Code::NotFound,
                    format!("volume {:?} not found", volume.name),
                )
            })?;
            match &row.backend {
                None => need.unplaced.push(row.id.clone()),
                Some(backend) => {
                    if need.backend.as_ref().is_some_and(|b| b != backend) {
                        return Err(ApiError::invalid(
                            "these volumes were made on different backends",
                        ));
                    }
                    need.backend = Some(backend.clone());
                    need.homes.insert(row.node.clone());
                }
            }
            need.rows.push(row);
        }
        Ok(need)
    }

    /// The one host with all placed volumes, if there is one.
    pub fn home(&self) -> Option<&Option<String>> {
        match self.homes.len() {
            1 => self.homes.first(),
            _ => None,
        }
    }

    /// Whether a sandbox can go here without copying.
    pub fn fits(&self, node: Option<&str>, backend: &str) -> bool {
        self.backend.as_deref().is_none_or(|b| b == backend)
            && (self.homes.is_empty() || self.home().is_some_and(|home| home.as_deref() == node))
    }

    /// GiB of the volumes on `node`, to prefer the host that needs the
    /// least copying.
    pub fn gib_on(&self, node: Option<&str>) -> u64 {
        self.rows
            .iter()
            .filter(|r| r.backend.is_some() && r.node.as_deref() == node)
            .map(|r| u64::from(r.size_gib))
            .sum()
    }

    /// Copies each placed volume that is not on `to` there.
    pub async fn gather(
        &self,
        app: &App,
        p: &Primary,
        to: Option<&NodeRow>,
    ) -> Result<(), ApiError> {
        for row in &self.rows {
            // A copy may have moved it since `of`.
            let Some(row) = app.db.get_volume_by_id(&row.id)? else {
                continue;
            };
            if row.backend.is_some() {
                copy(app, p, &row, to).await?;
            }
        }
        Ok(())
    }

    /// Whether no volume needs a file made or moved, so creates can run
    /// side by side.
    pub fn is_simple(&self) -> bool {
        self.unplaced.is_empty() && self.homes.len() <= 1
    }
}

#[cfg(test)]
mod drain_tests {
    use super::*;

    fn volume(name: &str, node: Option<&str>, backend: &str) -> db::Volume {
        db::Volume {
            id: format!("vol_{name}"),
            tenant: "t".into(),
            name: name.into(),
            size_gib: 1,
            node: node.map(str::to_owned),
            backend: Some(backend.into()),
            created_at: 0,
        }
    }

    #[test]
    fn a_volume_stays_only_when_no_host_has_its_backend() {
        let volumes = [
            volume("elsewhere", Some("nod_b"), "gvisor"),
            volume("here", Some("nod_a"), "firecracker"),
        ];
        let firecracker = ["firecracker".to_string()];
        assert_eq!(unmovable(&volumes, "nod_a", &firecracker), None);
        let gvisor = ["gvisor".to_string()];
        let why = unmovable(&volumes, "nod_a", &gvisor).unwrap();
        assert!(
            why.contains("\"here\"") && why.contains("firecracker"),
            "{why}"
        );
        assert_eq!(unmovable(&volumes, "nod_c", &[]), None);
    }
}
