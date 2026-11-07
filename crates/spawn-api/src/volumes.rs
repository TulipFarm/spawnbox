//! Persistent volumes: named disks that outlive sandboxes. A volume's file
//! is created on the host of the first sandbox that mounts it, and stays
//! there; see `fleet::primary` for how sandboxes follow it.

use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::Context;
use spawn_node::{Attach, Backend};

use crate::db::{self, Db, VolumeRef};
use crate::ids;
use crate::metering::{Meter, Rate};
use crate::model::{ApiError, Code, CreateVolume, VolumeMount};
use crate::tenancy::Tenant;

pub struct Volumes {
    db: Db,
    dir: PathBuf,
    backend: Backend,
    meter: Arc<Meter>,
    /// Whether this host meters volumes. A worker leaves it to the
    /// primary, which has every volume.
    metering: bool,
    /// Held while files are created, so two sandboxes never create one.
    making: tokio::sync::Mutex<()>,
    /// Volumes are metered up to here (Unix ms).
    metered_at: Mutex<i64>,
}

impl Volumes {
    pub fn new(
        db: Db,
        dir: PathBuf,
        backend: Backend,
        meter: Arc<Meter>,
        metering: bool,
    ) -> anyhow::Result<Self> {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .with_context(|| format!("create {}", dir.display()))?;
        Ok(Self {
            db,
            dir,
            backend,
            meter,
            metering,
            making: tokio::sync::Mutex::default(),
            metered_at: Mutex::new(now_ms()),
        })
    }

    pub fn backend(&self) -> Backend {
        self.backend
    }

    /// The volume's file on this host.
    pub fn file(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.ext4"))
    }

    pub fn create(&self, tenant: &Tenant, req: &CreateVolume) -> Result<db::Volume, ApiError> {
        let size_gib = req.check()?;
        tenant
            .quotas
            .admit_volume(self.db.volume_gib(&tenant.id)?, u64::from(size_gib))?;
        let volume = db::Volume {
            id: ids::new_id("vol").map_err(ApiError::internal)?,
            tenant: tenant.id.clone(),
            name: req.name.clone(),
            size_gib,
            node: None,
            backend: None,
            created_at: now_ms(),
        };
        if !self.db.insert_volume(&volume)? {
            return Err(ApiError::new(
                Code::Conflict,
                format!("volume {:?} already exists", req.name),
            ));
        }
        Ok(volume)
    }

    pub fn get(&self, tenant: &str, name: &str) -> Result<db::Volume, ApiError> {
        if !crate::model::is_volume_name(name) {
            return Err(ApiError::not_found());
        }
        self.db
            .get_volume(tenant, name)?
            .ok_or_else(|| ApiError::new(Code::NotFound, format!("volume {name:?} not found")))
    }

    pub fn list(&self, tenant: Option<&str>) -> Result<Vec<db::Volume>, ApiError> {
        Ok(self.db.list_volumes(tenant)?)
    }

    /// Deletes a volume no sandbox uses, and its file if it is on this
    /// host. Returns it, for the primary to remove a file on a worker.
    pub fn delete(&self, tenant: &str, name: &str) -> Result<db::Volume, ApiError> {
        let volume = self.get(tenant, name)?;
        if let Err(users) = self.db.delete_volume(&volume.id, now_ms())? {
            let ids: Vec<_> = users.iter().map(|u| u.sandbox.as_str()).collect();
            return Err(ApiError::new(
                Code::Conflict,
                format!(
                    "volume {name:?} is mounted in {}; delete those sandboxes first",
                    ids.join(", ")
                ),
            ));
        }
        if volume.node.is_none() {
            self.remove_file(&volume.id);
        }
        Ok(volume)
    }

    pub fn remove_file(&self, id: &str) {
        let file = self.file(id);
        if let Err(error) = std::fs::remove_file(&file)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            eprintln!("warning: remove {}: {error}", file.display());
        }
    }

    /// Finds the volumes a new sandbox asks for. Each one's slot is its
    /// place in the list.
    pub fn resolve(
        &self,
        tenant: &str,
        mounts: &[VolumeMount],
    ) -> Result<Vec<VolumeRef>, ApiError> {
        mounts
            .iter()
            .map(|mount| {
                let volume = self.get(tenant, &mount.volume)?;
                Ok(VolumeRef {
                    volume: volume.id,
                    name: volume.name,
                    path: mount.path.clone(),
                    read_only: mount.read_only,
                    size_gib: volume.size_gib,
                })
            })
            .collect()
    }

    /// Makes sure each volume's file is on this host, creating the files of
    /// new volumes. Returns what to attach and where the guest mounts it.
    pub async fn prepare(&self, refs: &[VolumeRef]) -> Result<Vec<(Attach, String)>, ApiError> {
        if refs.is_empty() {
            return Ok(Vec::new());
        }
        let _making = self.making.lock().await;
        for volume in refs {
            let row = self.db.get_volume_by_id(&volume.volume)?.ok_or_else(|| {
                ApiError::new(
                    Code::NotFound,
                    format!("volume {:?} not found", volume.name),
                )
            })?;
            let file = self.file(&row.id);
            if let Some(backend) = &row.backend
                && backend != self.backend.name()
            {
                return Err(ApiError::invalid(format!(
                    "volume {:?} holds {backend} sandboxes, and this host runs {}",
                    volume.name,
                    self.backend.name()
                )));
            }
            if row.backend.is_some() {
                if !file.exists() {
                    return Err(ApiError::new(
                        Code::Conflict,
                        format!("volume {:?} is on another host", volume.name),
                    ));
                }
                continue;
            }
            let partial = self.dir.join(format!(".new-{}.ext4", row.id));
            let _ = std::fs::remove_file(&partial);
            spawn_node::volume::create(&partial, row.size_gib)
                .await
                .map_err(|error| ApiError::internal(format!("create volume: {error:#}")))?;
            std::fs::rename(&partial, &file)
                .map_err(|error| ApiError::internal(format!("place volume: {error}")))?;
            self.db
                .set_volume_home(&row.id, None, self.backend.name())?;
        }
        Ok(self.attachments(refs))
    }

    /// What to attach for volumes whose files are here.
    pub fn attachments(&self, refs: &[VolumeRef]) -> Vec<(Attach, String)> {
        refs.iter()
            .zip(0..)
            .map(|(volume, slot)| {
                let attach = Attach {
                    slot,
                    file: self.file(&volume.volume),
                    read_only: volume.read_only,
                };
                (attach, volume.path.clone())
            })
            .collect()
    }

    /// Counts the size of every volume as stored, up to now. Call every
    /// few seconds.
    pub fn meter(&self) {
        if !self.metering {
            return;
        }
        let now = now_ms();
        let from = *self.metered_at.lock().unwrap_or_else(|e| e.into_inner());
        let volumes = match self.db.volumes_since(from) {
            Ok(volumes) => volumes,
            Err(error) => {
                eprintln!("usage: read volumes: {error}");
                return;
            }
        };
        for (volume, deleted_at) in volumes {
            let start = from.max(volume.created_at);
            let end = deleted_at.unwrap_or(now).min(now);
            if end > start {
                let rate = Rate {
                    disk_bytes: u64::from(volume.size_gib) << 30,
                    ..Rate::default()
                };
                self.meter
                    .charge(&volume.tenant, &volume.id, start, end, rate);
            }
        }
        *self.metered_at.lock().unwrap_or_else(|e| e.into_inner()) = now;
    }
}

fn now_ms() -> i64 {
    crate::runtime::now_ms()
}
