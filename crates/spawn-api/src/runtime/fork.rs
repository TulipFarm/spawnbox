//! Fork and snapshot: copies of a running sandbox, as new sandboxes or as a
//! template.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

use futures_util::future::join_all;
use serde_json::json;
use spawn_egress::{Attached, Policy};
use spawn_node::firecracker::Limits;
use spawn_node::{Build, Frozen, guest, new_identity};

use super::{Admission, Live, Record, Sandboxes, VmState, disk_bytes, now_ms, remove_dir};
use crate::db::{self, state};
use crate::egress::CA_ENV;
use crate::events::Origin;
use crate::ids;
use crate::model::{
    ApiError, BASE_TEMPLATE, Code, Resources, Service, SnapshotOf, TemplateSpec, is_template_name,
};
use crate::tenancy::{Quotas, scoped};

/// Copies one fork makes at most.
pub const MAX_FORK: u32 = 16;

/// What a copy takes from a running sandbox.
struct Source {
    tenant: String,
    env: BTreeMap<String, String>,
    egress: Policy,
    secrets: Vec<Attached>,
    limits: Limits,
    idle_pause_s: u64,
    expires_at: i64,
    has_layer: bool,
    own_rootfs: bool,
    persistent: bool,
    services: Vec<Service>,
    protected: bool,
}

/// A copy with its quota and slot, before it starts.
struct Child {
    id: String,
    index: u32,
    admission: Admission,
}

/// What every copy of one fork shares.
struct Fork<'a> {
    source: Source,
    row: db::Sandbox,
    build: Build,
    policies: Vec<Policy>,
    quotas: Quotas,
    origin: &'a Origin,
}

impl Sandboxes {
    /// Saves running sandbox `id` as template `name` of its tenant. It runs
    /// on. Returns the template's spec and build.
    pub async fn snapshot(
        &self,
        id: &str,
        name: &str,
        origin: &Origin,
    ) -> Result<(TemplateSpec, String), ApiError> {
        if name == BASE_TEMPLATE || !is_template_name(name) {
            return Err(ApiError::invalid(
                "name must be a template name other than \"base\"",
            ));
        }
        let lock = self.waking_lock(id, origin).await?;
        let _changing = lock.lock().await;
        let source = self.source(id)?;
        refuse_protected(source.protected)?;
        let row = self.get(id)?;
        let placeholders: HashSet<&str> = source
            .secrets
            .iter()
            .map(|a| a.placeholder.as_str())
            .collect();
        // Secrets are attached again to each new sandbox.
        let env = source
            .env
            .iter()
            .filter(|(k, v)| {
                !CA_ENV.iter().any(|(ca, _)| ca == k) && !placeholders.contains(v.as_str())
            })
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let spec = TemplateSpec {
            name: name.to_owned(),
            setup: Vec::new(),
            warmup: Vec::new(),
            env,
            resources: Resources {
                vcpus: Some(u32::from(source.limits.vcpus)),
                memory_mib: Some(source.limits.memory_mib),
                disk_gib: None,
            },
            min_warm: 0,
            base: None,
            registry_secrets: Vec::new(),
            snapshot: Some(SnapshotOf {
                id: ids::new_id("snp").map_err(ApiError::internal)?,
                sandbox: id.to_owned(),
                build: row.build,
                layer: source.has_layer,
                rootfs: source.own_rootfs,
            }),
        };
        let key = scoped(Some(&source.tenant), name);
        let (build, dir) = self.templates.begin_snapshot(&key, &spec)?;
        let begin = Instant::now();
        let stopped_ms = match self.save_running(id, &dir, origin).await {
            Ok(ms) => ms,
            Err(error) => {
                let failed = Err(anyhow::anyhow!("{}", error.message));
                let _ = self.templates.finish_snapshot(&build, &spec, failed).await;
                return Err(error);
            }
        };
        self.templates
            .finish_snapshot(&build, &spec, Ok(()))
            .await?;
        let duration_ms = begin.elapsed().as_millis();
        eprintln!(
            "{id} saved as template {name:?} ({}) in {duration_ms} ms (stopped {stopped_ms:.0})",
            build.id
        );
        self.event(
            "sandbox.snapshotted",
            origin,
            &source.tenant,
            id,
            json!({
                "template": name,
                "build": build.id,
                "duration_ms": u64::try_from(duration_ms).unwrap_or(u64::MAX),
            }),
        );
        Ok((spec, build.id))
    }

    /// Starts `count` copies of running sandbox `id` on this host. It runs
    /// on. Returns the copies that started.
    pub async fn fork(
        &self,
        id: &str,
        count: u32,
        origin: &Origin,
    ) -> Result<Vec<db::Sandbox>, ApiError> {
        if !(1..=MAX_FORK).contains(&count) {
            return Err(ApiError::invalid(format!("count must be 1 to {MAX_FORK}")));
        }
        if self.closing.load(Ordering::SeqCst) {
            return Err(Self::shutting_down());
        }
        let lock = self.waking_lock(id, origin).await?;
        let _changing = lock.lock().await;
        let mut source = self.source(id)?;
        let row = self.get(id)?;
        let tenant = self.db.get_tenant(&source.tenant)?;
        let quotas = tenant.as_ref().map(|t| t.quotas).unwrap_or_default();
        // Copies of a persistent sandbox are not persistent: they get the
        // longest timeout.
        if source.persistent {
            let timeout_s = quotas.max_timeout_s(self.settings.max_timeout_s);
            source.expires_at =
                now_ms().saturating_add(i64::try_from(timeout_s * 1000).unwrap_or(i64::MAX));
        }
        let mut children: Vec<Child> = Vec::new();
        let mut taken = Ok(());
        for _ in 0..count {
            let child = async {
                let id = ids::new_id("sbx").map_err(ApiError::internal)?;
                let admission = self.admit(&source.tenant, &quotas, &id, source.limits, true)?;
                let index = self.take_slot(None).await?;
                Ok::<_, ApiError>(Child {
                    id,
                    index,
                    admission,
                })
            };
            match child.await {
                Ok(child) => children.push(child),
                Err(error) => {
                    taken = Err(error);
                    break;
                }
            }
        }
        let begin = Instant::now();
        let saved = match (taken, self.staging_dir()) {
            (Ok(()), Ok(dir)) => self.save_running(id, &dir, origin).await.map(|_| dir),
            (Err(error), _) => Err(error),
            (_, Err(error)) => Err(ApiError::internal(error)),
        };
        let dir = match saved {
            Ok(dir) => dir,
            Err(error) => {
                for child in children {
                    self.release(child.index);
                }
                return Err(error);
            }
        };
        let build = Build::at(
            &dir,
            self.volumes.backend(),
            source.limits,
            source.has_layer,
        )
        .with_own_rootfs(source.own_rootfs);
        let policies: Vec<Policy> = tenant
            .and_then(|t| t.egress)
            .into_iter()
            .chain([source.egress.clone()])
            .collect();
        let fork = Fork {
            source,
            row,
            build,
            policies,
            quotas,
            origin,
        };
        let started = join_all(children.into_iter().map(|c| self.start_child(c, &fork))).await;
        remove_dir(&dir);
        let started: Vec<db::Sandbox> = started.into_iter().flatten().collect();
        let duration_ms = begin.elapsed().as_millis();
        let ids: Vec<&str> = started.iter().map(|s| s.id.as_str()).collect();
        eprintln!(
            "{id} forked into {} of {count} in {duration_ms} ms",
            ids.len()
        );
        self.event(
            "sandbox.forked",
            origin,
            &fork.source.tenant,
            id,
            json!({
                "sandboxes": ids,
                "failed": count as usize - ids.len(),
                "duration_ms": u64::try_from(duration_ms).unwrap_or(u64::MAX),
            }),
        );
        if started.is_empty() {
            return Err(ApiError::internal(format!(
                "no copy of sandbox {id} started; see the server log"
            )));
        }
        Ok(started)
    }

    /// Hold the sandbox's lock. What a copy of running sandbox `id` takes.
    fn source(&self, id: &str) -> Result<Source, ApiError> {
        let inner = self.inner();
        let Some(record) = inner.records.get(id) else {
            drop(inner);
            return Err(self.not_running(id));
        };
        if record.is_moving() {
            return Err(ApiError::new(
                Code::Conflict,
                "sandbox is moving to another host; try again soon",
            ));
        }
        let VmState::Running(live) = &record.vm else {
            return Err(ApiError::new(
                Code::Conflict,
                "sandbox is paused; resume it first",
            ));
        };
        if !record.volumes.is_empty() {
            return Err(ApiError::invalid(
                "a sandbox with volumes cannot be forked or saved",
            ));
        }
        Ok(Source {
            tenant: record.tenant.clone(),
            env: record.env.clone(),
            egress: record.egress.clone(),
            secrets: record.secrets.clone(),
            limits: record.limits,
            idle_pause_s: record.idle_pause_s,
            expires_at: live.expires_at,
            has_layer: live.vm.has_layer(),
            own_rootfs: live.vm.owns_rootfs(self.templates.base_rootfs()),
            persistent: record.persistent,
            services: record.services.clone(),
            protected: record.protected,
        })
    }

    /// Hold the sandbox's lock. Saves running sandbox `id` to `dir` as a
    /// build; it runs on. Returns the milliseconds it was stopped for.
    async fn save_running(&self, id: &str, dir: &Path, origin: &Origin) -> Result<f64, ApiError> {
        let not_running = || ApiError::new(Code::Conflict, "sandbox is not running");
        let (live, tenant) = {
            let mut inner = self.inner();
            let record = inner.records.get_mut(id).ok_or_else(not_running)?;
            match std::mem::replace(&mut record.vm, VmState::Changing) {
                VmState::Running(live) => (live, record.tenant.clone()),
                other => {
                    record.vm = other;
                    return Err(not_running());
                }
            }
        };
        let saved = self.node.save_running(&live.vm, dir).await;
        let failed = || {
            ApiError::internal(format!(
                "sandbox {id} could not be saved; see the server log"
            ))
        };
        if let Err(error) = &saved {
            eprintln!("save {id}: {error:#}");
            if error.downcast_ref::<Frozen>().is_some() {
                let mut generation = 0;
                let mut persistent = false;
                if let Some(mut record) = self.inner().records.remove(id) {
                    self.settle(id, &mut record, now_ms());
                    (generation, persistent) = (record.generation, record.persistent);
                }
                if persistent {
                    self.stop(id, generation, *live, state::COLD).await;
                    self.cold_event(origin, &tenant, id, "froze_while_saving");
                    return Err(failed());
                }
                self.stop(id, generation, *live, state::FAILED).await;
                self.event(
                    "sandbox.lost",
                    origin,
                    &tenant,
                    id,
                    json!({ "reason": "froze while saving" }),
                );
                return Err(failed());
            }
        }
        let (stopped_ms, channel) = match saved {
            Ok(saved) => saved,
            Err(_) => {
                self.put_back(id, live);
                return Err(failed());
            }
        };
        let mut live = live;
        live.channel = channel;
        self.put_back(id, live);
        Ok(stopped_ms)
    }

    fn put_back(&self, id: &str, live: Box<Live>) {
        if let Some(record) = self.inner().records.get_mut(id) {
            record.vm = VmState::Running(live);
            record.last_active = Instant::now();
        }
    }

    /// Restores one copy. `None` if it failed, which is logged and recorded.
    async fn start_child(&self, child: Child, fork: &Fork<'_>) -> Option<db::Sandbox> {
        let Child {
            id,
            index,
            admission,
        } = child;
        let Fork {
            source,
            row,
            build,
            policies,
            quotas,
            origin,
        } = fork;
        let mut sandbox = db::Sandbox {
            id: id.clone(),
            tenant: source.tenant.clone(),
            state: state::STARTING.into(),
            template: row.template.clone(),
            build: row.build.clone(),
            labels: row.labels.clone(),
            secrets: row.secrets.clone(),
            egress: source.egress.clone(),
            created_at: now_ms(),
            expires_at: source.expires_at,
            idle_pause_s: source.idle_pause_s,
            paused_at: None,
            node: None,
            vcpus: u32::from(source.limits.vcpus),
            memory_mib: source.limits.memory_mib,
            volumes: Vec::new(),
            persistent: false,
            generation: 1,
            cold_starts: 0,
            last_cold_start_at: None,
            first_start: false,
        };
        if !matches!(self.db.insert_sandbox(&sandbox), Ok(Ok(()))) {
            eprintln!("fork {}: could not record copy {id}", row.id);
            self.release(index);
            return None;
        }
        let name = ids::host_name(&id);
        let mode = self.network.mode(policies);
        let (send, receive) = self.network.rates(policies);
        self.network.register(
            index,
            &id,
            Some(&source.tenant),
            policies.clone(),
            source.secrets.clone(),
        );
        let started = async {
            let restored = self.node.restore(build, &name, index, mode, &[]).await?;
            let fixups = async {
                restored.vm.set_rates(send, receive).await?;
                guest::apply(&restored.channel, new_identity(&name)?).await
            };
            if let Err(error) = fixups.await {
                restored.vm.stop().await;
                return Err(error);
            }
            anyhow::Ok(restored)
        }
        .await;
        let restored = match started {
            Ok(restored) => restored,
            Err(error) => {
                eprintln!("fork {} into {id}: {error:#}", row.id);
                self.node.remove_failed(&name, index).await;
                self.release(index);
                let _ = self.db.set_state(&id, 1, state::FAILED, now_ms());
                self.event(
                    "sandbox.lost",
                    origin,
                    &source.tenant,
                    &id,
                    json!({ "reason": "failed to start" }),
                );
                return None;
            }
        };
        let live = Live {
            vm: restored.vm,
            channel: restored.channel,
            index,
            expires_at: source.expires_at,
            volumes: false,
        };
        let disk_bytes = disk_bytes(&live.vm);
        self.inner().records.insert(
            id.clone(),
            Record {
                tenant: source.tenant.clone(),
                vm: VmState::Running(Box::new(live)),
                env: source.env.clone(),
                // The copy's services run already, from the snapshot.
                ports: super::services::ports(&source.services).unwrap_or_default(),
                egress: source.egress.clone(),
                secrets: source.secrets.clone(),
                volumes: Vec::new(),
                limits: source.limits,
                idle_pause_s: source.idle_pause_s,
                retention_ms: self.retention_ms(quotas),
                busy: 0,
                last_active: Instant::now(),
                lock: Arc::default(),
                metered_at: now_ms(),
                disk_bytes,
                moving: None,
                generation: 1,
                persistent: false,
                services: source.services.clone(),
                protected: source.protected,
            },
        );
        drop(admission);
        if let Err(error) = self.db.set_state(&id, 1, state::RUNNING, now_ms()) {
            eprintln!("record {id} as running: {error}");
            let removed = self.inner().records.remove(&id);
            if let Some(Record {
                vm: VmState::Running(live),
                ..
            }) = removed
            {
                self.stop(&id, 1, *live, state::FAILED).await;
            }
            return None;
        }
        sandbox.state = state::RUNNING.into();
        self.event(
            "sandbox.created",
            origin,
            &source.tenant,
            &id,
            json!({
                "template": sandbox.template,
                "build": sandbox.build,
                "forked_from": row.id,
                "services": source.services.iter().map(|s| &s.name).collect::<Vec<_>>(),
                "vcpus": source.limits.vcpus,
                "memory_mib": source.limits.memory_mib,
                "labels": sandbox.labels,
                "secrets": sandbox.secrets,
            }),
        );
        if !source.services.is_empty() {
            self.watch_services(&id, 1, None);
        }
        Some(sandbox)
    }
}

/// A template spec would show the env values of a sandbox created with them.
fn refuse_protected(protected: bool) -> Result<(), ApiError> {
    if protected {
        return Err(ApiError::new(
            Code::ProtectedEnv,
            "a sandbox created with env values cannot be saved as a template, \
             as the template would expose them; attach secrets instead",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secretbox::SandboxEnv;

    fn snapshot_of(env: &str, services: &str) -> Result<(), ApiError> {
        let own = SandboxEnv {
            env: serde_json::from_str(env).unwrap(),
            services: serde_json::from_str(services).unwrap(),
        };
        refuse_protected(own.is_protected())
    }

    #[test]
    fn only_sandboxes_without_own_env_become_templates() {
        assert!(snapshot_of("{}", "[]").is_ok());
        assert!(snapshot_of("{}", r#"[{"name":"web","command":["srv"]}]"#).is_ok());
        for (env, services) in [
            (r#"{"TOKEN":"x"}"#, "[]"),
            (
                "{}",
                r#"[{"name":"web","command":["srv"],"env":{"KEY":"x"}}]"#,
            ),
        ] {
            let error = snapshot_of(env, services).unwrap_err();
            assert_eq!(error.code.as_str(), "protected_env");
            assert_eq!(error.code.http_status(), 409);
        }
    }
}
