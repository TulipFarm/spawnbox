//! Services: programs the guest keeps running. The host sends their specs
//! when a VM starts fresh, turns the guest's changes into events and
//! forwards calls for their state and logs.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use spawn_proto::guest::v1::service_health::Check;
use spawn_proto::guest::v1::services_client::ServicesClient;
use spawn_proto::guest::v1::{
    ServiceEvent, ServiceExit, ServiceHealth, ServiceLogChunk, ServiceLogsRequest, ServiceRestart,
    ServiceRestartRequest, ServiceSpec, ServiceStatus, ServicesListRequest, ServicesStartRequest,
    ServicesWatchRequest,
};
use tonic::Streaming;
use tonic::transport::Channel;

use super::{Busy, Opened, Published, Sandboxes, VmState, now_ms};
use crate::egress::CA_ENV;
use crate::events::Origin;
use crate::metrics;
use crate::model::{ApiError, Code, Restart, Service};
use crate::ports::{self, Access};

/// How long a preview request waits for its service to be healthy.
pub const HEALTHY_WAIT: Duration = Duration::from_secs(30);

const START_TIMEOUT: Duration = Duration::from_secs(30);

/// A watch with nothing to read for this long is opened again, so it sees
/// when its sandbox is gone.
const WATCH_IDLE: Duration = Duration::from_secs(60);

/// What the guest runs for `services`: each gets the sandbox's env with
/// its own on top.
fn specs(env: &BTreeMap<String, String>, services: &[Service]) -> Vec<ServiceSpec> {
    services
        .iter()
        .map(|service| {
            let mut merged = env.clone();
            merged.extend(service.env.clone());
            ServiceSpec {
                name: service.name.clone(),
                command: service.command.clone(),
                cwd: service.cwd.clone().unwrap_or_default(),
                env: merged.into_iter().collect(),
                user: String::new(),
                port: service.port.unwrap_or(0),
                health: service.health.as_ref().map(|health| ServiceHealth {
                    check: Some(match &health.http {
                        Some(path) => Check::Http(path.clone()),
                        None => Check::Tcp(true),
                    }),
                    interval_s: health.interval_s,
                    failures: health.failures,
                }),
                restart: match service.restart {
                    Restart::Always => ServiceRestart::Always,
                    Restart::OnFailure => ServiceRestart::OnFailure,
                } as i32,
            }
        })
        .collect()
}

/// Starts `services` in a VM that has just started. Returns the guest's
/// last service event before them.
pub(super) async fn start(
    channel: &Channel,
    env: &BTreeMap<String, String>,
    services: &[Service],
) -> anyhow::Result<u64> {
    let request = ServicesStartRequest {
        services: specs(env, services),
    };
    let started = tokio::time::timeout(
        START_TIMEOUT,
        ServicesClient::new(channel.clone()).start(request),
    )
    .await
    .map_err(|_| anyhow::anyhow!("starting services timed out"))??;
    Ok(started.into_inner().seq)
}

/// Whether a start failed because the guest has no services.
pub(super) fn unsupported(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<tonic::Status>()
        .is_some_and(|status| status.code() == tonic::Code::Unimplemented)
}

pub(super) fn unsupported_error() -> ApiError {
    ApiError::new(
        Code::Conflict,
        "this template's guest does not support services; build the template again",
    )
}

/// Refuses service env that would replace the CA variables or a secret's
/// variable.
pub(super) fn check_env(
    services: &[Service],
    placeholders: &BTreeMap<String, String>,
) -> Result<(), ApiError> {
    for service in services {
        for key in service.env.keys() {
            if CA_ENV.iter().any(|(ca, _)| ca == key) {
                return Err(ApiError::invalid(format!(
                    "service {:?} may not set {key}",
                    service.name
                )));
            }
            if placeholders.contains_key(key) {
                return Err(ApiError::invalid(format!(
                    "service {:?} may not set {key}, which a secret sets",
                    service.name
                )));
            }
        }
    }
    Ok(())
}

/// The ports `services` publish.
pub(super) fn ports(services: &[Service]) -> Result<BTreeMap<u16, Published>, ApiError> {
    let mut published = BTreeMap::new();
    for (port, access) in services.iter().filter_map(Service::published) {
        let token = match access {
            Access::Token => Some((
                ports::new_token().map_err(ApiError::internal)?,
                now_ms().saturating_add(
                    i64::try_from(ports::DEFAULT_TOKEN_TTL_S * 1000).unwrap_or(i64::MAX),
                ),
            )),
            Access::Public | Access::Private | Access::Gateway => None,
        };
        published.insert(port, Published { access, token });
    }
    Ok(published)
}

fn exit_json(exit: Option<&ServiceExit>) -> Value {
    match exit {
        Some(ServiceExit {
            code: Some(code), ..
        }) => json!({ "code": code }),
        Some(ServiceExit {
            signal: Some(signal),
            ..
        }) => json!({ "signal": signal }),
        _ => Value::Null,
    }
}

/// A service's state as the API shows it.
pub fn status_json(status: &ServiceStatus) -> Value {
    json!({
        "name": status.name,
        "state": status.state,
        "pid": (status.pid != 0).then_some(status.pid),
        "restarts": status.restarts,
        "last_exit": exit_json(status.last_exit.as_ref()),
        "started_at": (status.started_at_ms != 0)
            .then(|| crate::model::rfc3339_ms(status.started_at_ms)),
    })
}

impl Sandboxes {
    /// Turns the guest's service changes in sandbox `id` into events while
    /// its VM of `generation` lives. Starts after event `after`, or with
    /// new events for `None`.
    pub(super) fn watch_services(&self, id: &str, generation: i64, after: Option<u64>) {
        let (this, id) = (self.clone(), id.to_owned());
        tokio::spawn(async move {
            let mut after = after;
            loop {
                let found = {
                    let inner = this.inner();
                    let Some(record) = inner.records.get(&id) else {
                        return;
                    };
                    if record.generation != generation || record.services.is_empty() {
                        return;
                    }
                    match &record.vm {
                        VmState::Running(live) => {
                            Some((live.channel.clone(), record.tenant.clone()))
                        }
                        _ => None,
                    }
                };
                if let Some((channel, tenant)) = found {
                    this.follow_services(&id, &tenant, channel, &mut after)
                        .await;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
    }

    /// Records events from one watch until it ends or is idle.
    async fn follow_services(
        &self,
        id: &str,
        tenant: &str,
        channel: Channel,
        after: &mut Option<u64>,
    ) {
        let request = ServicesWatchRequest {
            after: after.unwrap_or(0),
            from_now: after.is_none(),
        };
        let watched =
            tokio::time::timeout(WATCH_IDLE, ServicesClient::new(channel).watch(request)).await;
        let Ok(Ok(stream)) = watched else {
            return;
        };
        let mut stream = stream.into_inner();
        while let Ok(Ok(Some(event))) = tokio::time::timeout(WATCH_IDLE, stream.message()).await {
            *after = Some(event.seq);
            self.service_event(id, tenant, &event);
        }
    }

    fn service_event(&self, id: &str, tenant: &str, event: &ServiceEvent) {
        let name = &event.name;
        let (kind, attrs) = match event.kind.as_str() {
            "started" => ("service.started", json!({ "name": name, "pid": event.pid })),
            "exited" => (
                "service.exited",
                json!({ "name": name, "exit": exit_json(event.exit.as_ref()) }),
            ),
            "unhealthy" => (
                "service.unhealthy",
                json!({ "name": name, "failures": event.count }),
            ),
            "restarted" => {
                metrics::inc(
                    "spawnbox_service_restarts_total",
                    vec![("reason", event.reason.clone())],
                );
                (
                    "service.restarted",
                    json!({ "name": name, "reason": event.reason, "restarts": event.count }),
                )
            }
            _ => return,
        };
        self.event(kind, &Origin::system(), tenant, id, attrs);
    }

    fn has_service(&self, id: &str, name: &str) -> bool {
        self.inner()
            .records
            .get(id)
            .is_some_and(|record| record.services.iter().any(|s| s.name == name))
    }

    fn unknown(name: &str) -> ApiError {
        ApiError::new(Code::NotFound, format!("service {name:?} not found"))
    }

    /// The state of each service. Wakes the sandbox like any call.
    pub async fn services(&self, id: &str, origin: &Origin) -> Result<Vec<Value>, ApiError> {
        let opened = self.open(id, origin).await?;
        let any = self
            .inner()
            .records
            .get(id)
            .is_some_and(|record| !record.services.is_empty());
        if !any {
            return Ok(Vec::new());
        }
        let listed = ServicesClient::new(opened.channel)
            .list(ServicesListRequest {})
            .await
            .map_err(|status| ApiError::from_guest(&status))?;
        Ok(listed
            .into_inner()
            .services
            .iter()
            .map(status_json)
            .collect())
    }

    pub async fn restart_service(
        &self,
        id: &str,
        name: &str,
        origin: &Origin,
    ) -> Result<(), ApiError> {
        let opened = self.open(id, origin).await?;
        if !self.has_service(id, name) {
            return Err(Self::unknown(name));
        }
        ServicesClient::new(opened.channel)
            .restart(ServiceRestartRequest {
                name: name.to_owned(),
            })
            .await
            .map_err(|status| ApiError::from_guest(&status))?;
        Ok(())
    }

    /// A service's recent output, then new output with `follow`. The
    /// sandbox counts as busy while the stream is held.
    pub async fn service_logs(
        &self,
        id: &str,
        name: &str,
        follow: bool,
        origin: &Origin,
    ) -> Result<(Streaming<ServiceLogChunk>, Busy), ApiError> {
        let Opened { channel, busy, .. } = self.open(id, origin).await?;
        if !self.has_service(id, name) {
            return Err(Self::unknown(name));
        }
        let stream = ServicesClient::new(channel)
            .logs(ServiceLogsRequest {
                name: name.to_owned(),
                follow,
            })
            .await
            .map_err(|status| ApiError::from_guest(&status))?;
        Ok((stream.into_inner(), busy))
    }

    /// The service of sandbox `id` that listens on `port`, if any.
    pub fn service_on_port(&self, id: &str, port: u16) -> Option<String> {
        let inner = self.inner();
        let record = inner.records.get(id)?;
        record
            .services
            .iter()
            .find(|s| s.port == Some(u32::from(port)))
            .map(|s| s.name.clone())
    }

    /// Waits until service `name` is healthy, for up to `HEALTHY_WAIT`.
    /// Returns whether it is. A guest that cannot tell counts as healthy,
    /// and the request goes on.
    pub async fn wait_healthy(&self, channel: &Channel, name: &str) -> bool {
        let deadline = Instant::now() + HEALTHY_WAIT;
        let mut client = ServicesClient::new(channel.clone());
        loop {
            let Ok(listed) = client.list(ServicesListRequest {}).await else {
                return true;
            };
            let healthy = listed
                .into_inner()
                .services
                .iter()
                .any(|s| s.name == name && s.state == "healthy");
            if healthy {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn services(json: &str) -> Vec<Service> {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn service_env_goes_on_top_of_the_sandbox_env() {
        let env = BTreeMap::from([
            ("A".to_owned(), "sandbox".to_owned()),
            ("B".to_owned(), "sandbox".to_owned()),
        ]);
        let list = services(
            r#"[{"name":"web","command":["srv","-p","80"],"env":{"B":"service"},"port":80,
                "health":{"http":"/healthz"},"restart":"on-failure"},
                {"name":"job","command":["work"],"health":null}]"#,
        );
        let specs = specs(&env, &list);
        assert_eq!(specs[0].env["A"], "sandbox");
        assert_eq!(specs[0].env["B"], "service");
        assert_eq!(specs[1].env["B"], "sandbox");
        assert_eq!(specs[0].command, ["srv", "-p", "80"]);
        assert_eq!(specs[0].restart, ServiceRestart::OnFailure as i32);
        assert_eq!(specs[1].restart, ServiceRestart::Always as i32);
        let health = specs[0].health.as_ref().unwrap();
        assert_eq!(health.check, Some(Check::Http("/healthz".into())));
        assert_eq!((health.interval_s, health.failures), (10, 3));
        assert_eq!(specs[1].health, None);
        assert_eq!(specs[1].port, 0);
    }

    #[test]
    fn service_env_may_not_replace_ca_or_secret_variables() {
        let placeholders = BTreeMap::from([("GH_TOKEN".to_owned(), "ph".to_owned())]);
        let ok = services(r#"[{"name":"web","command":["srv"],"env":{"PORT":"80"}}]"#);
        assert!(check_env(&ok, &placeholders).is_ok());
        let secret = services(r#"[{"name":"web","command":["srv"],"env":{"GH_TOKEN":"x"}}]"#);
        assert_eq!(
            check_env(&secret, &placeholders).unwrap_err().code,
            Code::InvalidRequest
        );
        let ca = format!(
            r#"[{{"name":"web","command":["srv"],"env":{{"{}":"x"}}}}]"#,
            CA_ENV[0].0
        );
        assert_eq!(
            check_env(&services(&ca), &placeholders).unwrap_err().code,
            Code::InvalidRequest
        );
    }

    #[test]
    fn service_ports_are_published_private_by_default() {
        let list = services(
            r#"[{"name":"a","command":["x"],"port":80},
                {"name":"b","command":["x"],"port":81,"access":"token"},
                {"name":"c","command":["x"]}]"#,
        );
        let published = ports(&list).unwrap();
        assert_eq!(published.len(), 2);
        assert_eq!(published[&80].access, Access::Private);
        assert!(published[&80].token.is_none());
        assert_eq!(published[&81].access, Access::Token);
        assert!(published[&81].token.is_some());
    }
}
