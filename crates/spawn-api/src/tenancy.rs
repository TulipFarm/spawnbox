//! Tenants, API key kinds and scopes, and per-tenant quotas.
//!
//! Templates and secrets are stored under a key: the bare name for
//! org-wide ones and `<tenant>/<name>` for a tenant's own. Names and tenant
//! IDs cannot contain `/`, so keys never collide.

use serde::{Deserialize, Deserializer, Serialize};
use spawn_egress::Policy;

use crate::model::{ApiError, Code};

pub const DEFAULT_TENANT: &str = "default";
const MAX_TENANT_ID: usize = 63;
const MAX_DISPLAY_NAME: usize = 200;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Scope {
    #[serde(rename = "sandboxes:read")]
    SandboxesRead,
    #[serde(rename = "sandboxes:write")]
    SandboxesWrite,
    #[serde(rename = "templates:write")]
    TemplatesWrite,
    #[serde(rename = "secrets:write")]
    SecretsWrite,
    #[serde(rename = "tenants:admin")]
    TenantsAdmin,
    #[serde(rename = "audit:read")]
    AuditRead,
    #[serde(rename = "usage:read")]
    UsageRead,
    /// Send requests to sandbox ports through the forward listener. Grants
    /// no other API call.
    #[serde(rename = "sandboxes:forward")]
    SandboxesForward,
}

impl Scope {
    pub const ALL: [Self; 8] = [
        Self::SandboxesRead,
        Self::SandboxesWrite,
        Self::TemplatesWrite,
        Self::SecretsWrite,
        Self::TenantsAdmin,
        Self::AuditRead,
        Self::UsageRead,
        Self::SandboxesForward,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::SandboxesRead => "sandboxes:read",
            Self::SandboxesWrite => "sandboxes:write",
            Self::TemplatesWrite => "templates:write",
            Self::SecretsWrite => "secrets:write",
            Self::TenantsAdmin => "tenants:admin",
            Self::AuditRead => "audit:read",
            Self::UsageRead => "usage:read",
            Self::SandboxesForward => "sandboxes:forward",
        }
    }

    /// Every scope a key of this kind may hold.
    pub fn allowed(tenant_key: bool) -> Vec<Self> {
        Self::ALL
            .into_iter()
            .filter(|s| !(tenant_key && *s == Self::TenantsAdmin))
            .collect()
    }
}

/// Who made a request: the API key's ID and tenant (`None` for org keys)
/// and its scopes.
#[derive(Clone, Debug)]
pub struct Caller {
    pub key: String,
    pub tenant: Option<String>,
    pub scopes: Vec<Scope>,
}

impl Caller {
    /// The caller behind a stored key. Keys without a scope list hold all
    /// their kind allows.
    pub fn from_key(key: &crate::db::Key) -> Result<Self, ApiError> {
        let scopes = match &key.scopes {
            Some(json) => serde_json::from_str(json)
                .map_err(|e| ApiError::internal(format!("key {}: bad scopes: {e}", key.id)))?,
            None => Scope::allowed(key.tenant.is_some()),
        };
        Ok(Self {
            key: key.id.clone(),
            tenant: key.tenant.clone(),
            scopes,
        })
    }

    pub fn require(&self, scope: Scope) -> Result<(), ApiError> {
        if self.scopes.contains(&scope) {
            Ok(())
        } else {
            Err(ApiError::new(
                Code::Forbidden,
                format!("this API key does not have the {} scope", scope.as_str()),
            ))
        }
    }

    /// Whether this caller may see resources of `tenant`.
    pub fn sees(&self, tenant: &str) -> bool {
        self.tenant.as_deref().is_none_or(|own| own == tenant)
    }

    /// The tenant a call works in: a tenant key's own, or what an org key
    /// asked for with `?tenant=` (`None` is org-wide). A tenant key that
    /// names another tenant gets `404`.
    pub fn namespace(&self, requested: Option<&str>) -> Result<Option<String>, ApiError> {
        match (&self.tenant, requested) {
            (Some(own), None) => Ok(Some(own.clone())),
            (Some(own), Some(asked)) if own == asked => Ok(Some(own.clone())),
            (Some(_), Some(_)) => Err(tenant_not_found()),
            (None, asked) => Ok(asked.map(str::to_owned)),
        }
    }
}

pub fn tenant_not_found() -> ApiError {
    ApiError::new(Code::NotFound, "tenant not found")
}

/// The scope a request needs.
pub fn required_scope(method: &str, path: &str) -> Scope {
    let read = method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD");
    let under = |prefix: &str| {
        path.strip_prefix(prefix)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
    };
    if path.starts_with("/v1/sandboxes/") && path.ends_with(":migrate") {
        // Moving sandboxes between hosts is the operator's job.
        Scope::TenantsAdmin
    } else if under("/v1/events")
        || (path.starts_with("/v1/sandboxes/") && path.ends_with("/events"))
    {
        Scope::AuditRead
    } else if under("/v1/usage") {
        Scope::UsageRead
    } else if under("/v1/tenants")
        || under("/v1/keys")
        || under("/v1/warm-pools")
        || under("/v1/nodes")
    {
        Scope::TenantsAdmin
    } else if under("/v1/templates") && !read {
        Scope::TemplatesWrite
    } else if under("/v1/secrets") && !read {
        Scope::SecretsWrite
    } else if read && !path.ends_with("/pty") {
        Scope::SandboxesRead
    } else {
        Scope::SandboxesWrite
    }
}

/// The sandbox ID in `/v1/sandboxes/{id}`, `/v1/sandboxes/{id}:verb` and
/// paths below them.
pub fn sandbox_in_path(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("/v1/sandboxes/")?;
    let segment = rest.split('/').next()?;
    let id = segment.split(':').next()?;
    (!id.is_empty()).then_some(id)
}

/// `a-z`, digits and `-`, starting with a letter.
pub fn is_tenant_id(id: &str) -> bool {
    (1..=MAX_TENANT_ID).contains(&id.len())
        && id.starts_with(|c: char| c.is_ascii_lowercase())
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The storage key of a template or secret.
pub fn scoped(tenant: Option<&str>, name: &str) -> String {
    match tenant {
        Some(tenant) => format!("{tenant}/{name}"),
        None => name.to_owned(),
    }
}

/// A storage key's tenant (`None` for org-wide) and name.
pub fn split(key: &str) -> (Option<&str>, &str) {
    match key.split_once('/') {
        Some((tenant, name)) => (Some(tenant), name),
        None => (None, key),
    }
}

/// Limits for one tenant. `None` means no limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Quotas {
    pub running_sandboxes: Option<u64>,
    pub running_vcpus: Option<u64>,
    pub running_memory_mib: Option<u64>,
    pub max_session_s: Option<u64>,
    pub max_paused_retention_s: Option<u64>,
    /// Egress bytes in a UTC month.
    pub monthly_egress_bytes: Option<u64>,
    /// Bytes stored for paused sandboxes, in GiB.
    pub snapshot_storage_gib: Option<u64>,
    /// Total size of volumes, in GiB.
    pub volume_storage_gib: Option<u64>,
    /// Persistent sandboxes in any state but deleted. 0, so none, unless
    /// set.
    pub persistent_sandboxes: Option<u64>,
}

impl Default for Quotas {
    fn default() -> Self {
        Self {
            running_sandboxes: None,
            running_vcpus: None,
            running_memory_mib: None,
            max_session_s: None,
            max_paused_retention_s: None,
            monthly_egress_bytes: None,
            snapshot_storage_gib: None,
            volume_storage_gib: None,
            persistent_sandboxes: Some(0),
        }
    }
}

impl Quotas {
    /// What a new tenant gets for fields it leaves out.
    pub const DEFAULTS: Self = Self {
        running_sandboxes: Some(20),
        running_vcpus: Some(40),
        running_memory_mib: Some(80 * 1024),
        max_session_s: Some(24 * 3600),
        max_paused_retention_s: Some(7 * 86_400),
        monthly_egress_bytes: None,
        snapshot_storage_gib: None,
        volume_storage_gib: None,
        persistent_sandboxes: Some(0),
    };

    /// Whether a sandbox of this shape may start next to `used`.
    pub fn admit(&self, used: Usage, vcpus: u64, memory_mib: u64) -> Result<(), ApiError> {
        for (name, limit, in_use, asked) in [
            (
                "running_sandboxes",
                self.running_sandboxes,
                used.running_sandboxes,
                1,
            ),
            (
                "running_vcpus",
                self.running_vcpus,
                used.running_vcpus,
                vcpus,
            ),
            (
                "running_memory_mib",
                self.running_memory_mib,
                used.running_memory_mib,
                memory_mib,
            ),
        ] {
            if let Some(limit) = limit
                && in_use.saturating_add(asked) > limit
            {
                return Err(ApiError::new(
                    Code::QuotaExceeded,
                    format!("quota {name} exceeded: {in_use} in use, {asked} asked, limit {limit}"),
                ));
            }
        }
        Ok(())
    }

    /// Whether a sandbox may start after `used` egress bytes this month.
    pub fn admit_egress(&self, used: u64) -> Result<(), ApiError> {
        match self.monthly_egress_bytes {
            Some(limit) if used >= limit => Err(ApiError::new(
                Code::QuotaExceeded,
                format!(
                    "quota monthly_egress_bytes exceeded: {used} bytes used this month, limit {limit}"
                ),
            )),
            _ => Ok(()),
        }
    }

    /// Whether a sandbox needing `asked` bytes may pause next to paused
    /// sandboxes storing `stored` bytes.
    pub fn admit_snapshot(&self, stored: u64, asked: u64) -> Result<(), ApiError> {
        match self.snapshot_storage_gib {
            Some(limit) if stored.saturating_add(asked) > limit.saturating_mul(1 << 30) => {
                Err(ApiError::new(
                    Code::QuotaExceeded,
                    format!(
                        "quota snapshot_storage_gib exceeded: {stored} bytes stored, {asked} asked, limit {limit} GiB"
                    ),
                ))
            }
            _ => Ok(()),
        }
    }

    /// Whether a volume of `asked` GiB may be added to volumes of `stored`
    /// GiB.
    pub fn admit_volume(&self, stored: u64, asked: u64) -> Result<(), ApiError> {
        match self.volume_storage_gib {
            Some(limit) if stored.saturating_add(asked) > limit => Err(ApiError::new(
                Code::QuotaExceeded,
                format!(
                    "quota volume_storage_gib exceeded: {stored} GiB of volumes, {asked} asked, limit {limit} GiB"
                ),
            )),
            _ => Ok(()),
        }
    }

    /// Whether one more persistent sandbox may be made next to `in_use`.
    pub fn admit_persistent(&self, in_use: u64) -> Result<(), ApiError> {
        match self.persistent_sandboxes {
            Some(limit) if in_use.saturating_add(1) > limit => Err(ApiError::new(
                Code::QuotaExceeded,
                format!(
                    "quota persistent_sandboxes exceeded: {in_use} in use, 1 asked, limit {limit}"
                ),
            )),
            _ => Ok(()),
        }
    }

    /// The longest `timeout_s` a sandbox may ask for.
    pub fn max_timeout_s(&self, server_max_s: u64) -> u64 {
        self.max_session_s
            .map_or(server_max_s, |s| s.min(server_max_s))
    }

    /// How long a paused sandbox is kept.
    pub fn paused_retention_s(&self, server_s: u64) -> u64 {
        self.max_paused_retention_s
            .map_or(server_s, |s| s.min(server_s))
    }
}

/// What a tenant's running sandboxes hold.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Usage {
    pub running_sandboxes: u64,
    pub running_vcpus: u64,
    pub running_memory_mib: u64,
}

impl Usage {
    pub fn add(&mut self, vcpus: u64, memory_mib: u64) {
        self.running_sandboxes += 1;
        self.running_vcpus += vcpus;
        self.running_memory_mib += memory_mib;
    }

    pub fn merge(&mut self, other: Self) {
        self.running_sandboxes += other.running_sandboxes;
        self.running_vcpus += other.running_vcpus;
        self.running_memory_mib += other.running_memory_mib;
    }
}

/// Tells a missing field (`None`) from an explicit `null` (`Some(None)`).
fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<Option<T>>, D::Error> {
    Option::<T>::deserialize(d).map(Some)
}

/// Quota changes: a missing field keeps its value, `null` removes the
/// limit.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuotaInput {
    #[serde(default, deserialize_with = "present")]
    pub running_sandboxes: Option<Option<u64>>,
    #[serde(default, deserialize_with = "present")]
    pub running_vcpus: Option<Option<u64>>,
    #[serde(default, deserialize_with = "present")]
    pub running_memory_mib: Option<Option<u64>>,
    #[serde(default, deserialize_with = "present")]
    pub max_session_s: Option<Option<u64>>,
    #[serde(default, deserialize_with = "present")]
    pub max_paused_retention_s: Option<Option<u64>>,
    #[serde(default, deserialize_with = "present")]
    pub monthly_egress_bytes: Option<Option<u64>>,
    #[serde(default, deserialize_with = "present")]
    pub snapshot_storage_gib: Option<Option<u64>>,
    #[serde(default, deserialize_with = "present")]
    pub volume_storage_gib: Option<Option<u64>>,
    #[serde(default, deserialize_with = "present")]
    pub persistent_sandboxes: Option<Option<u64>>,
}

impl QuotaInput {
    pub fn apply(self, mut quotas: Quotas) -> Result<Quotas, ApiError> {
        for (field, change) in [
            (&mut quotas.running_sandboxes, self.running_sandboxes),
            (&mut quotas.running_vcpus, self.running_vcpus),
            (&mut quotas.running_memory_mib, self.running_memory_mib),
            (&mut quotas.max_session_s, self.max_session_s),
            (
                &mut quotas.max_paused_retention_s,
                self.max_paused_retention_s,
            ),
            (&mut quotas.monthly_egress_bytes, self.monthly_egress_bytes),
            (&mut quotas.snapshot_storage_gib, self.snapshot_storage_gib),
            (&mut quotas.volume_storage_gib, self.volume_storage_gib),
            (&mut quotas.persistent_sandboxes, self.persistent_sandboxes),
        ] {
            if let Some(value) = change {
                *field = value;
            }
        }
        if quotas.max_session_s == Some(0) || quotas.max_paused_retention_s == Some(0) {
            return Err(ApiError::invalid(
                "max_session_s and max_paused_retention_s must be at least 1",
            ));
        }
        Ok(quotas)
    }
}

/// `POST /v1/tenants` and `PATCH /v1/tenants/{id}`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantInput {
    pub id: Option<String>,
    #[serde(default, deserialize_with = "present")]
    pub name: Option<Option<String>>,
    pub quotas: Option<QuotaInput>,
    /// Applies on top of the server's and each sandbox's policy.
    #[serde(default, deserialize_with = "present")]
    pub egress: Option<Option<Policy>>,
    pub isolation: Option<Isolation>,
}

/// Which hosts may run a tenant's sandboxes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Isolation {
    /// Firecracker or gVisor hosts.
    #[default]
    Any,
    /// Only Firecracker hosts, for untrusted code that needs a VM boundary.
    MicrovmOnly,
}

impl Isolation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::MicrovmOnly => "microvm-only",
        }
    }

    /// Unknown values read as the stricter `microvm-only`.
    pub fn parse(value: &str) -> Self {
        if value == "any" {
            Self::Any
        } else {
            Self::MicrovmOnly
        }
    }

    /// Whether a host with this backend (`Backend::name`) may run the
    /// tenant's sandboxes.
    pub fn allows(self, backend: &str) -> bool {
        self == Self::Any || backend != "gvisor"
    }
}

/// A tenant as stored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tenant {
    pub id: String,
    pub name: Option<String>,
    pub quotas: Quotas,
    pub egress: Option<Policy>,
    pub created_at: i64,
    pub updated_at: i64,
    #[serde(default)]
    pub isolation: Isolation,
}

impl TenantInput {
    /// A new tenant. Left-out quotas take `Quotas::DEFAULTS`.
    pub fn create(self, now: i64) -> Result<Tenant, ApiError> {
        let id = self
            .id
            .clone()
            .ok_or_else(|| ApiError::invalid("id is required"))?;
        if !is_tenant_id(&id) {
            return Err(ApiError::invalid(format!(
                "id must be 1 to {MAX_TENANT_ID} of a-z, 0-9 and -, starting with a letter"
            )));
        }
        let blank = Tenant {
            id,
            name: None,
            quotas: Quotas::DEFAULTS,
            egress: None,
            created_at: now,
            updated_at: now,
            isolation: Isolation::Any,
        };
        self.update(&blank, now)
    }

    /// `current` with these changes.
    pub fn update(self, current: &Tenant, now: i64) -> Result<Tenant, ApiError> {
        if self.id.as_ref().is_some_and(|id| *id != current.id) {
            return Err(ApiError::invalid("a tenant's id cannot change"));
        }
        let mut tenant = current.clone();
        if let Some(name) = self.name {
            if name
                .as_ref()
                .is_some_and(|n| n.len() > MAX_DISPLAY_NAME || n.chars().any(char::is_control))
            {
                return Err(ApiError::invalid(format!(
                    "name must be at most {MAX_DISPLAY_NAME} bytes with no control characters"
                )));
            }
            tenant.name = name.filter(|n| !n.is_empty());
        }
        if let Some(quotas) = self.quotas {
            tenant.quotas = quotas.apply(tenant.quotas)?;
        }
        if let Some(egress) = self.egress {
            tenant.egress = match egress {
                Some(mut policy) => {
                    policy.check().map_err(ApiError::invalid)?;
                    Some(policy)
                }
                None => None,
            };
        }
        if let Some(isolation) = self.isolation {
            tenant.isolation = isolation;
        }
        tenant.updated_at = now;
        Ok(tenant)
    }
}

/// `POST /v1/keys`
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyInput {
    pub tenant: Option<String>,
    pub scopes: Option<Vec<Scope>>,
    pub name: Option<String>,
}

impl KeyInput {
    /// Checks the scopes against the key's kind and sorts them.
    pub fn check(&mut self) -> Result<(), ApiError> {
        if let Some(name) = &self.name
            && (name.len() > MAX_DISPLAY_NAME || name.chars().any(char::is_control))
        {
            return Err(ApiError::invalid(format!(
                "name must be at most {MAX_DISPLAY_NAME} bytes with no control characters"
            )));
        }
        if let Some(scopes) = &mut self.scopes {
            scopes.sort();
            scopes.dedup();
            if scopes.is_empty() {
                return Err(ApiError::invalid("scopes must list at least one scope"));
            }
            if self.tenant.is_some() && scopes.contains(&Scope::TenantsAdmin) {
                return Err(ApiError::invalid("tenant keys cannot have tenants:admin"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn microvm_only_tenants_avoid_gvisor_hosts() {
        let strict = Isolation::parse("microvm-only");
        assert!(strict.allows("firecracker"));
        // Workers from before gVisor report no backend.
        assert!(strict.allows(""));
        assert!(!strict.allows("gvisor"));
        assert!(Isolation::Any.allows("gvisor"));
        assert_eq!(Isolation::parse("typo"), Isolation::MicrovmOnly);
        let input: TenantInput = serde_json::from_str(r#"{"isolation":"microvm-only"}"#).unwrap();
        assert_eq!(input.isolation, Some(Isolation::MicrovmOnly));
    }

    fn caller(tenant: Option<&str>) -> Caller {
        Caller {
            key: "key_test".into(),
            tenant: tenant.map(str::to_owned),
            scopes: Scope::allowed(tenant.is_some()),
        }
    }

    #[test]
    fn reads_scopes_from_keys() {
        let mut key = crate::db::Key {
            id: "key_1".into(),
            tenant: Some("acme".into()),
            scopes: None,
            name: None,
            created_at: 1,
            revoked_at: None,
        };
        let all = Caller::from_key(&key).unwrap();
        assert!(all.require(Scope::SandboxesWrite).is_ok());
        assert_eq!(
            all.require(Scope::TenantsAdmin).unwrap_err().code,
            Code::Forbidden
        );
        key.scopes = Some(r#"["sandboxes:read"]"#.into());
        let read = Caller::from_key(&key).unwrap();
        assert_eq!(read.scopes, [Scope::SandboxesRead]);
        assert_eq!(
            read.require(Scope::SandboxesWrite).unwrap_err().code,
            Code::Forbidden
        );
    }

    #[test]
    fn maps_requests_to_scopes() {
        use Scope::*;
        for (method, path, want) in [
            ("GET", "/v1/sandboxes", SandboxesRead),
            ("GET", "/v1/sandboxes/sbx_1/files", SandboxesRead),
            ("GET", "/v1/sandboxes/sbx_1/pty", SandboxesWrite),
            ("POST", "/v1/sandboxes/sbx_1:pause", SandboxesWrite),
            ("DELETE", "/v1/sandboxes/sbx_1", SandboxesWrite),
            ("GET", "/v1/templates/py", SandboxesRead),
            ("POST", "/v1/templates", TemplatesWrite),
            ("DELETE", "/v1/templates/py", TemplatesWrite),
            ("GET", "/v1/secrets", SandboxesRead),
            ("PATCH", "/v1/secrets/gh", SecretsWrite),
            ("GET", "/v1/tenants", TenantsAdmin),
            ("GET", "/v1/warm-pools", TenantsAdmin),
            ("GET", "/v1/nodes", TenantsAdmin),
            ("POST", "/v1/nodes/tokens", TenantsAdmin),
            ("POST", "/v1/keys", TenantsAdmin),
            ("DELETE", "/v1/keys/key_1", TenantsAdmin),
            ("POST", "/v1/templatesx", SandboxesWrite),
            ("GET", "/v1/events", AuditRead),
            ("GET", "/v1/sandboxes/sbx_1/events", AuditRead),
            ("GET", "/v1/usage", UsageRead),
        ] {
            assert_eq!(required_scope(method, path), want, "{method} {path}");
        }
    }

    #[test]
    fn finds_the_sandbox_in_a_path() {
        assert_eq!(sandbox_in_path("/v1/sandboxes/sbx_1"), Some("sbx_1"));
        assert_eq!(sandbox_in_path("/v1/sandboxes/sbx_1:pause"), Some("sbx_1"));
        assert_eq!(
            sandbox_in_path("/v1/sandboxes/sbx_1/ports/80"),
            Some("sbx_1")
        );
        assert_eq!(sandbox_in_path("/v1/sandboxes"), None);
        assert_eq!(sandbox_in_path("/v1/sandboxes/"), None);
        assert_eq!(sandbox_in_path("/v1/templates/x"), None);
    }

    #[test]
    fn tenant_keys_stay_in_their_tenant() {
        let acme = caller(Some("acme"));
        assert!(acme.sees("acme") && !acme.sees("other"));
        assert_eq!(acme.namespace(None).unwrap().as_deref(), Some("acme"));
        assert_eq!(
            acme.namespace(Some("acme")).unwrap().as_deref(),
            Some("acme")
        );
        assert_eq!(
            acme.namespace(Some("other")).unwrap_err().code,
            Code::NotFound
        );
        assert_eq!(
            acme.require(Scope::TenantsAdmin).unwrap_err().code,
            Code::Forbidden
        );

        let org = caller(None);
        assert!(org.sees("anything"));
        assert_eq!(org.namespace(None).unwrap(), None);
        assert_eq!(
            org.namespace(Some("acme")).unwrap().as_deref(),
            Some("acme")
        );
        assert!(org.require(Scope::TenantsAdmin).is_ok());
    }

    #[test]
    fn scoped_keys_round_trip() {
        assert_eq!(scoped(None, "py"), "py");
        assert_eq!(scoped(Some("acme"), "py"), "acme/py");
        assert_eq!(split("acme/py"), (Some("acme"), "py"));
        assert_eq!(split("py"), (None, "py"));
        assert!(is_tenant_id("acme-2") && is_tenant_id(DEFAULT_TENANT));
        for bad in ["", "Acme", "2acme", "a/b", "a_b", &"a".repeat(64)] {
            assert!(!is_tenant_id(bad), "{bad}");
        }
    }

    #[test]
    fn quotas_admit_up_to_the_limit() {
        let quotas = Quotas {
            running_sandboxes: Some(2),
            running_vcpus: Some(4),
            running_memory_mib: None,
            ..Quotas::default()
        };
        let mut used = Usage::default();
        assert!(quotas.admit(used, 2, 1 << 20).is_ok());
        used.add(2, 1024);
        assert!(quotas.admit(used, 2, 1024).is_ok());
        let err = quotas.admit(used, 3, 1024).unwrap_err();
        assert_eq!(err.code, Code::QuotaExceeded);
        assert!(err.message.contains("running_vcpus"), "{}", err.message);
        used.add(1, 1024);
        let err = quotas.admit(used, 1, 1024).unwrap_err();
        assert!(err.message.contains("running_sandboxes"), "{}", err.message);
        assert!(Quotas::default().admit(used, 100, 1 << 30).is_ok());

        assert_eq!(Quotas::DEFAULTS.max_timeout_s(3600), 3600);
        assert_eq!(Quotas::DEFAULTS.max_timeout_s(7 * 86_400), 86_400);
        assert_eq!(Quotas::default().paused_retention_s(10), 10);
    }

    #[test]
    fn usage_quotas() {
        let quotas = Quotas {
            monthly_egress_bytes: Some(100),
            snapshot_storage_gib: Some(1),
            ..Quotas::default()
        };
        assert!(quotas.admit_egress(99).is_ok());
        let err = quotas.admit_egress(100).unwrap_err();
        assert_eq!(err.code, Code::QuotaExceeded);
        assert!(
            err.message.contains("monthly_egress_bytes"),
            "{}",
            err.message
        );
        assert!(quotas.admit_snapshot(1 << 29, 1 << 29).is_ok());
        let err = quotas.admit_snapshot(1 << 29, (1 << 29) + 1).unwrap_err();
        assert!(
            err.message.contains("snapshot_storage_gib"),
            "{}",
            err.message
        );
        assert!(Quotas::default().admit_egress(u64::MAX).is_ok());
        assert!(Quotas::default().admit_snapshot(u64::MAX, 1).is_ok());

        let input: QuotaInput =
            serde_json::from_str(r#"{"monthly_egress_bytes":5,"snapshot_storage_gib":null}"#)
                .unwrap();
        let quotas = input.apply(quotas).unwrap();
        assert_eq!(quotas.monthly_egress_bytes, Some(5));
        assert_eq!(quotas.snapshot_storage_gib, None);
    }

    #[test]
    fn persistent_sandboxes_need_a_quota() {
        let err = Quotas::default().admit_persistent(0).unwrap_err();
        assert_eq!(err.code, Code::QuotaExceeded);
        assert!(
            err.message.contains("persistent_sandboxes"),
            "{}",
            err.message
        );
        // Stored quotas from before the field was added allow none.
        let old: Quotas = serde_json::from_str(r#"{"running_sandboxes":5}"#).unwrap();
        assert_eq!(old.persistent_sandboxes, Some(0));
        let input: QuotaInput = serde_json::from_str(r#"{"persistent_sandboxes":2}"#).unwrap();
        let quotas = input.apply(Quotas::DEFAULTS).unwrap();
        assert!(quotas.admit_persistent(1).is_ok());
        assert!(quotas.admit_persistent(2).is_err());
        let input: QuotaInput = serde_json::from_str(r#"{"persistent_sandboxes":null}"#).unwrap();
        assert!(input.apply(quotas).unwrap().admit_persistent(1000).is_ok());
    }

    #[test]
    fn tenant_input_fills_defaults_and_patches_fields() {
        let input: TenantInput = serde_json::from_str(
            r#"{"id":"acme","name":"Acme","quotas":{"running_vcpus":8,"max_session_s":null}}"#,
        )
        .unwrap();
        let tenant = input.create(1).unwrap();
        assert_eq!(tenant.name.as_deref(), Some("Acme"));
        assert_eq!(tenant.quotas.running_vcpus, Some(8));
        assert_eq!(tenant.quotas.max_session_s, None);
        assert_eq!(tenant.quotas.running_sandboxes, Some(20));

        let patch: TenantInput = serde_json::from_str(
            r#"{"quotas":{"running_sandboxes":null},"egress":{"mode":"allowlist","allow":["GitHub.com"]}}"#,
        )
        .unwrap();
        let patched = patch.update(&tenant, 2).unwrap();
        assert_eq!(patched.quotas.running_sandboxes, None);
        assert_eq!(patched.quotas.running_vcpus, Some(8));
        assert_eq!(patched.egress.as_ref().unwrap().allow, ["github.com"]);
        assert_eq!((patched.created_at, patched.updated_at), (1, 2));

        let clear: TenantInput = serde_json::from_str(r#"{"egress":null,"name":null}"#).unwrap();
        let cleared = clear.update(&patched, 3).unwrap();
        assert_eq!((cleared.egress, cleared.name), (None, None));

        let input = |json: &str| serde_json::from_str::<TenantInput>(json);
        assert!(input(r#"{"id":"Bad"}"#).unwrap().create(1).is_err());
        assert!(input("{}").unwrap().create(1).is_err());
        assert!(
            input(r#"{"id":"other"}"#)
                .unwrap()
                .update(&tenant, 4)
                .is_err()
        );
        let zero = input(r#"{"quotas":{"max_session_s":0}}"#).unwrap();
        assert!(zero.update(&tenant, 4).is_err());
        assert!(input(r#"{"quotas":{"cpu":1}}"#).is_err());
    }

    #[test]
    fn key_input_checks_scopes() {
        let mut input: KeyInput = serde_json::from_str(
            r#"{"tenant":"acme","scopes":["sandboxes:write","sandboxes:read","sandboxes:read"]}"#,
        )
        .unwrap();
        input.check().unwrap();
        assert_eq!(
            input.scopes.unwrap(),
            [Scope::SandboxesRead, Scope::SandboxesWrite]
        );
        let mut admin: KeyInput =
            serde_json::from_str(r#"{"tenant":"acme","scopes":["tenants:admin"]}"#).unwrap();
        assert!(admin.check().is_err());
        let mut empty: KeyInput = serde_json::from_str(r#"{"scopes":[]}"#).unwrap();
        assert!(empty.check().is_err());
        assert!(serde_json::from_str::<KeyInput>(r#"{"scopes":["root"]}"#).is_err());
        assert!(!Scope::allowed(true).contains(&Scope::TenantsAdmin));
        assert_eq!(Scope::allowed(false).len(), Scope::ALL.len());
    }
}
