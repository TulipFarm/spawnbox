//! Request and response bodies, request checks and API errors.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use spawn_egress::policy::check_pattern;
use spawn_egress::secrets::{VALUE_MARKER, is_header_name, is_header_text};
use spawn_egress::{Kind, Policy};
use time::OffsetDateTime;
use time::macros::format_description;

/// Built in from the server's flags: the base disk with nothing added.
pub const BASE_TEMPLATE: &str = "base";
pub const DEFAULT_TIMEOUT_S: u64 = 1800;
pub const DEFAULT_EXEC_TIMEOUT_S: u32 = 300;
pub const MAX_EXEC_TIMEOUT_S: u32 = 3600;
const MAX_IDLE_PAUSE_S: u64 = 7 * 86_400;
/// `idle_pause_s` of a persistent sandbox when not given.
pub const PERSISTENT_IDLE_PAUSE_S: u64 = 600;
const MAX_CMD_BYTES: usize = 64 * 1024;
const MAX_STDIN_BYTES: usize = 1024 * 1024;
const MAX_ENV: usize = 128;
const MAX_ENV_VALUE_BYTES: usize = 32 * 1024;
const MAX_LABELS: usize = 32;
const MAX_LABEL_KEY: usize = 63;
const MAX_LABEL_VALUE: usize = 256;
const MAX_TEMPLATE_NAME: usize = 63;
const MAX_SETUP_STEPS: usize = 64;
const MAX_WARMUP_STEPS: usize = 16;
/// Warm VMs a template may ask each host to keep.
const MAX_MIN_WARM: u32 = 16;
const MAX_STEP_BYTES: usize = 64 * 1024;
const MAX_IMAGE_REF: usize = 512;
const MAX_REGISTRY_SECRETS: usize = 4;
const VCPUS: std::ops::RangeInclusive<u32> = 1..=16;
const MEMORY_MIB: std::ops::RangeInclusive<u32> = 256..=32_768;
const DISK_GIB: std::ops::RangeInclusive<u32> = 1..=100;
const MAX_SANDBOX_SECRETS: usize = 16;
/// Volumes per sandbox; `spawn_node::volume::SLOTS` on Linux.
pub const MAX_SANDBOX_VOLUMES: usize = 4;
const MAX_VOLUME_NAME: usize = 63;
const MAX_VOLUME_PATH: usize = 1024;
pub const DEFAULT_VOLUME_GIB: u32 = 10;
pub const VOLUME_GIB: std::ops::RangeInclusive<u32> = 1..=1024;
/// Where volumes cannot be mounted: the guest's own mounts.
const RESERVED_VOLUME_DIRS: &[&str] = &["/proc", "/sys", "/dev", "/run", "/spawn"];
const MAX_SERVICES: usize = 8;
const MAX_SERVICE_NAME: usize = 63;
const MAX_SERVICE_ARGS: usize = 256;
const MAX_HEALTH_PATH: usize = 1024;
const MAX_SECRET_NAME: usize = 63;
const MAX_SECRET_VALUE: usize = 16 * 1024;
const MAX_SECRET_HOSTS: usize = 64;
const MAX_SECRET_FORMAT: usize = 1024;
const DEFAULT_SECRET_HEADER: &str = "Authorization";
const DEFAULT_SECRET_FORMAT: &str = "Bearer {value}";
const DEFAULT_GIT_USERNAME: &str = "x-access-token";
/// Headers a secret may not set: they frame or route the request.
const RESERVED_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "upgrade",
    "te",
    "trailer",
    "keep-alive",
];

/// `POST /v1/sandboxes`. Unknown fields are rejected so that spec fields
/// that are not built yet fail instead of being ignored.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateSandbox {
    pub template: Option<String>,
    pub timeout_s: Option<u64>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    /// Names of secrets to attach.
    #[serde(default)]
    pub secrets: Vec<String>,
    /// Narrows the server's egress policy.
    pub egress: Option<Policy>,
    /// Pause after this many seconds with no calls. 0 means never.
    pub idle_pause_s: Option<u64>,
    /// For org keys: the tenant to create it in. Defaults to `default`.
    pub tenant: Option<String>,
    /// Volumes to mount, by name.
    #[serde(default)]
    pub volumes: Vec<VolumeMount>,
    /// Kept until deleted: it has no timeout, and goes cold instead of
    /// being lost.
    #[serde(default)]
    pub persistent: bool,
    /// Programs kept running in the sandbox.
    #[serde(default)]
    pub services: Vec<Service>,
}

/// A program that Spawnbox keeps running in a sandbox.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Service {
    pub name: String,
    pub command: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u32>,
    /// How its port is published. Defaults to `private`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access: Option<crate::ports::Access>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<ServiceHealth>,
    #[serde(default)]
    pub restart: Restart,
}

/// How a service is checked: `{"http": "/path"}` or `{"tcp": true}`, on
/// its port.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceHealth {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub tcp: bool,
    #[serde(default = "default_interval_s")]
    pub interval_s: u32,
    #[serde(default = "default_failures")]
    pub failures: u32,
}

fn default_interval_s() -> u32 {
    10
}

fn default_failures() -> u32 {
    3
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Restart {
    #[default]
    Always,
    OnFailure,
}

impl Service {
    /// Its published port and access.
    pub fn published(&self) -> Option<(u16, crate::ports::Access)> {
        let port = u16::try_from(self.port?).ok()?;
        Some((port, self.access.unwrap_or(crate::ports::Access::Private)))
    }
}

/// One volume of `CreateSandbox`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VolumeMount {
    pub volume: String,
    /// Absolute path in the sandbox.
    pub path: String,
    #[serde(default)]
    pub read_only: bool,
}

impl CreateSandbox {
    /// Returns the timeout to use. Lowercases the egress patterns.
    pub fn check(&mut self, max_timeout_s: u64) -> Result<u64, ApiError> {
        if let Some(tenant) = &self.tenant
            && !crate::tenancy::is_tenant_id(tenant)
        {
            return Err(crate::tenancy::tenant_not_found());
        }
        if let Some(template) = &self.template
            && !is_template_name(template)
        {
            return Err(ApiError::invalid(format!(
                "template {template:?} is not a valid template name"
            )));
        }
        if self.persistent {
            if self.timeout_s.is_some() {
                return Err(ApiError::invalid(
                    "a persistent sandbox has no timeout_s; delete it when done",
                ));
            }
            match self.idle_pause_s {
                Some(0) => {
                    return Err(ApiError::invalid(
                        "idle_pause_s must be at least 1 for a persistent sandbox",
                    ));
                }
                None => self.idle_pause_s = Some(PERSISTENT_IDLE_PAUSE_S),
                Some(_) => {}
            }
        }
        let timeout = self
            .timeout_s
            .unwrap_or(DEFAULT_TIMEOUT_S.min(max_timeout_s));
        if timeout == 0 || timeout > max_timeout_s {
            return Err(ApiError::invalid(format!(
                "timeout_s must be 1 to {max_timeout_s}"
            )));
        }
        if self.idle_pause_s.is_some_and(|s| s > MAX_IDLE_PAUSE_S) {
            return Err(ApiError::invalid(format!(
                "idle_pause_s must be 0 to {MAX_IDLE_PAUSE_S}"
            )));
        }
        check_env(&self.env)?;
        if self.labels.len() > MAX_LABELS {
            return Err(ApiError::invalid(format!("at most {MAX_LABELS} labels")));
        }
        for (key, value) in &self.labels {
            let key_ok = (1..=MAX_LABEL_KEY).contains(&key.len())
                && key
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_.-".contains(&b));
            if !key_ok {
                return Err(ApiError::invalid(format!(
                    "label key {key:?} must be 1 to {MAX_LABEL_KEY} of a-z, 0-9, _ . -"
                )));
            }
            if value.len() > MAX_LABEL_VALUE {
                return Err(ApiError::invalid(format!(
                    "label {key:?} is longer than {MAX_LABEL_VALUE} bytes"
                )));
            }
        }
        if self.secrets.len() > MAX_SANDBOX_SECRETS {
            return Err(ApiError::invalid(format!(
                "at most {MAX_SANDBOX_SECRETS} secrets"
            )));
        }
        for (i, name) in self.secrets.iter().enumerate() {
            if !is_secret_name(name) {
                return Err(ApiError::invalid(format!(
                    "{name:?} is not a valid secret name"
                )));
            }
            if self.secrets[..i].contains(name) {
                return Err(ApiError::invalid(format!(
                    "secret {name:?} is listed twice"
                )));
            }
        }
        if let Some(egress) = &mut self.egress {
            egress.check().map_err(ApiError::invalid)?;
        }
        check_volume_mounts(&self.volumes)?;
        check_services(&self.services)?;
        Ok(timeout)
    }
}

fn check_services(services: &[Service]) -> Result<(), ApiError> {
    if services.len() > MAX_SERVICES {
        return Err(ApiError::invalid(format!(
            "at most {MAX_SERVICES} services"
        )));
    }
    for (i, service) in services.iter().enumerate() {
        let name = &service.name;
        if !is_service_name(name) {
            return Err(ApiError::invalid(format!(
                "service name {name:?} must be 1 to {MAX_SERVICE_NAME} of a-z, 0-9 and -, \
                 not starting with -"
            )));
        }
        let earlier = &services[..i];
        if earlier.iter().any(|s| s.name == *name) {
            return Err(ApiError::invalid(format!(
                "service {name:?} is listed twice"
            )));
        }
        let invalid = |what: &str| Err(ApiError::invalid(format!("service {name}: {what}")));
        if service.command.is_empty() || service.command.len() > MAX_SERVICE_ARGS {
            return invalid(&format!("command must have 1 to {MAX_SERVICE_ARGS} items"));
        }
        if service.command.iter().map(String::len).sum::<usize>() > MAX_CMD_BYTES
            || service.command.iter().any(|a| a.contains('\0'))
        {
            return invalid(&format!(
                "command must be at most {MAX_CMD_BYTES} bytes with no NUL"
            ));
        }
        if let Some(cwd) = &service.cwd
            && (!cwd.starts_with('/') || cwd.contains('\0'))
        {
            return invalid("cwd must be an absolute path");
        }
        check_env(&service.env)?;
        if let Some(port) = service.port {
            if !(1..=65_535).contains(&port) {
                return invalid("port must be 1 to 65535");
            }
            if earlier.iter().any(|s| s.port == Some(port)) {
                return invalid(&format!("port {port} is used by another service"));
            }
        } else if service.access.is_some() {
            return invalid("access needs a port");
        }
        if let Some(health) = &service.health {
            match (&health.http, health.tcp) {
                (Some(path), false) => {
                    let ok = path.starts_with('/')
                        && path.len() <= MAX_HEALTH_PATH
                        && path.bytes().all(|b| b.is_ascii_graphic());
                    if !ok {
                        return invalid(&format!(
                            "health.http must be a path of at most {MAX_HEALTH_PATH} bytes, \
                             starting with /"
                        ));
                    }
                }
                (None, true) => {}
                _ => return invalid("health needs one of http or tcp"),
            }
            if service.port.is_none() {
                return invalid("health needs a port");
            }
            if !(1..=3600).contains(&health.interval_s) {
                return invalid("health.interval_s must be 1 to 3600");
            }
            if !(1..=100).contains(&health.failures) {
                return invalid("health.failures must be 1 to 100");
            }
        }
    }
    Ok(())
}

pub fn is_service_name(name: &str) -> bool {
    (1..=MAX_SERVICE_NAME).contains(&name.len())
        && !name.starts_with('-')
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn check_volume_mounts(mounts: &[VolumeMount]) -> Result<(), ApiError> {
    if mounts.len() > MAX_SANDBOX_VOLUMES {
        return Err(ApiError::invalid(format!(
            "at most {MAX_SANDBOX_VOLUMES} volumes"
        )));
    }
    for (i, mount) in mounts.iter().enumerate() {
        if !is_volume_name(&mount.volume) {
            return Err(ApiError::invalid(format!(
                "{:?} is not a valid volume name",
                mount.volume
            )));
        }
        check_volume_path(&mount.path)?;
        for other in &mounts[..i] {
            if other.volume == mount.volume {
                return Err(ApiError::invalid(format!(
                    "volume {:?} is listed twice",
                    mount.volume
                )));
            }
            if path_within(&mount.path, &other.path) || path_within(&other.path, &mount.path) {
                return Err(ApiError::invalid(format!(
                    "volume paths {:?} and {:?} overlap",
                    other.path, mount.path
                )));
            }
        }
    }
    Ok(())
}

/// A clean absolute path, not `/` and not in the guest's own mounts.
fn check_volume_path(path: &str) -> Result<(), ApiError> {
    let clean = path.len() <= MAX_VOLUME_PATH
        && path.starts_with('/')
        && path[1..]
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != ".." && !part.contains('\0'));
    if !clean || path == "/" {
        return Err(ApiError::invalid(format!(
            "volume path {path:?} must be an absolute path such as /data, with no . or .. parts"
        )));
    }
    if let Some(dir) = RESERVED_VOLUME_DIRS
        .iter()
        .find(|dir| path_within(path, dir))
    {
        return Err(ApiError::invalid(format!(
            "volume path {path:?} cannot be in {dir}"
        )));
    }
    Ok(())
}

/// Whether `path` is `dir` or below it.
fn path_within(path: &str, dir: &str) -> bool {
    path.strip_prefix(dir)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

pub fn is_volume_name(name: &str) -> bool {
    (1..=MAX_VOLUME_NAME).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !name.starts_with('-')
}

/// `POST /v1/volumes`
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateVolume {
    pub name: String,
    pub size_gib: Option<u32>,
    /// For org keys: the tenant to create it in. Defaults to `default`.
    pub tenant: Option<String>,
}

impl CreateVolume {
    /// Returns the size to use.
    pub fn check(&self) -> Result<u32, ApiError> {
        if let Some(tenant) = &self.tenant
            && !crate::tenancy::is_tenant_id(tenant)
        {
            return Err(crate::tenancy::tenant_not_found());
        }
        if !is_volume_name(&self.name) {
            return Err(ApiError::invalid(format!(
                "volume name {:?} must be 1 to {MAX_VOLUME_NAME} of a-z, 0-9 and -, not starting with -",
                self.name
            )));
        }
        let size = self.size_gib.unwrap_or(DEFAULT_VOLUME_GIB);
        if !VOLUME_GIB.contains(&size) {
            return Err(ApiError::invalid(format!(
                "size_gib must be {} to {}",
                VOLUME_GIB.start(),
                VOLUME_GIB.end()
            )));
        }
        Ok(size)
    }
}

/// `POST /v1/sandboxes/{id}/exec`
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Exec {
    pub cmd: String,
    pub cwd: Option<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    pub user: Option<String>,
    pub timeout_s: Option<u32>,
    /// Written to the command's standard input, which is then closed.
    pub stdin: Option<String>,
}

impl Exec {
    /// Returns the timeout to use, in seconds.
    pub fn check(&self) -> Result<u32, ApiError> {
        if self.cmd.trim().is_empty() || self.cmd.len() > MAX_CMD_BYTES || self.cmd.contains('\0') {
            return Err(ApiError::invalid(format!(
                "cmd must be 1 to {MAX_CMD_BYTES} bytes with no NUL"
            )));
        }
        if let Some(cwd) = &self.cwd
            && (!cwd.starts_with('/') || cwd.contains('\0'))
        {
            return Err(ApiError::invalid("cwd must be an absolute path"));
        }
        if let Some(user) = &self.user {
            check_user(user)?;
        }
        check_env(&self.env)?;
        if self
            .stdin
            .as_ref()
            .is_some_and(|s| s.len() > MAX_STDIN_BYTES)
        {
            return Err(ApiError::invalid(format!(
                "stdin must be at most {MAX_STDIN_BYTES} bytes"
            )));
        }
        let timeout = self.timeout_s.unwrap_or(DEFAULT_EXEC_TIMEOUT_S);
        if timeout == 0 || timeout > MAX_EXEC_TIMEOUT_S {
            return Err(ApiError::invalid(format!(
                "timeout_s must be 1 to {MAX_EXEC_TIMEOUT_S}"
            )));
        }
        Ok(timeout)
    }
}

/// `POST /v1/sandboxes/{id}/git:clone`
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitClone {
    pub url: String,
    pub path: Option<String>,
    pub branch: Option<String>,
    pub depth: Option<u32>,
    pub user: Option<String>,
    pub timeout_s: Option<u32>,
}

impl GitClone {
    /// Returns the command that clones and then prints the commit and
    /// branch, and the destination path.
    pub fn command(&self) -> Result<(String, String), ApiError> {
        let repo = repo_name(&self.url).ok_or_else(|| {
            ApiError::invalid(
                "url must be an http:// or https:// repository URL without credentials; \
                 attach a git_https secret instead",
            )
        })?;
        let path = match &self.path {
            Some(path) if path.starts_with('/') && path.len() > 1 && !path.contains('\0') => {
                path.clone()
            }
            Some(_) => return Err(ApiError::invalid("path must be an absolute path")),
            None => format!("/workspace/{repo}"),
        };
        let mut clone = String::from("git clone --quiet");
        if let Some(branch) = &self.branch {
            let ok = (1..=255).contains(&branch.len())
                && !branch.starts_with('-')
                && branch.bytes().all(|b| b.is_ascii_graphic());
            if !ok {
                return Err(ApiError::invalid(format!(
                    "{branch:?} is not a valid branch or tag"
                )));
            }
            clone += &format!(" --branch {}", shell_quote(branch));
        }
        if let Some(depth) = self.depth {
            if depth == 0 {
                return Err(ApiError::invalid("depth must be at least 1"));
            }
            clone += &format!(" --depth {depth}");
        }
        if let Some(user) = &self.user {
            check_user(user)?;
        }
        let path_q = shell_quote(&path);
        let cmd = format!(
            "set -e\n{clone} -- {} {path_q}\ncd {path_q}\n\
             git rev-parse HEAD\ngit rev-parse --abbrev-ref HEAD",
            shell_quote(&self.url)
        );
        Ok((cmd, path))
    }
}

/// The last path segment of a clone URL without `.git`, or `None` if the
/// URL is not plain http(s) or carries credentials.
fn repo_name(url: &str) -> Option<&str> {
    if url.len() > 2048 || !url.bytes().all(|b| b.is_ascii_graphic()) {
        return None;
    }
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let (authority, path) = rest.split_once('/')?;
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let path = path.split(['?', '#']).next()?.trim_end_matches('/');
    let last = path.rsplit('/').next()?;
    let name = last.strip_suffix(".git").unwrap_or(last);
    let ok = !name.is_empty()
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
    ok.then_some(name)
}

/// Quotes `text` as one word for a POSIX shell.
pub fn shell_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

pub fn check_user(user: &str) -> Result<(), ApiError> {
    let ok = (1..=32).contains(&user.len())
        && user.starts_with(|c: char| c.is_ascii_lowercase() || c == '_')
        && user
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b));
    if ok {
        Ok(())
    } else {
        Err(ApiError::invalid(format!(
            "{user:?} is not a valid user name"
        )))
    }
}

/// `a-z`, digits, `-` and `_`, starting with a letter.
pub fn is_secret_name(name: &str) -> bool {
    (1..=MAX_SECRET_NAME).contains(&name.len())
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// A secret as stored, without its value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretSpec {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: Kind,
    pub allowed_hosts: Vec<String>,
    /// The environment variable that holds the placeholder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
}

impl SecretSpec {
    /// Checks the settings, lowercases the host patterns and fills defaults.
    fn check(&mut self) -> Result<(), ApiError> {
        if !is_secret_name(&self.name) {
            return Err(ApiError::invalid(format!(
                "name must be 1 to {MAX_SECRET_NAME} of a-z, 0-9, - and _, starting with a letter"
            )));
        }
        if self.allowed_hosts.is_empty() || self.allowed_hosts.len() > MAX_SECRET_HOSTS {
            return Err(ApiError::invalid(format!(
                "allowed_hosts must list 1 to {MAX_SECRET_HOSTS} hosts"
            )));
        }
        for host in &mut self.allowed_hosts {
            *host = check_pattern(host).map_err(ApiError::invalid)?;
        }
        if let Some(env) = &self.env {
            check_env(&BTreeMap::from([(env.clone(), String::new())]))?;
        }
        match self.kind {
            Kind::HttpHeader => {
                if self.username.is_some() {
                    return Err(ApiError::invalid("username only applies to git_https"));
                }
                let header = self
                    .header
                    .get_or_insert_with(|| DEFAULT_SECRET_HEADER.into());
                if !is_header_name(header)
                    || RESERVED_HEADERS.contains(&header.to_ascii_lowercase().as_str())
                    || header.to_ascii_lowercase().starts_with("proxy-")
                {
                    return Err(ApiError::invalid(format!(
                        "header {header:?} is not a header a secret may set"
                    )));
                }
                let format = self
                    .format
                    .get_or_insert_with(|| DEFAULT_SECRET_FORMAT.into());
                if !format.contains(VALUE_MARKER)
                    || format.len() > MAX_SECRET_FORMAT
                    || !is_header_text(format)
                {
                    return Err(ApiError::invalid(format!(
                        "format must contain {VALUE_MARKER} and be at most {MAX_SECRET_FORMAT} printable ASCII characters"
                    )));
                }
            }
            Kind::GitHttps => {
                if self.header.is_some() || self.format.is_some() {
                    return Err(ApiError::invalid(
                        "header and format only apply to http_header",
                    ));
                }
                let username = self
                    .username
                    .get_or_insert_with(|| DEFAULT_GIT_USERNAME.into());
                if username.is_empty()
                    || username.len() > 256
                    || username.contains(':')
                    || !is_header_text(username)
                {
                    return Err(ApiError::invalid(
                        "username must be 1 to 256 printable ASCII characters without :",
                    ));
                }
            }
        }
        Ok(())
    }

    /// The proxy's copy, stored under `key` (see `tenancy::scoped`).
    pub fn to_secret(&self, key: &str, value: String, version: i64) -> spawn_egress::Secret {
        spawn_egress::Secret {
            name: key.to_owned(),
            kind: self.kind,
            value,
            hosts: self.allowed_hosts.clone(),
            header: self.header.clone().unwrap_or_default(),
            format: self.format.clone().unwrap_or_default(),
            username: self.username.clone().unwrap_or_default(),
            version: u32::try_from(version).unwrap_or(u32::MAX),
        }
    }
}

fn check_secret_value(value: &str) -> Result<(), ApiError> {
    if value.is_empty() || value.len() > MAX_SECRET_VALUE || !is_header_text(value) {
        return Err(ApiError::invalid(format!(
            "value must be 1 to {MAX_SECRET_VALUE} printable ASCII characters"
        )));
    }
    Ok(())
}

/// `POST /v1/secrets` and `PATCH /v1/secrets/{name}`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretInput {
    pub name: Option<String>,
    #[serde(rename = "type")]
    pub kind: Option<Kind>,
    pub value: Option<String>,
    pub allowed_hosts: Option<Vec<String>>,
    /// An empty string removes it on update.
    pub env: Option<String>,
    pub header: Option<String>,
    pub format: Option<String>,
    pub username: Option<String>,
}

impl SecretInput {
    /// A new secret and its value.
    pub fn create(self) -> Result<(SecretSpec, String), ApiError> {
        let missing = |field: &str| ApiError::invalid(format!("{field} is required"));
        let mut spec = SecretSpec {
            name: self.name.ok_or_else(|| missing("name"))?,
            kind: self.kind.ok_or_else(|| missing("type"))?,
            allowed_hosts: self.allowed_hosts.ok_or_else(|| missing("allowed_hosts"))?,
            env: self.env.filter(|e| !e.is_empty()),
            header: self.header,
            format: self.format,
            username: self.username,
        };
        let value = self.value.ok_or_else(|| missing("value"))?;
        spec.check()?;
        check_secret_value(&value)?;
        Ok((spec, value))
    }

    /// `current` with these changes, and the new value if one was given.
    pub fn update(self, current: &SecretSpec) -> Result<(SecretSpec, Option<String>), ApiError> {
        if self.name.as_ref().is_some_and(|n| *n != current.name) {
            return Err(ApiError::invalid("a secret cannot be renamed"));
        }
        if self.kind.is_some_and(|k| k != current.kind) {
            return Err(ApiError::invalid("a secret's type cannot change"));
        }
        let mut spec = current.clone();
        if let Some(hosts) = self.allowed_hosts {
            spec.allowed_hosts = hosts;
        }
        if let Some(env) = self.env {
            spec.env = Some(env).filter(|e| !e.is_empty());
        }
        if self.header.is_some() {
            spec.header = self.header;
        }
        if self.format.is_some() {
            spec.format = self.format;
        }
        if self.username.is_some() {
            spec.username = self.username;
        }
        spec.check()?;
        if let Some(value) = &self.value {
            check_secret_value(value)?;
        }
        Ok((spec, self.value))
    }
}

#[derive(Debug, Serialize)]
pub struct SecretView {
    #[serde(flatten)]
    pub spec: SecretSpec,
    /// `null` for org-wide secrets.
    pub tenant: Option<String>,
    pub version: i64,
    pub created_at: String,
    pub updated_at: String,
}

/// `a-z`, digits and hyphens, starting with a letter.
pub fn is_template_name(name: &str) -> bool {
    (1..=MAX_TEMPLATE_NAME).contains(&name.len())
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// `POST /v1/templates`, and what is stored for every build. Unknown fields
/// are rejected, so a `base` image fails until images are supported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateSpec {
    pub name: String,
    /// Run as root with network. Their changes become a read-only layer.
    #[serde(default)]
    pub setup: Vec<String>,
    /// Run as `user` right before the snapshot.
    #[serde(default)]
    pub warmup: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub resources: Resources,
    /// Warm VMs each host keeps ready, besides demand. Not part of the
    /// build: changing it does not build the template again.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub min_warm: u32,
    /// An OCI image, such as `node:22-bookworm-slim`, to use as the base
    /// disk instead of the built-in Debian one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<String>,
    /// Held secrets the egress proxy adds to the image pull, for private
    /// registries. Not part of the build.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub registry_secrets: Vec<String>,
    /// Set by the server for a template saved from a running sandbox.
    /// Such a template is never built: its files come from the snapshot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<SnapshotOf>,
}

/// Where a snapshot template comes from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotOf {
    /// `snp_…`, unique to this snapshot.
    pub id: String,
    pub sandbox: String,
    /// The build the sandbox started from.
    pub build: Option<String>,
    /// Whether it has a read-only layer from a template's setup steps.
    pub layer: bool,
    /// Whether its base disk was unpacked from an OCI image.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub rootfs: bool,
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

/// Unset fields take the server's defaults when the template is saved.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resources {
    pub vcpus: Option<u32>,
    pub memory_mib: Option<u32>,
    pub disk_gib: Option<u32>,
}

impl TemplateSpec {
    /// The built-in `base` template.
    pub fn base(defaults: Resources) -> Self {
        Self {
            name: BASE_TEMPLATE.into(),
            setup: Vec::new(),
            warmup: Vec::new(),
            env: BTreeMap::new(),
            resources: defaults,
            min_warm: 0,
            base: None,
            registry_secrets: Vec::new(),
            snapshot: None,
        }
    }

    /// Whether its builds have their own base disk, unpacked from an image.
    pub fn own_rootfs(&self) -> bool {
        match &self.snapshot {
            Some(snapshot) => snapshot.rootfs,
            None => self.base.is_some(),
        }
    }

    /// Whether its builds have a read-only layer disk.
    pub fn has_layer(&self) -> bool {
        match &self.snapshot {
            Some(snapshot) => snapshot.layer,
            None => !self.setup.is_empty(),
        }
    }

    /// The parts a build is made from.
    pub fn for_build(&self) -> Self {
        Self {
            min_warm: 0,
            registry_secrets: Vec::new(),
            ..self.clone()
        }
    }

    /// Checks a user's template and fills unset resources from `defaults`.
    pub fn check(&mut self, defaults: Resources) -> Result<(), ApiError> {
        if self.name == BASE_TEMPLATE {
            return Err(ApiError::invalid(format!(
                "{BASE_TEMPLATE:?} is built in and cannot be changed"
            )));
        }
        if !is_template_name(&self.name) {
            return Err(ApiError::invalid(format!(
                "name must be 1 to {MAX_TEMPLATE_NAME} of a-z, 0-9 and -, starting with a letter"
            )));
        }
        if self.snapshot.is_some() {
            return Err(ApiError::invalid(
                "snapshot is set by the server; use POST /v1/sandboxes/{id}:snapshot",
            ));
        }
        check_steps("setup", &self.setup, MAX_SETUP_STEPS)?;
        check_steps("warmup", &self.warmup, MAX_WARMUP_STEPS)?;
        check_env(&self.env)?;
        if let Some(base) = &self.base
            && !is_image_ref(base)
        {
            return Err(ApiError::invalid(format!(
                "base must be an image reference of 1 to {MAX_IMAGE_REF} bytes, such as \"node:22\""
            )));
        }
        if !self.registry_secrets.is_empty() && self.base.is_none() {
            return Err(ApiError::invalid("registry_secrets needs base"));
        }
        if self.registry_secrets.len() > MAX_REGISTRY_SECRETS {
            return Err(ApiError::invalid(format!(
                "at most {MAX_REGISTRY_SECRETS} registry_secrets"
            )));
        }
        if self.min_warm > MAX_MIN_WARM {
            return Err(ApiError::invalid(format!(
                "min_warm must be 0 to {MAX_MIN_WARM}"
            )));
        }
        let r = &mut self.resources;
        for (field, value, default, range) in [
            ("vcpus", &mut r.vcpus, defaults.vcpus, VCPUS),
            (
                "memory_mib",
                &mut r.memory_mib,
                defaults.memory_mib,
                MEMORY_MIB,
            ),
            ("disk_gib", &mut r.disk_gib, defaults.disk_gib, DISK_GIB),
        ] {
            let chosen = value.or(default).unwrap_or(*range.start());
            if !range.contains(&chosen) {
                return Err(ApiError::invalid(format!(
                    "resources.{field} must be {} to {}",
                    range.start(),
                    range.end()
                )));
            }
            *value = Some(chosen);
        }
        Ok(())
    }
}

/// An image name with an optional registry, tag and digest. The guest
/// parses it fully.
fn is_image_ref(reference: &str) -> bool {
    (1..=MAX_IMAGE_REF).contains(&reference.len())
        && reference.starts_with(|c: char| c.is_ascii_alphanumeric())
        && reference
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-/:@".contains(&b))
}

fn check_steps(field: &str, steps: &[String], max: usize) -> Result<(), ApiError> {
    if steps.len() > max {
        return Err(ApiError::invalid(format!("at most {max} {field} steps")));
    }
    for (i, step) in steps.iter().enumerate() {
        if step.trim().is_empty() || step.len() > MAX_STEP_BYTES || step.contains('\0') {
            return Err(ApiError::invalid(format!(
                "{field}[{i}] must be 1 to {MAX_STEP_BYTES} bytes with no NUL"
            )));
        }
    }
    Ok(())
}

fn check_env(env: &BTreeMap<String, String>) -> Result<(), ApiError> {
    if env.len() > MAX_ENV {
        return Err(ApiError::invalid(format!(
            "at most {MAX_ENV} environment variables"
        )));
    }
    for (name, value) in env {
        let name_ok = name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
        if !name_ok {
            return Err(ApiError::invalid(format!(
                "{name:?} is not a valid environment variable name"
            )));
        }
        if value.len() > MAX_ENV_VALUE_BYTES || value.contains('\0') {
            return Err(ApiError::invalid(format!(
                "{name} must be at most {MAX_ENV_VALUE_BYTES} bytes with no NUL"
            )));
        }
    }
    Ok(())
}

/// `POST /v1/sandboxes/{id}:snapshot`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotSandbox {
    /// The new template's name.
    pub name: String,
}

/// `POST /v1/sandboxes/{id}:fork`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForkSandbox {
    pub count: Option<u32>,
}

/// Step times for creating a sandbox, in milliseconds.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Timings {
    /// Jail files, writable disk and network.
    pub prepare: f64,
    /// Start the jailer, load the snapshot, wait for the guest agent.
    pub restore: f64,
    /// Clock, entropy and hostname.
    pub fixups: f64,
    pub total: f64,
    /// Started from a warm VM instead of restored from the build.
    #[serde(skip)]
    pub warm: bool,
}

#[derive(Debug, Serialize)]
pub struct SandboxView {
    pub id: String,
    pub tenant: String,
    pub state: String,
    pub template: String,
    /// The template build it was restored from.
    pub build: Option<String>,
    pub labels: BTreeMap<String, String>,
    pub secrets: Vec<String>,
    pub volumes: Vec<VolumeMount>,
    pub egress: Policy,
    pub created_at: String,
    /// Null while paused: the timeout counts running time only.
    pub expires_at: Option<String>,
    pub paused_at: Option<String>,
    pub idle_pause_s: u64,
    /// The fleet node it runs on; null on the primary or a single server.
    pub node: Option<String>,
    pub persistent: bool,
    /// Counts the VMs it has had: 1 at create, one more per cold start.
    pub generation: i64,
    pub cold_starts: i64,
    pub last_cold_start_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timings_ms: Option<Timings>,
    /// Only on create: `warm_pool` or `build`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_from: Option<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct TemplateView {
    #[serde(flatten)]
    pub spec: TemplateSpec,
    /// `null` for org-wide templates.
    pub tenant: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    /// The build new sandboxes start from, if one is ready.
    pub current_build: Option<String>,
    pub latest_build: Option<BuildView>,
}

#[derive(Debug, Serialize)]
pub struct BuildView {
    pub id: String,
    pub template: String,
    pub state: String,
    pub created_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub error: Option<String>,
    /// The end of the build log. Only on the build endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log: Option<String>,
}

/// `2026-11-04T01:40:12.381Z`
pub fn rfc3339_ms(unix_ms: i64) -> String {
    let format =
        format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z");
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(unix_ms) * 1_000_000)
        .ok()
        .and_then(|t| t.format(format).ok())
        .unwrap_or_default()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    InvalidRequest,
    Unauthorized,
    NotFound,
    Forbidden,
    Conflict,
    QuotaExceeded,
    NoCapacity,
    NodeUnreachable,
    Internal,
}

impl Code {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::Unauthorized => "unauthorized",
            Self::NotFound => "not_found",
            Self::Forbidden => "forbidden",
            Self::Conflict => "conflict",
            Self::QuotaExceeded => "quota_exceeded",
            Self::NoCapacity => "no_capacity",
            Self::NodeUnreachable => "node_unreachable",
            Self::Internal => "internal",
        }
    }

    pub fn http_status(self) -> u16 {
        match self {
            Self::InvalidRequest => 400,
            Self::Unauthorized => 401,
            Self::NotFound => 404,
            Self::Forbidden => 403,
            Self::Conflict => 409,
            Self::QuotaExceeded => 429,
            Self::NoCapacity | Self::NodeUnreachable => 503,
            Self::Internal => 500,
        }
    }

    pub fn retryable(self) -> bool {
        matches!(
            self,
            Self::NoCapacity | Self::NodeUnreachable | Self::Internal | Self::QuotaExceeded
        )
    }
}

#[derive(Debug)]
pub struct ApiError {
    pub code: Code,
    pub message: String,
}

impl ApiError {
    pub fn new(code: Code, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(Code::InvalidRequest, message)
    }

    pub fn not_found() -> Self {
        Self::new(Code::NotFound, "sandbox not found")
    }

    /// For errors from the guest agent's file calls.
    #[cfg(target_os = "linux")]
    pub fn from_guest(status: &tonic::Status) -> Self {
        use tonic::Code as Grpc;
        let message = status.message().to_owned();
        match status.code() {
            Grpc::NotFound => Self::new(Code::NotFound, message),
            Grpc::PermissionDenied => Self::new(Code::Forbidden, message),
            Grpc::InvalidArgument => Self::invalid(message),
            Grpc::FailedPrecondition | Grpc::AlreadyExists | Grpc::ResourceExhausted => {
                Self::new(Code::Conflict, message)
            }
            _ => Self::internal(format!("guest agent: {message}")),
        }
    }

    pub fn internal(error: impl std::fmt::Display) -> Self {
        Self::new(Code::Internal, error.to_string())
    }

    /// The spec's error body.
    pub fn body(&self, request_id: &str) -> serde_json::Value {
        serde_json::json!({
            "error": {
                "code": self.code.as_str(),
                "message": self.message,
                "retryable": self.code.retryable(),
                "request_id": request_id,
            }
        })
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for ApiError {}

impl From<crate::db::Error> for ApiError {
    fn from(error: crate::db::Error) -> Self {
        Self::internal(format!("database: {error}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn min_warm_is_not_part_of_the_build() {
        let mut spec: TemplateSpec =
            serde_json::from_value(serde_json::json!({"name": "py", "setup": ["true"]})).unwrap();
        spec.check(Resources::default()).unwrap();
        let before = serde_json::to_string(&spec).unwrap();
        assert!(!before.contains("min_warm"));
        spec.min_warm = 2;
        spec.check(Resources::default()).unwrap();
        assert_eq!(serde_json::to_string(&spec.for_build()).unwrap(), before);
        spec.min_warm = MAX_MIN_WARM + 1;
        assert!(spec.check(Resources::default()).is_err());
    }

    #[test]
    fn only_the_server_sets_snapshot() {
        let snapshot =
            serde_json::json!({"id": "snp_x", "sandbox": "sbx_x", "build": null, "layer": true});
        let mut spec: TemplateSpec =
            serde_json::from_value(serde_json::json!({"name": "s", "snapshot": snapshot})).unwrap();
        assert!(spec.has_layer());
        assert!(spec.check(Resources::default()).is_err());
    }

    #[test]
    fn checks_volume_mount_paths() {
        let mount = |volume: &str, path: &str| VolumeMount {
            volume: volume.into(),
            path: path.into(),
            read_only: false,
        };
        assert!(check_volume_mounts(&[mount("a", "/data"), mount("b", "/database")]).is_ok());
        assert!(check_volume_mounts(&[mount("a", "/data"), mount("b", "/data/x")]).is_err());
        for bad in ["/", "data", "/data/", "/a/../b", "/proc/x", "/dev"] {
            assert!(check_volume_mounts(&[mount("a", bad)]).is_err(), "{bad}");
        }
    }

    fn clone(json: &str) -> Result<(String, String), String> {
        serde_json::from_str::<GitClone>(json)
            .map_err(|e| e.to_string())?
            .command()
            .map_err(|e| e.message)
    }

    #[test]
    fn clone_defaults_to_the_repo_name_under_workspace() {
        let (cmd, path) = clone(r#"{"url":"https://github.com/octocat/Hello-World.git"}"#).unwrap();
        assert_eq!(path, "/workspace/Hello-World");
        assert!(cmd.contains("git clone --quiet -- 'https://github.com/octocat/Hello-World.git' '/workspace/Hello-World'"));
        let (_, path) = clone(r#"{"url":"http://git.local:8080/a/b/c/"}"#).unwrap();
        assert_eq!(path, "/workspace/c");
    }

    #[test]
    fn clone_quotes_branch_and_path() {
        let (cmd, path) =
            clone(r#"{"url":"https://x.dev/r","path":"/tmp/it's","branch":"v1;rm","depth":1}"#)
                .unwrap();
        assert_eq!(path, "/tmp/it's");
        assert!(cmd.contains("--branch 'v1;rm' --depth 1 -- 'https://x.dev/r' '/tmp/it'\\''s'"));
    }

    #[test]
    fn clone_rejects_unsafe_requests() {
        for body in [
            r#"{"url":"https://user:pw@github.com/a/b"}"#,
            r#"{"url":"git@github.com:a/b.git"}"#,
            r#"{"url":"ssh://github.com/a/b"}"#,
            r#"{"url":"file:///etc"}"#,
            r#"{"url":"https://github.com/"}"#,
            r#"{"url":"https://github.com/a/.."}"#,
            r#"{"url":"https://github.com/a b"}"#,
            r#"{"url":"https://github.com/a/b","path":"rel"}"#,
            r#"{"url":"https://github.com/a/b","branch":"--upload-pack=x"}"#,
            r#"{"url":"https://github.com/a/b","depth":0}"#,
            r#"{"url":"https://github.com/a/b","user":"Root"}"#,
            r#"{"url":"https://github.com/a/b","token":"x"}"#,
        ] {
            assert!(clone(body).is_err(), "{body}");
        }
    }

    fn create(json: &str) -> Result<u64, String> {
        serde_json::from_str::<CreateSandbox>(json)
            .map_err(|e| e.to_string())?
            .check(86_400)
            .map_err(|e| e.message)
    }

    fn exec(json: &str) -> Result<u32, String> {
        serde_json::from_str::<Exec>(json)
            .map_err(|e| e.to_string())?
            .check()
            .map_err(|e| e.message)
    }

    #[test]
    fn create_defaults_and_accepts_good_input() {
        assert_eq!(create("{}"), Ok(DEFAULT_TIMEOUT_S));
        assert!(create(r#"{"idle_pause_s":0}"#).is_ok());
        let mut req: CreateSandbox = serde_json::from_str(
            r#"{"secrets":["gh"],"egress":{"mode":"allowlist","allow":["GitHub.com","*.npmjs.org"]}}"#,
        )
        .unwrap();
        // The default timeout shrinks to a lower cap; an asked one does not.
        assert_eq!(req.check(60).unwrap(), 60);
        req.timeout_s = Some(61);
        req.check(60).unwrap_err();
        req.check(86_400).unwrap();
        assert_eq!(req.egress.unwrap().allow, ["github.com", "*.npmjs.org"]);
        assert_eq!(
            create(
                r#"{"template":"base","timeout_s":60,"env":{"CI":"1","_X2":""},"labels":{"run.id":"r-42"}}"#
            ),
            Ok(60)
        );
    }

    #[test]
    fn persistent_create_has_no_timeout_and_pauses_when_idle() {
        let mut req: CreateSandbox = serde_json::from_str(r#"{"persistent":true}"#).unwrap();
        req.check(86_400).unwrap();
        assert_eq!(req.idle_pause_s, Some(PERSISTENT_IDLE_PAUSE_S));
        let mut req: CreateSandbox =
            serde_json::from_str(r#"{"persistent":true,"idle_pause_s":30}"#).unwrap();
        req.check(86_400).unwrap();
        assert_eq!(req.idle_pause_s, Some(30));
        let error = create(r#"{"persistent":true,"timeout_s":60}"#).unwrap_err();
        assert!(error.contains("timeout_s"), "{error}");
        let error = create(r#"{"persistent":true,"idle_pause_s":0}"#).unwrap_err();
        assert!(error.contains("idle_pause_s"), "{error}");
        assert!(create(r#"{"persistent":"yes"}"#).is_err());
    }

    #[test]
    fn checks_services() {
        let with = |services: &str| create(&format!(r#"{{"services":[{services}]}}"#));
        let web = r#"{"name":"web","command":["srv","--port","8000"],"cwd":"/workspace",
            "env":{"LOG_LEVEL":"info"},"port":8000,"access":"public",
            "health":{"http":"/healthz"},"restart":"on-failure"}"#;
        assert!(with(web).is_ok());
        assert!(with(r#"{"name":"a","command":["x"],"port":1,"health":{"tcp":true}}"#).is_ok());
        let ok =
            |name: &str, port: u32| format!(r#"{{"name":"{name}","command":["x"],"port":{port}}}"#);
        let nine: Vec<String> = (1..=9).map(|i| ok(&format!("s{i}"), i)).collect();
        assert!(with(&nine[..8].join(",")).is_ok());
        assert!(with(&nine.join(",")).is_err());
        let long = "a".repeat(64);
        for bad in [
            r#"{"name":"","command":["x"]}"#.to_owned(),
            r#"{"name":"-a","command":["x"]}"#.to_owned(),
            r#"{"name":"Web","command":["x"]}"#.to_owned(),
            r#"{"name":"a_b","command":["x"]}"#.to_owned(),
            format!(r#"{{"name":"{long}","command":["x"]}}"#),
            format!("{},{}", ok("a", 1), ok("a", 2)),
            format!("{},{}", ok("a", 1), ok("b", 1)),
            r#"{"name":"a","command":[]}"#.to_owned(),
            r#"{"name":"a"}"#.to_owned(),
            r#"{"name":"a","command":"x"}"#.to_owned(),
            r#"{"name":"a","command":["x"],"cwd":"rel"}"#.to_owned(),
            r#"{"name":"a","command":["x"],"port":0}"#.to_owned(),
            r#"{"name":"a","command":["x"],"port":65536}"#.to_owned(),
            r#"{"name":"a","command":["x"],"access":"public"}"#.to_owned(),
            r#"{"name":"a","command":["x"],"env":{"1X":"y"}}"#.to_owned(),
            r#"{"name":"a","command":["x"],"health":{"tcp":true}}"#.to_owned(),
            r#"{"name":"a","command":["x"],"port":1,"health":{}}"#.to_owned(),
            r#"{"name":"a","command":["x"],"port":1,"health":{"tcp":true,"http":"/"}}"#.to_owned(),
            r#"{"name":"a","command":["x"],"port":1,"health":{"http":"x"}}"#.to_owned(),
            r#"{"name":"a","command":["x"],"port":1,"health":{"http":"/a b"}}"#.to_owned(),
            r#"{"name":"a","command":["x"],"port":1,"health":{"tcp":true,"interval_s":0}}"#
                .to_owned(),
            r#"{"name":"a","command":["x"],"port":1,"health":{"tcp":true,"interval_s":3601}}"#
                .to_owned(),
            r#"{"name":"a","command":["x"],"port":1,"health":{"tcp":true,"failures":0}}"#
                .to_owned(),
            r#"{"name":"a","command":["x"],"port":1,"health":{"tcp":true,"failures":101}}"#
                .to_owned(),
            r#"{"name":"a","command":["x"],"restart":"never"}"#.to_owned(),
            r#"{"name":"a","command":["x"],"user":"root"}"#.to_owned(),
        ] {
            assert!(with(&bad).is_err(), "{bad}");
        }
        let req: CreateSandbox =
            serde_json::from_str(&format!(r#"{{"services":[{}]}}"#, ok("a", 80))).unwrap();
        let service = &req.services[0];
        assert_eq!(service.restart, Restart::Always);
        assert_eq!(
            service.published(),
            Some((80, crate::ports::Access::Private))
        );
        let health: ServiceHealth = serde_json::from_str(r#"{"tcp":true}"#).unwrap();
        assert_eq!((health.interval_s, health.failures), (10, 3));
    }

    #[test]
    fn create_rejects_bad_or_unsupported_input() {
        assert!(create(r#"{"template":"node22"}"#).is_ok());
        for json in [
            r#"{"template":"Node_22"}"#,
            r#"{"timeout_s":0}"#,
            r#"{"idle_pause_s":604801}"#,
            r#"{"timeout_s":86401}"#,
            r#"{"env":{"1X":"a"}}"#,
            r#"{"env":{"A-B":"a"}}"#,
            r#"{"env":{"A":"a\u0000"}}"#,
            r#"{"labels":{"Run":"a"}}"#,
            r#"{"labels":{"":"a"}}"#,
            r#"{"secrets":["Git Hub"]}"#,
            r#"{"secrets":["gh","gh"]}"#,
            r#"{"egress":{"mode":"allow_all","allow":["a.com"]}}"#,
            r#"{"egress":{"mode":"allowlist","allow":["10.0.0.1"]}}"#,
            r#"{"egress":{"mode":"open"}}"#,
            r#"{"ports":[3000]}"#,
        ] {
            assert!(create(json).is_err(), "{json}");
        }
    }

    #[test]
    fn exec_checks_its_fields() {
        assert_eq!(exec(r#"{"cmd":"ls"}"#), Ok(DEFAULT_EXEC_TIMEOUT_S));
        assert_eq!(
            exec(r#"{"cmd":"ls","cwd":"/tmp","user":"root","timeout_s":5}"#),
            Ok(5)
        );
        assert!(exec(r#"{"cmd":"cat","stdin":"x"}"#).is_ok());
        let big = format!(
            r#"{{"cmd":"cat","stdin":"{}"}}"#,
            "x".repeat(MAX_STDIN_BYTES + 1)
        );
        assert!(exec(&big).is_err());
        for json in [
            r#"{"cmd":" "}"#,
            r#"{"cmd":"ls","cwd":"tmp"}"#,
            r#"{"cmd":"ls","user":"Root"}"#,
            r#"{"cmd":"ls","user":"a;b"}"#,
            r#"{"cmd":"ls","timeout_s":0}"#,
            r#"{"cmd":"ls","timeout_s":3601}"#,
            r#"{"cmd":"ls","stdin":1}"#,
        ] {
            assert!(exec(json).is_err(), "{json}");
        }
    }

    fn template(json: &str) -> Result<TemplateSpec, String> {
        let mut spec: TemplateSpec = serde_json::from_str(json).map_err(|e| e.to_string())?;
        let defaults = Resources {
            vcpus: Some(2),
            memory_mib: Some(1024),
            disk_gib: Some(20),
        };
        spec.check(defaults).map_err(|e| e.message)?;
        Ok(spec)
    }

    #[test]
    fn template_base_is_an_image_reference() {
        let spec = template(r#"{"name":"n","base":"ghcr.io/acme/node:22@sha256:ab12"}"#).unwrap();
        assert!(spec.own_rootfs());
        assert!(template(r#"{"name":"n","base":"node 22"}"#).is_err());
        assert!(template(r#"{"name":"n","base":"-v"}"#).is_err());
        assert!(template(r#"{"name":"n","registry_secrets":["reg"]}"#).is_err());
        let spec = template(r#"{"name":"n","base":"x","registry_secrets":["reg"]}"#).unwrap();
        assert!(spec.for_build().registry_secrets.is_empty());
    }

    #[test]
    fn template_fills_default_resources() {
        let spec = template(
            r#"{"name":"py","setup":["apt-get install -y python3"],"resources":{"vcpus":4}}"#,
        )
        .unwrap();
        assert_eq!(
            spec.resources,
            Resources {
                vcpus: Some(4),
                memory_mib: Some(1024),
                disk_gib: Some(20),
            }
        );
    }

    #[test]
    fn template_rejects_bad_specs() {
        let many_steps = serde_json::to_string(&vec!["true"; MAX_SETUP_STEPS + 1]).unwrap();
        for json in [
            r#"{"name":"base"}"#.to_owned(),
            r#"{"name":"9lives"}"#.to_owned(),
            r#"{"name":"a_b"}"#.to_owned(),
            r#"{"name":"py","setup":[" "]}"#.to_owned(),
            format!(r#"{{"name":"py","setup":{many_steps}}}"#),
            r#"{"name":"py","env":{"A-B":"1"}}"#.to_owned(),
            r#"{"name":"py","resources":{"vcpus":0}}"#.to_owned(),
            r#"{"name":"py","resources":{"memory_mib":128}}"#.to_owned(),
            r#"{"name":"py","resources":{"disk_gib":101}}"#.to_owned(),
            r#"{"name":"py","resources":{"gpus":1}}"#.to_owned(),
        ] {
            assert!(template(&json).is_err(), "{json}");
        }
    }

    #[test]
    fn formats_times_with_milliseconds() {
        assert_eq!(rfc3339_ms(1_793_756_412_381), "2026-11-04T01:40:12.381Z");
        assert_eq!(rfc3339_ms(0), "1970-01-01T00:00:00.000Z");
    }

    fn secret(json: &str) -> Result<(SecretSpec, String), String> {
        serde_json::from_str::<SecretInput>(json)
            .map_err(|e| e.to_string())?
            .create()
            .map_err(|e| e.message)
    }

    #[test]
    fn secrets_fill_defaults() {
        let (spec, value) = secret(
            r#"{"name":"gh","type":"http_header","value":"tok","allowed_hosts":["API.github.com"],"env":"GH_TOKEN"}"#,
        )
        .unwrap();
        assert_eq!(value, "tok");
        assert_eq!(spec.allowed_hosts, ["api.github.com"]);
        assert_eq!(spec.header.as_deref(), Some("Authorization"));
        assert_eq!(spec.format.as_deref(), Some("Bearer {value}"));
        let (spec, _) = secret(
            r#"{"name":"git","type":"git_https","value":"tok","allowed_hosts":["github.com"]}"#,
        )
        .unwrap();
        assert_eq!(spec.username.as_deref(), Some("x-access-token"));
        assert_eq!(spec.header, None);
    }

    #[test]
    fn secrets_reject_bad_input() {
        let ok = r#""name":"gh","type":"http_header","allowed_hosts":["a.com"]"#;
        for json in [
            format!(r#"{{{ok}}}"#),
            format!(r#"{{{ok},"value":""}}"#),
            format!(r#"{{{ok},"value":"a
b"}}"#),
            format!(r#"{{{ok},"value":"v","header":"Host"}}"#),
            format!(r#"{{{ok},"value":"v","header":"Proxy-Authorization"}}"#),
            format!(r#"{{{ok},"value":"v","format":"Bearer"}}"#),
            format!(r#"{{{ok},"value":"v","username":"me"}}"#),
            format!(r#"{{{ok},"value":"v","env":"1X"}}"#),
            format!(r#"{{{ok},"value":"v","extra":1}}"#),
            r#"{"name":"gh","type":"http_header","value":"v","allowed_hosts":[]}"#.into(),
            r#"{"name":"gh","type":"ssh_key","value":"v","allowed_hosts":["a.com"]}"#.into(),
            r#"{"name":"gh","type":"git_https","value":"v","allowed_hosts":["a.com"],"header":"X"}"#.into(),
            r#"{"name":"g:h","type":"git_https","value":"v","allowed_hosts":["a.com"]}"#.into(),
        ] {
            assert!(secret(&json).is_err(), "{json}");
        }
    }

    #[test]
    fn secret_updates_keep_name_and_type() {
        let (spec, _) = secret(
            r#"{"name":"gh","type":"http_header","value":"v","allowed_hosts":["a.com"],"env":"T"}"#,
        )
        .unwrap();
        let update = |json: &str| {
            serde_json::from_str::<SecretInput>(json)
                .unwrap()
                .update(&spec)
                .map_err(|e| e.message)
        };
        let (new, value) = update(r#"{"value":"v2","allowed_hosts":["b.com"],"env":""}"#).unwrap();
        assert_eq!(
            (new.allowed_hosts, new.env, value),
            (vec!["b.com".to_owned()], None, Some("v2".to_owned()))
        );
        assert_eq!(update("{}").unwrap(), (spec.clone(), None));
        assert!(update(r#"{"name":"other"}"#).is_err());
        assert!(update(r#"{"type":"git_https"}"#).is_err());
    }
}
