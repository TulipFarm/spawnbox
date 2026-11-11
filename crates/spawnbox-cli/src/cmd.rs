//! What each command does.

use std::collections::BTreeMap;
use std::io::{IsTerminal, Read, Write};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use reqwest::{Method, StatusCode};
use serde_json::{Map, Value, json};

use crate::api::{Api, ApiError, seg};
use crate::{
    Cli, Command, CreateArgs, EgressArgs, EventsArgs, ExecArgs, KeysCommand, PortsCommand,
    SecretsCommand, ServicesArgs, ServicesCommand, TemplatesCommand, TenantsCommand,
    VolumesCommand, config, files, pty,
};

const DEFAULT_URL: &str = "http://127.0.0.1:8080";
const MAX_STDIN: usize = 1024 * 1024;

pub async fn run(cli: Cli) -> Result<i32> {
    let path = config::path();
    let saved = match &path {
        Some(path) => config::load(path)?,
        None => config::Config::default(),
    };
    let url = cli
        .url
        .clone()
        .or(saved.url)
        .unwrap_or_else(|| DEFAULT_URL.to_owned());
    if matches!(cli.command, Command::Login) {
        return login(&url, cli.key, path.as_deref()).await;
    }
    let key = cli
        .key
        .or(saved.key)
        .context("no API key: run `spawnbox login`, or set SPAWNBOX_API_KEY")?;
    let api = Api::new(&url, key, cli.step)?;
    let out = Out { json: cli.json };
    match cli.command {
        Command::Login | Command::Doctor => unreachable!("handled before"),
        Command::Create(args) => create(&api, &out, args).await,
        Command::Ls { tenant, state } => list(&api, &out, tenant, state).await,
        Command::Get { id } => {
            out.json(&api.get(&format!("/sandboxes/{}", seg(&id))).await?);
            Ok(0)
        }
        Command::Kill { ids } => {
            for id in ids {
                api.delete(&format!("/sandboxes/{}", seg(&id))).await?;
                println!("{id}");
            }
            Ok(0)
        }
        Command::Pause { ids } => state_change(&api, &out, &ids, "pause").await,
        Command::Resume { ids } => state_change(&api, &out, &ids, "resume").await,
        Command::Fork { id, count } => {
            let path = format!("/sandboxes/{}:fork", seg(&id));
            let reply = api.post(&path, &json!({ "count": count })).await?;
            out.show(&reply, || {
                let ids = reply["sandboxes"].as_array().into_iter().flatten();
                ids.map(|s| text(&s["id"])).collect::<Vec<_>>().join("\n")
            });
            let failed = reply["failed"].as_u64().unwrap_or(0);
            if failed > 0 {
                eprintln!("{failed} of {count} copies failed to start");
                return Ok(1);
            }
            Ok(0)
        }
        Command::Snapshot { id, name } => {
            let path = format!("/sandboxes/{}:snapshot", seg(&id));
            let reply = api.post(&path, &json!({ "name": name })).await?;
            out.show(&reply, || {
                format!("{} {}", text(&reply["template"]), text(&reply["build"]))
            });
            Ok(0)
        }
        Command::Exec(args) => exec(&api, &out, args).await,
        Command::Sh { id, user, cwd, cmd } => {
            let options = pty::Options {
                user: user.as_deref(),
                cwd: cwd.as_deref(),
                cmd: cmd.as_deref(),
            };
            pty::run(&api, &id, &options).await
        }
        Command::Cp { from, to, user } => {
            files::copy(
                &api,
                &files::place(&from),
                &files::place(&to),
                user.as_deref(),
            )
            .await?;
            Ok(0)
        }
        Command::Clone {
            id,
            repo,
            path,
            branch,
            depth,
            user,
        } => {
            let body = object([
                ("url", Some(json!(repo))),
                ("path", path.map(Value::from)),
                ("branch", branch.map(Value::from)),
                ("depth", depth.map(Value::from)),
                ("user", user.map(Value::from)),
            ]);
            let done = api
                .post(&format!("/sandboxes/{}/git:clone", seg(&id)), &body)
                .await?;
            out.show(&done, || {
                format!(
                    "{} at {} ({})",
                    text(&done["path"]),
                    text(&done["commit"]),
                    text(&done["branch"])
                )
            });
            Ok(0)
        }
        Command::Ports(command) => ports(&api, &out, command).await,
        Command::Services(args) => services(&api, &out, args).await,
        Command::Templates(command) => templates(&api, &out, command).await,
        Command::Secrets(command) => secrets(&api, &out, command).await,
        Command::Volumes(command) => volumes(&api, &out, command).await,
        Command::Tenants(command) => tenants(&api, &out, command).await,
        Command::Keys(command) => keys(&api, &out, command).await,
        Command::Events(args) => events(&api, &out, args).await,
        Command::Usage {
            tenant,
            from,
            to,
            by_sandbox,
        } => usage(&api, &out, tenant, from, to, by_sandbox).await,
    }
}

/// Human output by default, the server's JSON with `--json`.
struct Out {
    json: bool,
}

impl Out {
    fn json(&self, value: &Value) {
        println!(
            "{}",
            serde_json::to_string_pretty(value).unwrap_or_default()
        );
    }

    fn show(&self, value: &Value, human: impl FnOnce() -> String) {
        if self.json {
            self.json(value);
        } else {
            println!("{}", human());
        }
    }

    fn table(&self, value: &Value, items: &[Value], columns: &[(&str, &str)]) {
        if self.json {
            return self.json(value);
        }
        let rows: Vec<Vec<String>> = items
            .iter()
            .map(|item| columns.iter().map(|(_, key)| cell(item, key)).collect())
            .collect();
        let headers: Vec<String> = columns.iter().map(|(h, _)| (*h).to_owned()).collect();
        print!("{}", render_table(&headers, &rows));
    }
}

fn render_table(headers: &[String], rows: &[Vec<String>]) -> String {
    let mut widths: Vec<usize> = headers.iter().map(String::len).collect();
    for row in rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }
    let mut out = String::new();
    for row in std::iter::once(headers).chain(rows.iter().map(Vec::as_slice)) {
        let line: Vec<String> = row
            .iter()
            .zip(&widths)
            .map(|(cell, width)| format!("{cell:<width$}"))
            .collect();
        out.push_str(line.join("  ").trim_end());
        out.push('\n');
    }
    out
}

/// A field as text; `a.b` reads nested fields; missing or null is `-`.
fn cell(item: &Value, key: &str) -> String {
    let value = key.split('.').fold(item, |v, k| &v[k]);
    match value {
        Value::Null => "-".to_owned(),
        Value::String(s) => s.clone(),
        Value::Array(items) => items.iter().map(text).collect::<Vec<_>>().join(","),
        other => other.to_string(),
    }
}

fn text(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => "-".to_owned(),
        other => other.to_string(),
    }
}

/// A JSON object of the fields that are set.
fn object<const N: usize>(fields: [(&str, Option<Value>); N]) -> Value {
    Value::Object(
        fields
            .into_iter()
            .filter_map(|(k, v)| v.map(|v| (k.to_owned(), v)))
            .collect::<Map<_, _>>(),
    )
}

fn pairs(items: &[String], what: &str) -> Result<BTreeMap<String, String>> {
    items
        .iter()
        .map(|item| {
            item.split_once('=')
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .with_context(|| format!("{what} {item:?} must be KEY=VALUE"))
        })
        .collect()
}

fn egress(args: EgressArgs) -> Option<Value> {
    if args.egress.is_none() && args.allow.is_empty() && args.deny.is_empty() {
        return None;
    }
    let mode = args.egress.unwrap_or_else(|| {
        if args.allow.is_empty() {
            "allow_all".to_owned()
        } else {
            "allowlist".to_owned()
        }
    });
    Some(json!({ "mode": mode, "allow": args.allow, "deny": args.deny }))
}

fn tenant_query(tenant: Option<&str>) -> String {
    tenant.map_or_else(String::new, |t| format!("?tenant={}", seg(t)))
}

async fn login(url: &str, key: Option<String>, path: Option<&std::path::Path>) -> Result<i32> {
    let path = path.context("cannot find a config directory: set HOME or XDG_CONFIG_HOME")?;
    let key = match key {
        Some(key) => key,
        None if std::io::stdin().is_terminal() => rpassword::prompt_password("API key: ")?,
        None => {
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            line
        }
    };
    let key = key.trim().to_owned();
    anyhow::ensure!(!key.is_empty(), "the API key is empty");
    let api = Api::new(url, key.clone(), None)?;
    match api.get("/sandboxes?limit=1").await {
        Ok(_) => {}
        // The key works but cannot list sandboxes (scopes); still save it.
        Err(error) if ApiError::is(&error, StatusCode::FORBIDDEN) => {}
        Err(error) => return Err(error.context("check the key")),
    }
    let config = config::Config {
        url: Some(api.base().to_owned()),
        key: Some(key),
    };
    config::save(path, &config)?;
    println!("Logged in to {}. Saved in {}.", api.base(), path.display());
    Ok(0)
}

async fn create(api: &Api, out: &Out, args: CreateArgs) -> Result<i32> {
    let env = pairs(&args.env, "--env")?;
    let labels = pairs(&args.labels, "--label")?;
    let volumes = args
        .volumes
        .iter()
        .map(|v| volume_mount(v))
        .collect::<Result<Vec<_>>>()?;
    let file = match &args.service_file {
        Some(path) => Some(
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?,
        ),
        None => None,
    };
    let services = service_list(&args.services, file.as_deref())?;
    let body = object([
        ("template", args.template.map(Value::from)),
        ("tenant", args.tenant.map(Value::from)),
        ("timeout_s", args.timeout.map(Value::from)),
        ("idle_pause_s", args.idle_pause.map(Value::from)),
        ("persistent", args.persistent.then_some(Value::from(true))),
        ("env", (!env.is_empty()).then(|| json!(env))),
        ("labels", (!labels.is_empty()).then(|| json!(labels))),
        (
            "secrets",
            (!args.secrets.is_empty()).then(|| json!(args.secrets)),
        ),
        ("volumes", (!volumes.is_empty()).then(|| json!(volumes))),
        ("services", (!services.is_empty()).then(|| json!(services))),
        ("egress", egress(args.egress)),
    ]);
    let sandbox = api.post("/sandboxes", &body).await?;
    out.show(&sandbox, || text(&sandbox["id"]));
    Ok(0)
}

async fn list(api: &Api, out: &Out, tenant: Option<String>, state: Option<String>) -> Result<i32> {
    let mut all = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let mut query = vec![("limit", "200".to_owned())];
        query.extend(tenant.clone().map(|t| ("tenant", t)));
        query.extend(state.clone().map(|s| ("state", s)));
        query.extend(cursor.take().map(|c| ("cursor", c)));
        let page = api
            .json(api.request(Method::GET, "/sandboxes").query(&query))
            .await?;
        all.extend(page["sandboxes"].as_array().cloned().unwrap_or_default());
        match page["next_cursor"].as_str() {
            Some(next) => cursor = Some(next.to_owned()),
            None => break,
        }
    }
    out.table(
        &json!({ "sandboxes": all }),
        &all,
        &[
            ("ID", "id"),
            ("STATE", "state"),
            ("TEMPLATE", "template"),
            ("TENANT", "tenant"),
            ("CREATED", "created_at"),
            ("EXPIRES", "expires_at"),
        ],
    );
    Ok(0)
}

async fn state_change(api: &Api, out: &Out, ids: &[String], action: &str) -> Result<i32> {
    for id in ids {
        let sandbox = api
            .json(api.request(Method::POST, &format!("/sandboxes/{}:{action}", seg(id))))
            .await?;
        out.show(&sandbox, || format!("{id} {}", text(&sandbox["state"])));
    }
    Ok(0)
}

/// One argument is a shell line as written. More arguments are quoted, so
/// that `exec ID -- ls "my dir"` means what it says.
pub fn shell_line(args: &[String]) -> String {
    if let [line] = args {
        return line.clone();
    }
    args.iter()
        .map(|arg| {
            let safe = !arg.is_empty()
                && arg
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_@%+=:,./-".contains(&b));
            if safe {
                arg.clone()
            } else {
                format!("'{}'", arg.replace('\'', r"'\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

async fn exec(api: &Api, out: &Out, args: ExecArgs) -> Result<i32> {
    let env = pairs(&args.env, "--env")?;
    let stdin = if args.stdin {
        let mut data = Vec::new();
        std::io::stdin()
            .take(MAX_STDIN as u64 + 1)
            .read_to_end(&mut data)?;
        anyhow::ensure!(data.len() <= MAX_STDIN, "stdin is larger than 1 MiB");
        Some(String::from_utf8(data).context("stdin must be UTF-8 text")?)
    } else {
        None
    };
    let body = object([
        ("cmd", Some(json!(shell_line(&args.cmd)))),
        ("cwd", args.cwd.map(Value::from)),
        ("user", args.user.map(Value::from)),
        ("env", (!env.is_empty()).then(|| json!(env))),
        ("timeout_s", args.timeout.map(Value::from)),
        ("stdin", stdin.map(Value::from)),
    ]);
    let path = format!("/sandboxes/{}/exec", seg(&args.id));
    if out.json {
        let result = api.post(&path, &body).await?;
        out.json(&result);
        return Ok(pty::exit_code(&result));
    }
    let request = api.request(Method::POST, &path).json(&body);
    let (mut stdout, mut stderr) = (std::io::stdout(), std::io::stderr());
    let code = api
        .events(request, |event| {
            let data: Value = serde_json::from_str(&event.data).unwrap_or_default();
            match event.event.as_str() {
                "stdout" => {
                    stdout.write_all(text(&data["text"]).as_bytes())?;
                    stdout.flush()?;
                }
                "stderr" => {
                    stderr.write_all(text(&data["text"]).as_bytes())?;
                    stderr.flush()?;
                }
                "exit" => {
                    if data["timed_out"] == true {
                        eprintln!("spawnbox: the command timed out");
                    }
                    return Ok(Some(pty::exit_code(&data)));
                }
                "error" => {
                    let error = ApiError::from_body(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        event.data.as_bytes(),
                    );
                    return Err(error.into());
                }
                _ => {}
            }
            Ok(None)
        })
        .await?;
    code.context("the output stream ended without an exit status")
}

async fn ports(api: &Api, out: &Out, command: PortsCommand) -> Result<i32> {
    match command {
        PortsCommand::Publish {
            id,
            port,
            access,
            ttl,
        } => {
            let body = object([
                ("port", Some(json!(port))),
                ("access", access.map(Value::from)),
                ("ttl_s", ttl.map(Value::from)),
            ]);
            let published = api
                .post(&format!("/sandboxes/{}/ports", seg(&id)), &body)
                .await?;
            out.show(&published, || text(&published["url"]));
        }
        PortsCommand::Ls { id } => {
            let list = api.get(&format!("/sandboxes/{}/ports", seg(&id))).await?;
            let items = list["ports"].as_array().cloned().unwrap_or_default();
            out.table(
                &list,
                &items,
                &[
                    ("PORT", "port"),
                    ("ACCESS", "access"),
                    ("URL", "url"),
                    ("EXPIRES", "expires_at"),
                ],
            );
        }
        PortsCommand::Rm { id, port } => {
            api.delete(&format!("/sandboxes/{}/ports/{port}", seg(&id)))
                .await?;
        }
    }
    Ok(0)
}

/// The services of `--service` values, then those of a `--service-file`
/// that holds a list.
fn service_list(items: &[String], file: Option<&str>) -> Result<Vec<Value>> {
    let mut services = items
        .iter()
        .map(|item| {
            let service: Value = serde_json::from_str(item)
                .with_context(|| format!("--service {item:?} is not JSON"))?;
            anyhow::ensure!(
                service.is_object(),
                "--service {item:?} must be a JSON object"
            );
            Ok(service)
        })
        .collect::<Result<Vec<_>>>()?;
    if let Some(file) = file {
        let listed: Vec<Value> =
            serde_json::from_str(file).context("--service-file must hold a JSON list")?;
        services.extend(listed);
    }
    Ok(services)
}

async fn services(api: &Api, out: &Out, args: ServicesArgs) -> Result<i32> {
    let command = match (args.command, args.id) {
        (Some(command), _) => command,
        (None, Some(id)) => ServicesCommand::Ls { id },
        (None, None) => bail!("give a sandbox ID, or a command: ls, restart or logs"),
    };
    match command {
        ServicesCommand::Ls { id } => {
            let list = api
                .get(&format!("/sandboxes/{}/services", seg(&id)))
                .await?;
            let items = list["services"].as_array().cloned().unwrap_or_default();
            let items: Vec<Value> = items
                .into_iter()
                .map(|mut item| {
                    item["last_exit"] = match &item["last_exit"] {
                        Value::Null => Value::Null,
                        exit if !exit["code"].is_null() => json!(format!("code {}", exit["code"])),
                        exit => json!(format!("signal {}", exit["signal"])),
                    };
                    item
                })
                .collect();
            out.table(
                &list,
                &items,
                &[
                    ("NAME", "name"),
                    ("STATE", "state"),
                    ("PID", "pid"),
                    ("RESTARTS", "restarts"),
                    ("LAST EXIT", "last_exit"),
                    ("STARTED", "started_at"),
                ],
            );
        }
        ServicesCommand::Restart { id, name } => {
            api.post(
                &format!("/sandboxes/{}/services/{}:restart", seg(&id), seg(&name)),
                &json!({}),
            )
            .await?;
        }
        ServicesCommand::Logs { id, name, follow } => {
            let path = format!("/sandboxes/{}/services/{}/logs", seg(&id), seg(&name));
            let mut stdout = std::io::stdout();
            if !follow {
                let response = api.send(api.request(Method::GET, &path)).await?;
                stdout.write_all(&response.bytes().await?)?;
                return Ok(0);
            }
            let request = api.request(Method::GET, &path).query(&[("follow", "true")]);
            api.events(request, |event| {
                let data: Value = serde_json::from_str(&event.data).unwrap_or_default();
                match event.event.as_str() {
                    "output" => {
                        stdout.write_all(text(&data["text"]).as_bytes())?;
                        stdout.flush()?;
                    }
                    "error" => {
                        let error = ApiError::from_body(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            event.data.as_bytes(),
                        );
                        return Err(error.into());
                    }
                    _ => {}
                }
                Ok(None::<()>)
            })
            .await?;
            bail!("the log stream ended");
        }
    }
    Ok(0)
}

async fn templates(api: &Api, out: &Out, command: TemplatesCommand) -> Result<i32> {
    match command {
        TemplatesCommand::Build {
            file,
            devcontainer,
            name,
            tenant,
            no_wait,
        } => {
            let source = std::fs::read_to_string(&file)
                .with_context(|| format!("read {}", file.display()))?;
            let body: Value = if devcontainer {
                let (body, ignored) = crate::devcontainer::to_template(&source, name.as_deref())?;
                if !ignored.is_empty() {
                    eprintln!("ignored: {}", ignored.join(", "));
                }
                body
            } else {
                serde_json::from_str(&source)
                    .with_context(|| format!("{} must be JSON", file.display()))?
            };
            let template = api
                .post(
                    &format!("/templates{}", tenant_query(tenant.as_deref())),
                    &body,
                )
                .await?;
            let name = text(&template["template"]["name"]);
            let build = text(&template["build"]["id"]);
            if no_wait {
                out.show(&template, || format!("{name}: build {build} started"));
                return Ok(0);
            }
            eprintln!("{name}: build {build} started");
            wait_for_build(api, out, &name, &build, tenant.as_deref()).await
        }
        TemplatesCommand::Ls { tenant } => {
            let list = api
                .get(&format!("/templates{}", tenant_query(tenant.as_deref())))
                .await?;
            let items = list["templates"].as_array().cloned().unwrap_or_default();
            out.table(
                &list,
                &items,
                &[
                    ("NAME", "name"),
                    ("TENANT", "tenant"),
                    ("BUILD", "latest_build.state"),
                    ("READY BUILD", "current_build"),
                    ("UPDATED", "updated_at"),
                ],
            );
            Ok(0)
        }
        TemplatesCommand::Get { name, tenant } => {
            out.json(&get_template(api, &name, tenant.as_deref()).await?);
            Ok(0)
        }
        TemplatesCommand::Logs { name, tenant } => {
            let template = get_template(api, &name, tenant.as_deref()).await?;
            let build = template["latest_build"]["id"]
                .as_str()
                .context("the template has no build")?;
            let build = get_build(api, &name, build, tenant.as_deref()).await?;
            out.show(&build, || {
                build["log"]
                    .as_str()
                    .unwrap_or_default()
                    .trim_end()
                    .to_owned()
            });
            Ok(0)
        }
        TemplatesCommand::Rm { name, tenant } => {
            api.delete(&format!(
                "/templates/{}{}",
                seg(&name),
                tenant_query(tenant.as_deref())
            ))
            .await?;
            Ok(0)
        }
    }
}

async fn get_template(api: &Api, name: &str, tenant: Option<&str>) -> Result<Value> {
    api.get(&format!("/templates/{}{}", seg(name), tenant_query(tenant)))
        .await
}

async fn get_build(api: &Api, name: &str, build: &str, tenant: Option<&str>) -> Result<Value> {
    api.get(&format!(
        "/templates/{}/builds/{}{}",
        seg(name),
        seg(build),
        tenant_query(tenant)
    ))
    .await
}

async fn wait_for_build(
    api: &Api,
    out: &Out,
    name: &str,
    build: &str,
    tenant: Option<&str>,
) -> Result<i32> {
    let mut last = String::new();
    loop {
        let view = get_build(api, name, build, tenant).await?;
        let state = text(&view["state"]);
        if state != last {
            eprintln!("{name}: {state}");
            last.clone_from(&state);
        }
        match state.as_str() {
            "ready" => {
                out.show(&view, || format!("{name} is ready"));
                return Ok(0);
            }
            "queued" | "building" => tokio::time::sleep(Duration::from_secs(2)).await,
            _ => {
                if out.json {
                    out.json(&view);
                } else {
                    if let Some(log) = view["log"].as_str() {
                        eprintln!("{}", log.trim_end());
                    }
                    eprintln!("error: build {state}: {}", text(&view["error"]));
                }
                return Ok(1);
            }
        }
    }
}

async fn secrets(api: &Api, out: &Out, command: SecretsCommand) -> Result<i32> {
    let columns = [
        ("NAME", "name"),
        ("TYPE", "type"),
        ("HOSTS", "allowed_hosts"),
        ("ENV", "env"),
        ("TENANT", "tenant"),
        ("VERSION", "version"),
    ];
    match command {
        SecretsCommand::Set {
            name,
            kind,
            hosts,
            env,
            header,
            format,
            username,
            from_env,
            keep_value,
            tenant,
        } => {
            let value = if keep_value {
                None
            } else {
                Some(secret_value(from_env.as_deref())?)
            };
            let body = object([
                ("name", Some(json!(name))),
                ("type", kind.clone().map(Value::from)),
                ("value", value.map(Value::from)),
                ("allowed_hosts", (!hosts.is_empty()).then(|| json!(hosts))),
                ("env", env.map(Value::from)),
                ("header", header.map(Value::from)),
                ("format", format.map(Value::from)),
                ("username", username.map(Value::from)),
            ]);
            let query = tenant_query(tenant.as_deref());
            let path = format!("/secrets/{}{query}", seg(&name));
            let exists = match api.get(&path).await {
                Ok(_) => true,
                Err(error) if ApiError::is(&error, StatusCode::NOT_FOUND) => false,
                Err(error) => return Err(error),
            };
            let (secret, verb) = if exists {
                let request = api.request(Method::PATCH, &path).json(&body);
                (api.json(request).await?, "updated")
            } else {
                let mut create = body;
                if kind.is_none() {
                    create["type"] = json!("http_header");
                }
                (
                    api.post(&format!("/secrets{query}"), &create).await?,
                    "created",
                )
            };
            out.show(&secret, || {
                format!("{name} {verb} (version {})", text(&secret["version"]))
            });
        }
        SecretsCommand::Ls { tenant } => {
            let list = api
                .get(&format!("/secrets{}", tenant_query(tenant.as_deref())))
                .await?;
            let items = list["secrets"].as_array().cloned().unwrap_or_default();
            out.table(&list, &items, &columns);
        }
        SecretsCommand::Get { name, tenant } => {
            out.json(
                &api.get(&format!(
                    "/secrets/{}{}",
                    seg(&name),
                    tenant_query(tenant.as_deref())
                ))
                .await?,
            );
        }
        SecretsCommand::Rm { name, tenant } => {
            api.delete(&format!(
                "/secrets/{}{}",
                seg(&name),
                tenant_query(tenant.as_deref())
            ))
            .await?;
        }
    }
    Ok(0)
}

/// `NAME:/path` or `NAME:/path:ro`.
fn volume_mount(text: &str) -> Result<Value> {
    let (name, rest) = text
        .split_once(':')
        .with_context(|| format!("--volume {text:?}: use NAME:/path or NAME:/path:ro"))?;
    let (path, read_only) = match rest.strip_suffix(":ro") {
        Some(path) => (path, true),
        None => (rest.strip_suffix(":rw").unwrap_or(rest), false),
    };
    if name.is_empty() || !path.starts_with('/') {
        bail!("--volume {text:?}: use NAME:/path or NAME:/path:ro");
    }
    Ok(json!({ "volume": name, "path": path, "read_only": read_only }))
}

async fn volumes(api: &Api, out: &Out, command: VolumesCommand) -> Result<i32> {
    match command {
        VolumesCommand::Create { name, size, tenant } => {
            let body = object([
                ("name", Some(json!(name))),
                ("size_gib", size.map(Value::from)),
                ("tenant", tenant.map(Value::from)),
            ]);
            let volume = api.post("/volumes", &body).await?;
            out.show(&volume, || {
                format!("{name} created ({} GiB)", text(&volume["size_gib"]))
            });
        }
        VolumesCommand::Ls { tenant } => {
            let list = api
                .get(&format!("/volumes{}", tenant_query(tenant.as_deref())))
                .await?;
            let items: Vec<Value> = list["volumes"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .map(|mut v| {
                    let users: Vec<String> = v["mounts"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .map(|m| text(&m["sandbox"]))
                        .collect();
                    v["used_by"] = json!(if users.is_empty() {
                        "-".to_owned()
                    } else {
                        users.join(",")
                    });
                    v
                })
                .collect();
            out.table(
                &list,
                &items,
                &[
                    ("NAME", "name"),
                    ("SIZE_GIB", "size_gib"),
                    ("BACKEND", "backend"),
                    ("NODE", "node"),
                    ("USED_BY", "used_by"),
                    ("TENANT", "tenant"),
                ],
            );
        }
        VolumesCommand::Get { name, tenant } => {
            out.json(
                &api.get(&format!(
                    "/volumes/{}{}",
                    seg(&name),
                    tenant_query(tenant.as_deref())
                ))
                .await?,
            );
        }
        VolumesCommand::Rm { name, tenant } => {
            api.delete(&format!(
                "/volumes/{}{}",
                seg(&name),
                tenant_query(tenant.as_deref())
            ))
            .await?;
        }
    }
    Ok(0)
}

/// From an environment variable, a hidden prompt, or all of stdin. Never
/// from the command line, where `ps` and shell history would show it.
fn secret_value(from_env: Option<&str>) -> Result<String> {
    let value = if let Some(var) = from_env {
        std::env::var(var).with_context(|| format!("environment variable {var} is not set"))?
    } else if std::io::stdin().is_terminal() {
        rpassword::prompt_password("Secret value: ")?
    } else {
        let mut value = String::new();
        std::io::stdin().read_to_string(&mut value)?;
        value.trim_end_matches(['\r', '\n']).to_owned()
    };
    anyhow::ensure!(!value.is_empty(), "the secret value is empty");
    Ok(value)
}

fn quotas(items: &[String]) -> Result<Option<Value>> {
    if items.is_empty() {
        return Ok(None);
    }
    let mut quotas = Map::new();
    for (name, value) in pairs(items, "--quota")? {
        let value = if value == "none" {
            Value::Null
        } else {
            json!(
                value
                    .parse::<u64>()
                    .with_context(|| format!("quota {name} must be a number or none"))?
            )
        };
        quotas.insert(name, value);
    }
    Ok(Some(Value::Object(quotas)))
}

async fn tenants(api: &Api, out: &Out, command: TenantsCommand) -> Result<i32> {
    match command {
        TenantsCommand::Create {
            id,
            name,
            quotas: items,
            egress: policy,
        } => {
            let body = object([
                ("id", Some(json!(id))),
                ("name", name.map(Value::from)),
                ("quotas", quotas(&items)?),
                ("egress", egress(policy)),
            ]);
            let tenant = api.post("/tenants", &body).await?;
            out.show(&tenant, || text(&tenant["id"]));
        }
        TenantsCommand::Ls => {
            let list = api.get("/tenants").await?;
            let items = list["tenants"].as_array().cloned().unwrap_or_default();
            out.table(
                &list,
                &items,
                &[("ID", "id"), ("NAME", "name"), ("CREATED", "created_at")],
            );
        }
        TenantsCommand::Get { id } => {
            out.json(&api.get(&format!("/tenants/{}", seg(&id))).await?);
        }
        TenantsCommand::Set {
            id,
            name,
            quotas: items,
            egress: policy,
        } => {
            let body = object([
                ("name", name.map(Value::from)),
                ("quotas", quotas(&items)?),
                ("egress", egress(policy)),
            ]);
            anyhow::ensure!(
                body.as_object().is_some_and(|b| !b.is_empty()),
                "nothing to change: give --name, --quota or an egress option"
            );
            let request = api
                .request(Method::PATCH, &format!("/tenants/{}", seg(&id)))
                .json(&body);
            let tenant = api.json(request).await?;
            out.show(&tenant, || format!("{id} updated"));
        }
        TenantsCommand::Rm { id } => {
            api.delete(&format!("/tenants/{}", seg(&id))).await?;
        }
    }
    Ok(0)
}

async fn keys(api: &Api, out: &Out, command: KeysCommand) -> Result<i32> {
    match command {
        KeysCommand::Create {
            tenant,
            name,
            scopes,
        } => {
            let body = object([
                ("tenant", tenant.map(Value::from)),
                ("name", name.map(Value::from)),
                ("scopes", (!scopes.is_empty()).then(|| json!(scopes))),
            ]);
            let key = api.post("/keys", &body).await?;
            if out.json {
                out.json(&key);
            } else {
                println!("{}", text(&key["key"]));
                eprintln!(
                    "Key {} created. Save it now: Spawnbox does not show it again.",
                    text(&key["id"])
                );
            }
        }
        KeysCommand::Ls => {
            let list = api.get("/keys").await?;
            let items = list["keys"].as_array().cloned().unwrap_or_default();
            out.table(
                &list,
                &items,
                &[
                    ("ID", "id"),
                    ("NAME", "name"),
                    ("TENANT", "tenant"),
                    ("SCOPES", "scopes"),
                    ("CREATED", "created_at"),
                    ("REVOKED", "revoked_at"),
                ],
            );
        }
        KeysCommand::Rm { id } => {
            api.delete(&format!("/keys/{}", seg(&id))).await?;
        }
    }
    Ok(0)
}

fn event_line(event: &Value) -> String {
    let attrs = match &event["attrs"] {
        Value::Object(map) if map.is_empty() => String::new(),
        Value::Null => String::new(),
        attrs => attrs.to_string(),
    };
    format!(
        "{}  {:<18}  {:<22}  {}  {}",
        text(&event["ts"]),
        text(&event["type"]),
        text(&event["sandbox"]),
        text(&event["step_id"]),
        attrs
    )
    .trim_end()
    .to_owned()
}

async fn events(api: &Api, out: &Out, args: EventsArgs) -> Result<i32> {
    let path = match &args.id {
        Some(id) => format!("/sandboxes/{}/events", seg(id)),
        None => "/events".to_owned(),
    };
    let mut query: Vec<(&str, String)> = Vec::new();
    query.extend(args.tenant.map(|v| ("tenant", v)));
    query.extend(args.kind.map(|v| ("type", v)));
    query.extend(args.step_id.map(|v| ("step_id", v)));
    query.extend(args.since.map(|v| ("since", v)));
    query.extend(args.until.map(|v| ("until", v)));
    if args.follow {
        query.push(("follow", "true".to_owned()));
        let request = api.request(Method::GET, &path).query(&query);
        let mut stdout = std::io::stdout();
        api.events(request, |event| {
            let value: Value = serde_json::from_str(&event.data).unwrap_or_default();
            let line = if out.json {
                value.to_string()
            } else {
                event_line(&value)
            };
            writeln!(stdout, "{line}")?;
            stdout.flush()?;
            Ok(None::<()>)
        })
        .await?;
        bail!("the event stream ended");
    }
    query.push(("limit", args.limit.unwrap_or(100).to_string()));
    let page = api
        .json(api.request(Method::GET, &path).query(&query))
        .await?;
    if out.json {
        out.json(&page);
    } else {
        for event in page["events"].as_array().into_iter().flatten() {
            println!("{}", event_line(event));
        }
        if page["has_more"] == true {
            eprintln!("More events exist. Use --since or --limit to see them.");
        }
    }
    Ok(0)
}

async fn usage(
    api: &Api,
    out: &Out,
    tenant: Option<String>,
    from: Option<String>,
    to: Option<String>,
    by_sandbox: bool,
) -> Result<i32> {
    let mut query: Vec<(&str, String)> = Vec::new();
    query.extend(tenant.map(|v| ("tenant", v)));
    query.extend(from.map(|v| ("from", v)));
    query.extend(to.map(|v| ("to", v)));
    if by_sandbox {
        query.push(("group_by", "sandbox".to_owned()));
    }
    let report = api
        .json(api.request(Method::GET, "/usage").query(&query))
        .await?;
    let rows = report["usage"].as_array().cloned().unwrap_or_default();
    let mut columns = vec![("HOUR", "hour"), ("TENANT", "tenant")];
    if by_sandbox {
        columns.push(("SANDBOX", "sandbox"));
    }
    columns.extend([
        ("VCPU_S", "vcpu_s"),
        ("MEM_GIB_S", "mem_gib_s"),
        ("DISK_GIB_H", "disk_gib_h"),
        ("EGRESS_BYTES", "egress_bytes"),
    ]);
    out.table(&report, &rows, &columns);
    if !out.json {
        let total = &report["total"];
        println!(
            "\nTotal {} to {}: vcpu_s {}, mem_gib_s {}, disk_gib_h {}, egress_bytes {}",
            text(&report["from"]),
            text(&report["to"]),
            text(&total["vcpu_s"]),
            text(&total["mem_gib_s"]),
            text(&total["disk_gib_h"]),
            text(&total["egress_bytes"]),
        );
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_arguments_only_when_needed() {
        let args = |items: &[&str]| items.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert_eq!(shell_line(&args(&["ls -la | wc -l"])), "ls -la | wc -l");
        assert_eq!(
            shell_line(&args(&["ls", "my dir", "it's", "a=b", ""])),
            r#"ls 'my dir' 'it'\''s' a=b ''"#
        );
    }

    #[test]
    fn parses_volume_mounts() {
        assert_eq!(
            volume_mount("data:/data").unwrap(),
            json!({ "volume": "data", "path": "/data", "read_only": false })
        );
        assert_eq!(
            volume_mount("data:/mnt/in:ro").unwrap(),
            json!({ "volume": "data", "path": "/mnt/in", "read_only": true })
        );
        assert!(volume_mount("data").is_err());
        assert!(volume_mount("data:rel").is_err());
        assert!(volume_mount(":/data").is_err());
    }

    #[test]
    fn builds_egress_and_quota_bodies() {
        let policy = |egress: Option<&str>, allow: &[&str]| EgressArgs {
            egress: egress.map(str::to_owned),
            allow: allow.iter().map(|s| (*s).to_owned()).collect(),
            deny: Vec::new(),
        };
        assert_eq!(egress(policy(None, &[])), None);
        assert_eq!(
            egress(policy(None, &["github.com"])).unwrap()["mode"],
            "allowlist"
        );
        assert_eq!(
            egress(policy(Some("deny_all"), &[])).unwrap()["mode"],
            "deny_all"
        );
        let body = quotas(&[
            "running_sandboxes=5".into(),
            "monthly_egress_bytes=none".into(),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(
            body,
            json!({"running_sandboxes": 5, "monthly_egress_bytes": null})
        );
        assert!(quotas(&["running_sandboxes=lots".into()]).is_err());
    }

    #[test]
    fn reads_services_from_flags_and_a_file() {
        let services = service_list(
            &[r#"{"name":"web","command":["srv"]}"#.into()],
            Some(r#"[{"name":"job","command":["work"]}]"#),
        )
        .unwrap();
        assert_eq!(services.len(), 2);
        assert_eq!(services[1]["name"], "job");
        assert!(service_list(&["web".into()], None).is_err());
        assert!(service_list(&["[]".into()], None).is_err());
        assert!(service_list(&[], Some(r#"{"name":"web"}"#)).is_err());
    }

    #[test]
    fn renders_tables_with_nested_fields() {
        let item = json!({"id": "a", "build": {"state": "ready"}, "hosts": ["x", "y"], "n": null});
        assert_eq!(cell(&item, "build.state"), "ready");
        assert_eq!(cell(&item, "hosts"), "x,y");
        assert_eq!(cell(&item, "n"), "-");
        let table = render_table(
            &["ID".into(), "STATE".into()],
            &[vec!["sbx_1".into(), "running".into()]],
        );
        assert_eq!(table, "ID     STATE\nsbx_1  running\n");
    }
}
