mod api;
mod cmd;
mod config;
mod devcontainer;
mod doctor;
mod files;
mod pty;
mod sse;

use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};

const AFTER_HELP: &str = "\
The server URL and API key come from --url and --key, then from
SPAWNBOX_URL and SPAWNBOX_API_KEY, then from `spawnbox login`.
The default URL is http://127.0.0.1:8080.";

/// Spawnbox - open-source, self-hosted sandboxes
#[derive(Parser)]
#[command(name = "spawnbox", version, after_help = AFTER_HELP)]
pub struct Cli {
    /// Server URL, for example http://127.0.0.1:8080
    #[arg(long, env = "SPAWNBOX_URL", global = true)]
    pub url: Option<String>,
    /// API key
    #[arg(long, env = "SPAWNBOX_API_KEY", global = true, hide_env_values = true)]
    pub key: Option<String>,
    /// Step ID for the events of this call (X-Spawnbox-Step)
    #[arg(long, env = "SPAWNBOX_STEP", global = true)]
    pub step: Option<String>,
    /// Print the server's JSON response
    #[arg(long, global = true)]
    pub json: bool,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Save the server URL and API key for later commands
    Login,
    /// Create a sandbox and print its ID
    Create(CreateArgs),
    /// List sandboxes
    #[command(alias = "list")]
    Ls {
        #[arg(long)]
        tenant: Option<String>,
        /// Only this state, for example running or paused
        #[arg(long)]
        state: Option<String>,
    },
    /// Show one sandbox
    Get { id: String },
    /// Delete sandboxes
    #[command(alias = "rm")]
    Kill {
        #[arg(required = true)]
        ids: Vec<String>,
    },
    /// Pause sandboxes: save memory and disk, release CPU and memory
    Pause {
        #[arg(required = true)]
        ids: Vec<String>,
    },
    /// Resume paused sandboxes
    Resume {
        #[arg(required = true)]
        ids: Vec<String>,
    },
    /// Start copies of a running sandbox, with its memory and disk; print their IDs
    Fork {
        id: String,
        #[arg(long, default_value_t = 1)]
        count: u32,
    },
    /// Save a running sandbox as a new template
    Snapshot {
        id: String,
        /// The new template's name
        #[arg(long)]
        name: String,
    },
    /// Run a command and stream its output; exits with its exit code
    Exec(ExecArgs),
    /// Open an interactive terminal
    Sh {
        id: String,
        #[arg(long)]
        user: Option<String>,
        #[arg(long)]
        cwd: Option<String>,
        /// Run this instead of a login shell
        #[arg(long)]
        cmd: Option<String>,
    },
    /// Copy files: `cp ./src ID:/workspace/src`, `cp ID:/tmp/out.txt .`, `-` is stdin/stdout
    Cp {
        from: String,
        to: String,
        #[arg(long)]
        user: Option<String>,
    },
    /// Clone a Git repository into a sandbox
    Clone {
        id: String,
        repo: String,
        /// Default: /workspace/<repo>
        #[arg(long)]
        path: Option<String>,
        #[arg(long)]
        branch: Option<String>,
        #[arg(long)]
        depth: Option<u32>,
        #[arg(long)]
        user: Option<String>,
    },
    /// Preview URLs for ports in a sandbox
    #[command(subcommand)]
    Ports(PortsCommand),
    /// Services: programs Spawnbox keeps running in a sandbox. With an ID, list them
    #[command(alias = "service", args_conflicts_with_subcommands = true)]
    Services(ServicesArgs),
    /// Templates: start images with your packages
    #[command(subcommand, alias = "template")]
    Templates(TemplatesCommand),
    /// Secrets that the egress proxy adds to HTTPS requests
    #[command(subcommand, alias = "secret")]
    Secrets(SecretsCommand),
    /// Volumes: disks that keep their files after sandboxes end
    #[command(subcommand, alias = "volume")]
    Volumes(VolumesCommand),
    /// Tenants (org key only)
    #[command(subcommand, alias = "tenant")]
    Tenants(TenantsCommand),
    /// API keys (org key only)
    #[command(subcommand, alias = "key")]
    Keys(KeysCommand),
    /// Show events; with an ID, only that sandbox's
    Events(EventsArgs),
    /// Show usage for a time range (default: this month)
    Usage {
        #[arg(long)]
        tenant: Option<String>,
        /// RFC 3339 time, for example 2026-11-01T00:00:00Z
        #[arg(long)]
        from: Option<String>,
        #[arg(long)]
        to: Option<String>,
        /// One row per sandbox instead of per tenant
        #[arg(long)]
        by_sandbox: bool,
    },
    /// Check this host's prerequisites for running Spawnbox (operators)
    Doctor,
}

#[derive(Args)]
pub struct CreateArgs {
    #[arg(long)]
    pub template: Option<String>,
    #[arg(long)]
    pub tenant: Option<String>,
    /// Seconds before the sandbox is deleted
    #[arg(long)]
    pub timeout: Option<u64>,
    /// Seconds without requests before the sandbox pauses (0: never)
    #[arg(long)]
    pub idle_pause: Option<u64>,
    /// Keep the sandbox until it is deleted; it never expires
    #[arg(long, conflicts_with = "timeout")]
    pub persistent: bool,
    /// KEY=VALUE, can repeat
    #[arg(long = "env", short = 'e', value_name = "KEY=VALUE")]
    pub env: Vec<String>,
    /// KEY=VALUE, can repeat
    #[arg(long = "label", value_name = "KEY=VALUE")]
    pub labels: Vec<String>,
    /// Secret name, can repeat
    #[arg(long = "secret", value_name = "NAME")]
    pub secrets: Vec<String>,
    /// Mount a volume: NAME:/path, or NAME:/path:ro to read only. Can repeat
    #[arg(long = "volume", short = 'v', value_name = "NAME:PATH[:ro]")]
    pub volumes: Vec<String>,
    /// A service as JSON, for example '{"name":"web","command":["python3","-m","http.server"],"port":8000}'. Can repeat
    #[arg(long = "service", value_name = "JSON")]
    pub services: Vec<String>,
    /// A JSON file with a list of services
    #[arg(long, value_name = "PATH")]
    pub service_file: Option<std::path::PathBuf>,
    #[command(flatten)]
    pub egress: EgressArgs,
}

#[derive(Args)]
pub struct EgressArgs {
    /// allow_all, allowlist or deny_all
    #[arg(long)]
    pub egress: Option<String>,
    /// Host or *.domain the sandbox can reach; sets allowlist mode
    #[arg(long = "allow", value_name = "HOST")]
    pub allow: Vec<String>,
    /// Host or *.domain to block
    #[arg(long = "deny", value_name = "HOST")]
    pub deny: Vec<String>,
}

#[derive(Args)]
pub struct ExecArgs {
    pub id: String,
    #[arg(long)]
    pub cwd: Option<String>,
    #[arg(long)]
    pub user: Option<String>,
    /// KEY=VALUE, can repeat
    #[arg(long = "env", short = 'e', value_name = "KEY=VALUE")]
    pub env: Vec<String>,
    /// Seconds before the command is stopped
    #[arg(long)]
    pub timeout: Option<u32>,
    /// Send this program's stdin to the command (maximum 1 MiB)
    #[arg(long, short = 'i')]
    pub stdin: bool,
    /// The command. One argument runs as a shell line; more are quoted
    #[arg(last = true, required = true)]
    pub cmd: Vec<String>,
}

#[derive(Subcommand)]
pub enum PortsCommand {
    /// Publish a port and print its URL
    Publish {
        id: String,
        port: u16,
        /// token (default), public or private
        #[arg(long)]
        access: Option<String>,
        /// Seconds a token URL works
        #[arg(long)]
        ttl: Option<u64>,
    },
    /// List published ports
    Ls { id: String },
    /// Remove a published port
    Rm { id: String, port: u16 },
}

#[derive(Args)]
pub struct ServicesArgs {
    pub id: Option<String>,
    #[command(subcommand)]
    pub command: Option<ServicesCommand>,
}

#[derive(Subcommand)]
pub enum ServicesCommand {
    /// List a sandbox's services and their state
    Ls { id: String },
    /// Stop a service and start it again
    Restart { id: String, name: String },
    /// Print a service's recent output
    Logs {
        id: String,
        name: String,
        /// Keep the connection open and print new output
        #[arg(long, short = 'f')]
        follow: bool,
    },
}

#[derive(Subcommand)]
pub enum TemplatesCommand {
    /// Create or change a template from a JSON file and build it
    Build {
        /// JSON with name, base, setup, warmup, env and resources
        file: std::path::PathBuf,
        /// The file is an image-based devcontainer.json
        #[arg(long)]
        devcontainer: bool,
        /// Template name for --devcontainer (default: its "name")
        #[arg(long, requires = "devcontainer")]
        name: Option<String>,
        #[arg(long)]
        tenant: Option<String>,
        /// Return when the build starts
        #[arg(long)]
        no_wait: bool,
    },
    Ls {
        #[arg(long)]
        tenant: Option<String>,
    },
    Get {
        name: String,
        #[arg(long)]
        tenant: Option<String>,
    },
    /// Print the end of the latest build log
    Logs {
        name: String,
        #[arg(long)]
        tenant: Option<String>,
    },
    Rm {
        name: String,
        #[arg(long)]
        tenant: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum SecretsCommand {
    /// Create or change a secret. The value comes from stdin, a prompt or --from-env
    Set {
        name: String,
        /// http_header (default) or git_https
        #[arg(long = "type")]
        kind: Option<String>,
        /// Comma-separated hosts that get the value
        #[arg(long, value_delimiter = ',')]
        hosts: Vec<String>,
        /// Environment variable that holds the placeholder in the sandbox
        #[arg(long)]
        env: Option<String>,
        #[arg(long)]
        header: Option<String>,
        /// For example "Bearer {value}"
        #[arg(long)]
        format: Option<String>,
        #[arg(long)]
        username: Option<String>,
        /// Read the value from this environment variable
        #[arg(long, value_name = "VAR")]
        from_env: Option<String>,
        /// Keep the current value; change only the other fields
        #[arg(long, conflicts_with = "from_env")]
        keep_value: bool,
        #[arg(long)]
        tenant: Option<String>,
    },
    Ls {
        #[arg(long)]
        tenant: Option<String>,
    },
    Get {
        name: String,
        #[arg(long)]
        tenant: Option<String>,
    },
    Rm {
        name: String,
        #[arg(long)]
        tenant: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum VolumesCommand {
    /// Create a volume. Its disk is made when a sandbox first mounts it
    Create {
        name: String,
        /// Size in GiB (default 10)
        #[arg(long)]
        size: Option<u32>,
        #[arg(long)]
        tenant: Option<String>,
    },
    Ls {
        #[arg(long)]
        tenant: Option<String>,
    },
    Get {
        name: String,
        #[arg(long)]
        tenant: Option<String>,
    },
    /// Delete a volume and its files. No sandbox may have it mounted
    Rm {
        name: String,
        #[arg(long)]
        tenant: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum TenantsCommand {
    Create {
        id: String,
        #[arg(long)]
        name: Option<String>,
        /// NAME=VALUE, for example running_sandboxes=5; `none` removes a limit
        #[arg(long = "quota", value_name = "NAME=VALUE")]
        quotas: Vec<String>,
        #[command(flatten)]
        egress: EgressArgs,
    },
    Ls,
    /// Show a tenant with its current usage
    Get {
        id: String,
    },
    /// Change a tenant's name, quotas or egress policy
    Set {
        id: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long = "quota", value_name = "NAME=VALUE")]
        quotas: Vec<String>,
        #[command(flatten)]
        egress: EgressArgs,
    },
    Rm {
        id: String,
    },
}

#[derive(Subcommand)]
pub enum KeysCommand {
    /// Create a key. The key is shown only once
    Create {
        /// Make a tenant key; without it, an org key
        #[arg(long)]
        tenant: Option<String>,
        #[arg(long)]
        name: Option<String>,
        /// Scope, can repeat, for example sandboxes:read
        #[arg(long = "scope")]
        scopes: Vec<String>,
    },
    Ls,
    /// Revoke a key
    Rm {
        id: String,
    },
}

#[derive(Args)]
pub struct EventsArgs {
    pub id: Option<String>,
    #[arg(long)]
    pub tenant: Option<String>,
    /// Event type, for example exec.finished or exec.*
    #[arg(long = "type")]
    pub kind: Option<String>,
    /// Only events with this step ID
    #[arg(long)]
    pub step_id: Option<String>,
    #[arg(long)]
    pub since: Option<String>,
    #[arg(long)]
    pub until: Option<String>,
    /// Maximum number of events (default 100)
    #[arg(long)]
    pub limit: Option<u32>,
    /// Keep the connection open and print new events
    #[arg(long, short = 'f')]
    pub follow: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if matches!(cli.command, Command::Doctor) {
        return doctor::run();
    }
    let _ = rustls::crypto::ring::default_provider().install_default();
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("error: start: {error}");
            return ExitCode::FAILURE;
        }
    };
    let code = match runtime.block_on(cmd::run(cli)) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error:#}");
            1
        }
    };
    // Stdin reads run on a blocking thread that would hold up a normal exit.
    std::process::exit(code);
}
