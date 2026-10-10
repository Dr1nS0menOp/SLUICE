//! Command-line arguments.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// Shrink SIEM ingest without changing a single detection.
#[derive(Debug, Parser)]
#[command(name = "sluice", version, about)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Run the autopilot on generated sample data with example rules.
    Demo(DemoArgs),
    /// Run the autopilot on your own sample and rules.
    Analyze(AnalyzeArgs),
    /// List the built-in community recipes, print their JSON Schema, or export them to edit.
    Recipes(RecipesArgs),
    /// Inspect detection rules as Sluice understands them.
    Rules(RulesArgs),
    /// Run the control plane and Vector live: shadow, promote, verify, roll back.
    Up(UpArgs),
    /// Show the live control plane's status.
    Status(StatusArgs),
    /// Print archived events as NDJSON (full fidelity, before any reduction).
    Search(SearchArgs),
    /// Send archived events to an HTTP endpoint, such as a Vector `http_server` source in front
    /// of a SIEM.
    Replay(ReplayArgs),
    /// Print a destination for the `sluice up` configuration: the Vector sink for a SIEM and
    /// what else to set up.
    Connect(ConnectArgs),
    /// Serve MCP on stdin/stdout, so an AI assistant can ask what was cut, why, and whether it
    /// still holds (for example `claude mcp add sluice -- sluice mcp --archive DIR`).
    Mcp(McpArgs),
}

#[derive(Debug, Args)]
pub(crate) struct McpArgs {
    /// Address of the control plane (`sluice up`).
    #[arg(long, default_value = "127.0.0.1:8686")]
    pub(crate) listen: String,
    /// The archive directory, to offer archive search.
    #[arg(long)]
    pub(crate) archive: Option<PathBuf>,
    /// Also offer the `replay` tool, which sends archived events to a destination.
    #[arg(long, requires = "archive")]
    pub(crate) allow_replay: bool,
    /// Serve MCP over HTTP at `http://ADDRESS/mcp` instead of stdio. Clients must send
    /// `Authorization: Bearer $SLUICE_MCP_TOKEN` (at least 32 characters).
    #[arg(long, value_name = "ADDRESS")]
    pub(crate) http: Option<std::net::SocketAddr>,
    /// A host name clients use to reach the HTTP server, besides localhost. Repeat for several.
    #[arg(long = "allowed-host", requires = "http")]
    pub(crate) allowed_hosts: Vec<String>,
}

#[derive(Debug, Args)]
pub(crate) struct ConnectArgs {
    /// The SIEM or platform.
    pub(crate) target: ConnectTarget,
    /// Its endpoint URL (for Wazuh: the file the manager or agent reads). Defaults to a
    /// placeholder to replace.
    #[arg(long)]
    pub(crate) endpoint: Option<String>,
    /// The destination's name in the configuration (default: the target's name).
    #[arg(long)]
    pub(crate) name: Option<String>,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub(crate) enum ConnectTarget {
    Splunk,
    Elastic,
    Sentinel,
    Chronicle,
    Wazuh,
    Http,
}

#[derive(Debug, Args)]
pub(crate) struct RulesArgs {
    #[command(subcommand)]
    pub(crate) command: RulesCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum RulesCommand {
    /// Print, as JSON, what each rule needs: its log source, the fields it reads (`unknown` when
    /// it may read any), whether it matches raw text, and whether it is stateful. Sluice never
    /// removes what these say.
    Requirements {
        /// Directory of Sigma rules (`*.yml`, `*.yaml`), searched recursively.
        #[arg(long)]
        rules: Option<PathBuf>,
        /// Directory of Wazuh rule files (`*.xml`), searched recursively.
        #[arg(long)]
        wazuh_rules: Option<PathBuf>,
        /// Directory of Wazuh decoder files (`*.xml`), to bound rules by `<decoded_as>`.
        #[arg(long, requires = "wazuh_rules")]
        wazuh_decoders: Option<PathBuf>,
    },
}

#[derive(Debug, Args)]
pub(crate) struct RecipesArgs {
    #[command(subcommand)]
    pub(crate) command: Option<RecipesCommand>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum RecipesCommand {
    /// Print the JSON Schema of a recipe file.
    Schema,
    /// Write the built-in recipes and their schema to a new directory. Pass it to
    /// `--recipes` afterwards: an edited recipe replaces the built-in one with the same id.
    Export {
        /// The directory to create.
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Debug, Args)]
pub(crate) struct SelectArgs {
    /// The archive directory (`archive_dir` in the `sluice up` configuration).
    #[arg(long)]
    pub(crate) archive: PathBuf,
    /// Only events of this source. Repeat for several.
    #[arg(long = "source")]
    pub(crate) sources: Vec<String>,
    /// Events Vector received at or after this time: RFC 3339 or `YYYY-MM-DD` (UTC midnight).
    #[arg(long)]
    pub(crate) from: Option<String>,
    /// Events Vector received before this time: RFC 3339 or `YYYY-MM-DD` (UTC midnight).
    #[arg(long)]
    pub(crate) to: Option<String>,
    /// A condition every event must meet: `field=value`, `field!=value` or `field~text`
    /// (contains, ignoring case). Repeat for several.
    #[arg(long = "where")]
    pub(crate) conditions: Vec<String>,
}

#[derive(Debug, Args)]
pub(crate) struct SearchArgs {
    #[command(flatten)]
    pub(crate) select: SelectArgs,
    /// Stop after this many events.
    #[arg(long)]
    pub(crate) limit: Option<u64>,
    /// Print only the number of matching events.
    #[arg(long)]
    pub(crate) count: bool,
}

#[derive(Debug, Args)]
pub(crate) struct ReplayArgs {
    #[command(flatten)]
    pub(crate) select: SelectArgs,
    /// Endpoint that receives the events as newline-delimited JSON.
    #[arg(long)]
    pub(crate) url: String,
    /// Events per request.
    #[arg(long, default_value_t = 500, value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..=100_000))]
    pub(crate) batch: usize,
}

#[derive(Debug, Args)]
pub(crate) struct UpArgs {
    /// The `sluice up` configuration (sources with their Vector sources, destinations, paths).
    #[arg(long)]
    pub(crate) config: PathBuf,
    /// Directory of Sigma rules (`*.yml`, `*.yaml`), searched recursively.
    #[arg(long)]
    pub(crate) rules: Option<PathBuf>,
    /// Directory of Wazuh rule files (`*.xml`), searched recursively.
    #[arg(long)]
    pub(crate) wazuh_rules: Option<PathBuf>,
    /// Directory of Wazuh decoder files (`*.xml`), to bound rules by `<decoded_as>`
    /// (for example a copy of `/var/ossec/ruleset/decoders` and `/var/ossec/etc/decoders`).
    #[arg(long, requires = "wazuh_rules")]
    pub(crate) wazuh_decoders: Option<PathBuf>,
    /// Feed synthetic traffic into the configured `http_server` sources (for trying it out).
    #[arg(long)]
    pub(crate) demo_traffic: bool,
    /// Check the configuration and rules and print the Vector configuration `up` would start
    /// with, without starting anything (pipe it to `vector validate`).
    #[arg(long, conflicts_with = "demo_traffic")]
    pub(crate) check: bool,
}

#[derive(Debug, Args)]
pub(crate) struct StatusArgs {
    /// Address of the control plane.
    #[arg(long, default_value = "127.0.0.1:8686")]
    pub(crate) listen: String,
    /// The rule profile to show, such as `sigma` or `sigma+wazuh` (default: the first).
    #[arg(long)]
    pub(crate) profile: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct DemoArgs {
    /// Directory for the sample, `vector.yaml` and `report.html`.
    #[arg(long, default_value = "out")]
    pub(crate) out: PathBuf,
    /// Sample volume relative to the default hour of traffic (100 = about 80 000 events).
    #[arg(long, default_value_t = 25)]
    pub(crate) scale: u64,
    /// Seed for the generated sample.
    #[arg(long, default_value_t = 1)]
    pub(crate) seed: u64,
    #[command(flatten)]
    pub(crate) ai: AiArgs,
}

#[derive(Debug, Args)]
pub(crate) struct AnalyzeArgs {
    /// Directory with one `<source-id>.ndjson` file per source.
    #[arg(long)]
    pub(crate) input: PathBuf,
    /// Sources file (YAML) describing each source's log source and format.
    #[arg(long)]
    pub(crate) sources: PathBuf,
    /// Directory of Sigma rules (`*.yml`, `*.yaml`), searched recursively.
    #[arg(long)]
    pub(crate) rules: Option<PathBuf>,
    /// Directory of Wazuh rule files (`*.xml`), searched recursively.
    #[arg(long)]
    pub(crate) wazuh_rules: Option<PathBuf>,
    /// Directory of Wazuh decoder files (`*.xml`), to bound rules by `<decoded_as>`
    /// (for example a copy of `/var/ossec/ruleset/decoders` and `/var/ossec/etc/decoders`).
    #[arg(long, requires = "wazuh_rules")]
    pub(crate) wazuh_decoders: Option<PathBuf>,
    /// Wazuh manager API (for example `https://wazuh:55000`) to spot-check reductions with its
    /// real decoders and rules through `logtest`. The password is read from
    /// `WAZUH_API_PASSWORD`.
    #[arg(long, requires = "wazuh_user")]
    pub(crate) wazuh_api: Option<String>,
    /// Wazuh API user (needs the `logtest:run` permission).
    #[arg(long)]
    pub(crate) wazuh_user: Option<String>,
    /// Accept the Wazuh API's self-signed certificate. Only on a trusted network path.
    #[arg(long)]
    pub(crate) wazuh_insecure: bool,
    /// Directory of extra recipes, used next to the built-in ones.
    #[arg(long)]
    pub(crate) recipes: Option<PathBuf>,
    /// Directory for `vector.yaml` and `report.html`.
    #[arg(long, default_value = "out")]
    pub(crate) out: PathBuf,
    #[command(flatten)]
    pub(crate) ai: AiArgs,
}

#[derive(Debug, Args)]
pub(crate) struct AiArgs {
    /// Model for frequent templates no recipe covers: `none`, `anthropic[:MODEL]`,
    /// `ollama:MODEL`, `lmstudio:MODEL` or `openai:BASE_URL#MODEL`. Local models keep samples
    /// on this machine; samples sent anywhere are redacted first.
    #[arg(long, default_value = "none")]
    pub(crate) llm: String,
    /// Directory caching model answers per template (default: `~/.cache/sluice/ai`).
    #[arg(long)]
    pub(crate) llm_cache: Option<PathBuf>,
}
