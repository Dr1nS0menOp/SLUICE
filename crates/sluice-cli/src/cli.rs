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
    /// Print the Vector configuration for a collection agent on a host, which sends its events
    /// to `sluice up` shaped as the SIEM stores them.
    Agent(AgentArgs),
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
    /// Also offer the `operator_action` tool: hold, release, approve, keep fields and acknowledge
    /// rollbacks, audited by the control plane (ADR 0016).
    #[arg(long)]
    pub(crate) allow_actions: bool,
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
    /// Sentinel: sample records of a source (NDJSON, as forwarded) to derive a custom table
    /// `<TABLE>_CL` and its data collection rule from.
    #[arg(long, requires_all = ["table", "out"])]
    pub(crate) sample: Option<PathBuf>,
    /// Sentinel: the custom table's name, without `_CL`.
    #[arg(long, requires = "sample")]
    pub(crate) table: Option<String>,
    /// Sentinel: the field `TimeGenerated` is read from (default: the time of ingestion).
    #[arg(long, requires = "sample")]
    pub(crate) time_field: Option<String>,
    /// Sentinel: the workspace's resource ID, for the data collection rule.
    #[arg(long, requires = "out")]
    pub(crate) workspace: Option<String>,
    /// Sentinel: the Azure region of the workspace.
    #[arg(long, requires = "out", default_value = "westeurope")]
    pub(crate) location: String,
    /// Sentinel: records shaped as a standard table (`shape: sentinel_syslog`,
    /// `sentinel_common_security_log`, `sentinel_asim_network_session`, `sentinel_asim_dns` or `sentinel_asim_web_session`): write the data
    /// collection rule that stores them there.
    #[arg(long, value_enum, requires = "out", conflicts_with = "sample")]
    pub(crate) standard_table: Option<StandardTable>,
    /// Sentinel: directory to write the table and data collection rule JSON to.
    #[arg(long)]
    pub(crate) out: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct AgentArgs {
    /// The kind of host.
    pub(crate) platform: AgentPlatform,
    /// URL of the `http_server` source of `sluice up` that receives Security channel events,
    /// shaped as `SecurityEvent`.
    #[arg(long)]
    pub(crate) to: String,
    /// URL of the `http_server` source that receives every other channel, shaped as
    /// `WindowsEvent`. Required when reading channels other than Security.
    #[arg(long)]
    pub(crate) events_to: Option<String>,
    /// Event log channels to read. Repeat for several, such as `--channel Security --channel
    /// System`. Security needs Vector to run elevated or as a service.
    #[arg(long = "channel", default_values_t = ["Security".to_owned()])]
    pub(crate) channels: Vec<String>,
    /// Vector's data directory on the host (read checkpoints and the send buffer).
    #[arg(long, default_value = "C:/ProgramData/Vector/data")]
    pub(crate) data_dir: String,
    /// Also write the Sentinel data collection rule (JSON) that stores the records in
    /// `SecurityEvent`, for this workspace resource id.
    #[arg(long, value_name = "FILE", requires = "workspace")]
    pub(crate) dcr: Option<PathBuf>,
    /// The Log Analytics workspace resource id, for `--dcr`.
    #[arg(long)]
    pub(crate) workspace: Option<String>,
    /// The Azure region of the workspace, for `--dcr`.
    #[arg(long, default_value = "westeurope")]
    pub(crate) location: String,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub(crate) enum AgentPlatform {
    /// Windows Event Log, shaped as Microsoft Sentinel's `SecurityEvent`.
    Windows,
}

/// A standard Sentinel table Sluice can shape records for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum StandardTable {
    /// `Syslog`.
    Syslog,
    /// `CommonSecurityLog`.
    CommonSecurityLog,
    /// `ASimNetworkSessionLogs`.
    AsimNetworkSession,
    /// `ASimDnsActivityLogs`.
    AsimDns,
    /// `ASimWebSessionLogs`.
    AsimWebSession,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
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
        /// Directory of Microsoft Sentinel analytics rules (`*.yaml` with a KQL `query`),
        /// searched recursively, such as a clone of Azure/Azure-Sentinel.
        #[arg(long)]
        sentinel_rules: Option<PathBuf>,
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
    /// Directory of Microsoft Sentinel analytics rules (`*.yaml` with a KQL `query`), searched
    /// recursively, for destinations whose `sluice_rules` name `sentinel`.
    #[arg(long)]
    pub(crate) sentinel_rules: Option<PathBuf>,
    /// URL of a Kusto emulator (`scripts/kql-check.sh` starts one). The proof then runs the
    /// Sentinel rules themselves on full and forwarded records; without it, their requirements
    /// still constrain every cut, but the proof covers the other rule sets only.
    #[arg(long, requires = "sentinel_rules")]
    pub(crate) kusto: Option<String>,
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
