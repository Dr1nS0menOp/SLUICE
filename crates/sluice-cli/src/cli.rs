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
    Analyze(Box<AnalyzeArgs>),
    /// List the built-in community recipes, print their JSON Schema, or export them to edit.
    Recipes(RecipesArgs),
    /// Inspect detection rules as Sluice understands them.
    Rules(RulesArgs),
    /// Prove a generated Vector configuration on a sample, as it is: fails (exit 1) when the
    /// rules' alerts on what it forwards differ from their alerts on the full sample. For CI.
    Prove(ProveArgs),
    /// Write the Microsoft Sentinel tables and data collection rules a source needs: a custom
    /// table for JSON records, the rule of a standard table, or the table for summaries.
    Connect(ConnectArgs),
}

#[derive(Debug, Args)]
pub(crate) struct ConnectArgs {
    /// The SIEM: `sentinel`.
    pub(crate) target: ConnectTarget,
    /// Sentinel: sample records of a source (NDJSON, as the agent sends them) to derive a custom
    /// table `<TABLE>_CL` and its data collection rule from.
    #[arg(long, requires = "table")]
    pub(crate) sample: Option<PathBuf>,
    /// Sentinel: the custom table's name, without `_CL`.
    #[arg(long, requires = "sample")]
    pub(crate) table: Option<String>,
    /// Sentinel: the field `TimeGenerated` is read from (default: the time of ingestion).
    #[arg(long, requires = "sample")]
    pub(crate) time_field: Option<String>,
    /// Sentinel: also write the table summary records go to (`SluiceSummary_CL`), its data
    /// collection rule and the `SluiceCounts` function (ADR 0029).
    #[arg(long)]
    pub(crate) summary_table: bool,
    /// Sentinel: the workspace's resource ID, for the data collection rule.
    #[arg(long)]
    pub(crate) workspace: Option<String>,
    /// Sentinel: the Azure region of the workspace.
    #[arg(long, default_value = "westeurope")]
    pub(crate) location: String,
    /// Sentinel: records shaped as a standard table (`shape: sentinel_syslog`,
    /// `sentinel_common_security_log`, `sentinel_asim_network_session`, `sentinel_asim_dns` or `sentinel_asim_web_session`): write the data
    /// collection rule that stores them there.
    #[arg(long, value_enum, conflicts_with = "sample")]
    pub(crate) standard_table: Option<StandardTable>,
    /// Directory to write the tables and data collection rules to.
    #[arg(long)]
    pub(crate) out: PathBuf,
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
    /// Microsoft Sentinel.
    Sentinel,
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
    Requirements(RequirementsArgs),
    /// Read the rules a SIEM runs from its API (read-only) into a directory, with an
    /// `inventory.json` that marks them complete (ADR 0021). Fetching again replaces it.
    Fetch(FetchArgs),
}

#[derive(Debug, Args)]
pub(crate) struct RequirementsArgs {
    /// Directory of Sigma rules (`*.yml`, `*.yaml`), searched recursively.
    #[arg(long)]
    pub(crate) rules: Option<PathBuf>,
    /// Map the Sigma rules onto another field naming convention (`SCHEMA=PIPELINE`), as for
    /// `sluice analyze`, so the fields printed are the ones its cuts are checked against.
    #[arg(long, value_name = "SCHEMA=PIPELINE")]
    pub(crate) sigma_pipeline: Vec<String>,
    /// Directory of Wazuh rule files (`*.xml`), searched recursively.
    #[arg(long)]
    pub(crate) wazuh_rules: Option<PathBuf>,
    /// Directory of Wazuh decoder files (`*.xml`), to bound rules by `<decoded_as>`.
    #[arg(long, requires = "wazuh_rules")]
    pub(crate) wazuh_decoders: Option<PathBuf>,
    /// Directory of Microsoft Sentinel analytics rules (`*.yaml` with a KQL `query`), searched
    /// recursively, such as a clone of Azure/Azure-Sentinel.
    #[arg(long)]
    pub(crate) sentinel_rules: Option<PathBuf>,
    /// Directory of Elastic Security detection rules (Kibana's export, `*.ndjson` or `*.json`,
    /// or the prebuilt rules package), searched recursively.
    #[arg(long)]
    pub(crate) elastic_rules: Option<PathBuf>,
    /// Directory of Splunk configuration (`savedsearches.conf`, `macros.conf`, or the REST
    /// API's JSON answers), searched recursively.
    #[arg(long)]
    pub(crate) splunk_rules: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct FetchArgs {
    #[command(subcommand)]
    pub(crate) target: FetchTarget,
    /// The directory to write: new, empty, or an earlier fetch (which is replaced).
    #[arg(long, global = true)]
    pub(crate) out: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum FetchTarget {
    /// Microsoft Sentinel: enabled analytics rules, hunting queries and workspace functions.
    /// Credentials: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` (an app with
    /// Microsoft Sentinel Reader on the workspace). Then `--sentinel-rules OUT`.
    Sentinel {
        /// The workspace's resource id, `/subscriptions/…/workspaces/NAME`.
        #[arg(long)]
        workspace: String,
        /// Also read saved searches that are not hunting queries or functions.
        #[arg(long)]
        all_saved_searches: bool,
        /// Also read the distinct queries people ran in this many days (`LAQueryLogs`; needs
        /// query auditing on the workspace and Log Analytics Reader).
        #[arg(long, value_name = "DAYS", value_parser = clap::value_parser!(u32).range(1..=730))]
        query_log_days: Option<u32>,
    },
    /// Wazuh: the rule and decoder files the manager loads. The password is read from
    /// `WAZUH_API_PASSWORD` (a user with `rules:read` and `decoders:read`). Then
    /// `--wazuh-rules OUT/rules --wazuh-decoders OUT/decoders`.
    Wazuh {
        /// The manager API, such as `https://wazuh:55000`.
        #[arg(long)]
        api: String,
        /// The API user.
        #[arg(long)]
        user: String,
        /// Accept the API's self-signed certificate. Only on a trusted network path.
        #[arg(long)]
        insecure: bool,
    },
    /// Elastic Security: the detection rules of a Kibana space, enabled or not (only enabled
    /// ones count). Credentials: `KIBANA_API_KEY`, or `KIBANA_USER` and `KIBANA_PASSWORD` (a
    /// role that may read detection rules). Then `--elastic-rules OUT`.
    Elastic {
        /// Kibana, such as `https://kibana:5601`.
        #[arg(long)]
        kibana: String,
        /// The Kibana space; the default space without it.
        #[arg(long)]
        space: Option<String>,
    },
    /// Splunk: the saved searches and macros of every app the user sees, enabled or not (only
    /// scheduled, enabled ones count). Credentials: `SPLUNK_TOKEN` (an authentication token),
    /// or `SPLUNK_USER` and `SPLUNK_PASSWORD`. Then `--splunk-rules OUT`.
    Splunk {
        /// The management port, such as `https://splunk:8089`.
        #[arg(long)]
        api: String,
        /// Accept Splunk's self-signed certificate. Only on a trusted network path.
        #[arg(long)]
        insecure: bool,
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
    /// Copy recipes an AI advisor proposed and the proof kept (`sluice analyze --llm` writes
    /// them to `OUT/ai-recipes`) into a recipe repository, checked against the recipe book, for
    /// a pull request. Review each one first: its pattern and rationale come from your logs.
    Contribute {
        /// The recipes, such as `out/ai-recipes`.
        #[arg(long)]
        from: PathBuf,
        /// The recipe directory of a clone of the recipe repository.
        #[arg(long)]
        into: PathBuf,
    },
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
    /// An Elasticsearch, for `--elastic-native`.
    #[arg(long, value_name = "URL")]
    pub(crate) elasticsearch: Option<String>,
    /// Also prove and write Elasticsearch ingest pipelines, as `sluice analyze --elastic-native`.
    #[arg(long, requires = "elasticsearch")]
    pub(crate) elastic_native: bool,
    /// A command that runs Fluent Bit, for `--fluent-bit-native`.
    #[arg(long, value_name = "CMD")]
    pub(crate) fluent_bit: Option<PathBuf>,
    /// Also prove and write Fluent Bit Lua filters, as `sluice analyze --fluent-bit-native`.
    #[arg(long, requires = "fluent_bit")]
    pub(crate) fluent_bit_native: bool,
    /// A command that runs the OpenTelemetry Collector (contrib), for `--otel-native`.
    #[arg(long, value_name = "CMD")]
    pub(crate) otel_collector: Option<PathBuf>,
    /// Also prove and write OpenTelemetry Collector transform statements, as `sluice analyze
    /// --otel-native`.
    #[arg(long, requires = "otel_collector")]
    pub(crate) otel_native: bool,
    #[command(flatten)]
    pub(crate) ai: AiArgs,
}

#[derive(Debug, Args)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "each is a command-line switch of its own"
)]
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
    /// Map the Sigma rules onto another field naming convention, as the SIEM's own conversion
    /// does: `SCHEMA=PIPELINE`, such as `ecs=ecs_windows` (built in) or `ecs=my-pipeline.yml`
    /// (pySigma's format). Repeatable, one per convention.
    #[arg(long, value_name = "SCHEMA=PIPELINE")]
    pub(crate) sigma_pipeline: Vec<String>,
    /// Directory of Wazuh rule files (`*.xml`), searched recursively.
    #[arg(long)]
    pub(crate) wazuh_rules: Option<PathBuf>,
    /// Directory of Wazuh decoder files (`*.xml`), to bound rules by `<decoded_as>`
    /// (for example a copy of `/var/ossec/ruleset/decoders` and `/var/ossec/etc/decoders`).
    #[arg(long, requires = "wazuh_rules")]
    pub(crate) wazuh_decoders: Option<PathBuf>,
    /// Directory of Microsoft Sentinel analytics rules, hunting queries and functions, such as
    /// a `sluice rules fetch sentinel` directory. Their requirements constrain every cut.
    #[arg(long)]
    pub(crate) sentinel_rules: Option<PathBuf>,
    /// URL of a Kusto emulator: the proof then runs the Sentinel rules themselves on full and
    /// forwarded records of the sources named with `--sentinel-table`.
    #[arg(long, requires_all = ["sentinel_rules", "sentinel_table"])]
    pub(crate) kusto: Option<String>,
    /// The Sentinel table a source's sample records are stored in, as `SOURCE=TABLE` (such as
    /// `windows-security=SecurityEvent`). Repeatable.
    #[arg(long, value_name = "SOURCE=TABLE", requires = "kusto")]
    pub(crate) sentinel_table: Vec<String>,
    /// Directory of Elastic Security detection rules: Kibana's export (`_export` NDJSON or
    /// `_find` JSON) or Elastic's prebuilt rules package (ADR 0025). Their requirements
    /// constrain every cut.
    #[arg(long)]
    pub(crate) elastic_rules: Option<PathBuf>,
    /// Directory of Splunk saved searches and macros: `savedsearches.conf` and `macros.conf`,
    /// or the REST API's `saved/searches` and `admin/macros` JSON, with `props.conf` and
    /// `transforms.conf` for the fields Splunk derives (ADR 0026). Their requirements
    /// constrain every cut; no engine runs them in the proof.
    #[arg(long)]
    pub(crate) splunk_rules: Option<PathBuf>,
    /// Also prove, per `--sentinel-table` source, a data collection rule transformation that
    /// makes the plan's field removals in Sentinel's own ingestion, in the emulator (ADR 0013).
    /// Needs a sample read from the table, where empty and missing columns are the same.
    #[arg(long, requires = "sentinel_table")]
    pub(crate) sentinel_native: bool,
    /// The data collection rule (JSON, as Azure exports it) the records go through, for
    /// `--sentinel-native`: its stream's columns are what the
    /// transformation sees, and it runs after the data flow's own transformation. Sluice writes
    /// it back as `sentinel/dcr.json` with the proven transformations and an untransformed flow
    /// into an archive table per changed table (`sentinel/*.table.json`). Without it, nothing is
    /// written.
    #[arg(long, value_name = "FILE", requires = "sentinel_native")]
    pub(crate) sentinel_dcr: Option<PathBuf>,
    /// An Elasticsearch (`scripts/elastic-check.sh` starts one): the proof then runs the
    /// `--elastic-rules` EQL and ES|QL rules themselves on full and forwarded documents (ADR
    /// 0025), and `--elastic-native` proves its pipelines there.
    #[arg(long, value_name = "URL")]
    pub(crate) elasticsearch: Option<String>,
    /// Also write, per source, an Elasticsearch ingest pipeline (`elastic/SOURCE.pipeline.json`)
    /// that makes the plan's field removals in Elastic's own ingestion, after proving it in
    /// `--elasticsearch` (ADR 0024): it removes nothing Vector keeps, and the rules raise the
    /// same alerts. Needs documents as the index stores them.
    #[arg(long, requires = "elasticsearch")]
    pub(crate) elastic_native: bool,
    /// A command that runs Fluent Bit: the `fluent-bit` binary, or a wrapper that runs it in a
    /// container (`scripts/fluentbit-check.sh` writes one). It takes Fluent Bit's own arguments.
    #[arg(long, value_name = "CMD")]
    pub(crate) fluent_bit: Option<PathBuf>,
    /// Also write, per source, a Fluent Bit Lua filter (`fluent-bit/SOURCE.lua`) that makes the
    /// plan's field removals in the agent, after proving it in `--fluent-bit` (ADR 0027): it
    /// removes nothing Vector keeps, changes nothing else, and the rules raise the same alerts.
    /// Needs records as the agent reads them.
    #[arg(long, requires = "fluent_bit")]
    pub(crate) fluent_bit_native: bool,
    /// A command that runs the OpenTelemetry Collector with the `filelog` receiver, `transform`
    /// processor and `file` exporter (the contrib distribution, or a wrapper that runs it in a
    /// container: `scripts/otel-check.sh` writes one). It takes the collector's own arguments.
    #[arg(long, value_name = "CMD")]
    pub(crate) otel_collector: Option<PathBuf>,
    /// Also write `otel/processors.yaml`: per source, a `transform` processor whose OTTL
    /// statements make the plan's field removals in the collector, after proving them in
    /// `--otel-collector` (ADR 0028): they remove nothing Vector keeps, change nothing else,
    /// and the rules raise the same alerts. For records whose body is the parsed JSON.
    #[arg(long, requires = "otel_collector")]
    pub(crate) otel_native: bool,
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
    /// The rules given are every rule and query the SIEM runs. Only then are events summarized
    /// (L2, L3); otherwise Sluice makes lossless cuts only. Rules fetched with `sluice rules
    /// fetch` count as complete without it (ADR 0021).
    #[arg(long)]
    pub(crate) rules_complete: bool,
    /// Directory for `vector.yaml` and `report.html`.
    #[arg(long, default_value = "out")]
    pub(crate) out: PathBuf,
    #[command(flatten)]
    pub(crate) ai: AiArgs,
}

#[derive(Debug, Args)]
pub(crate) struct ProveArgs {
    /// The Vector configuration to prove: a `vector.yaml` from `sluice analyze`, as generated or
    /// as changed in review.
    #[arg(long)]
    pub(crate) config: PathBuf,
    /// Directory with one `<source-id>.ndjson` file per source, as the configuration's
    /// programs see them.
    #[arg(long)]
    pub(crate) input: PathBuf,
    /// Sources file (YAML), as for `sluice analyze`.
    #[arg(long)]
    pub(crate) sources: PathBuf,
    /// Directory of Sigma rules (`*.yml`, `*.yaml`), searched recursively.
    #[arg(long)]
    pub(crate) rules: Option<PathBuf>,
    /// Map the Sigma rules onto another field naming convention (`SCHEMA=PIPELINE`).
    #[arg(long, value_name = "SCHEMA=PIPELINE")]
    pub(crate) sigma_pipeline: Vec<String>,
    /// Directory of Sentinel rules and queries, run in the Kusto emulator (`--kusto`).
    #[arg(long)]
    pub(crate) sentinel_rules: Option<PathBuf>,
    /// URL of a Kusto emulator.
    #[arg(long, requires_all = ["sentinel_rules", "sentinel_table"])]
    pub(crate) kusto: Option<String>,
    /// The Sentinel table of a source's records, as `SOURCE=TABLE`. Repeatable.
    #[arg(long, value_name = "SOURCE=TABLE", requires = "kusto")]
    pub(crate) sentinel_table: Vec<String>,
    /// Print the result as JSON (for CI).
    #[arg(long)]
    pub(crate) json: bool,
    /// Pass even when the sample raises no alert. Such a proof shows nothing about detections,
    /// so by default it fails: give a sample with the attacks your rules detect.
    #[arg(long)]
    pub(crate) allow_no_alerts: bool,
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
