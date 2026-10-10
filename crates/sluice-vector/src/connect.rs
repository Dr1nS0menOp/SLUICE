//! Destination sinks for common SIEMs (`sluice connect`).
//!
//! Each target is a Vector sink, written for the `destinations:` map of the `sluice up`
//! configuration. Secrets are never written: they are `${VAR}` references that Vector reads from
//! its environment. Every sink here is checked with `vector validate` against the Vector release
//! in `docs/compatibility.md` (`scripts/vector-check.sh`).

use serde_json::{Map, Value, json};

use crate::live::FORMATS_KEY;

/// A SIEM or log platform Sluice can forward to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Target {
    /// Splunk through the HTTP Event Collector.
    Splunk,
    /// Elasticsearch or `OpenSearch` through the bulk API.
    Elastic,
    /// Microsoft Sentinel through the Logs Ingestion API (a data collection rule).
    Sentinel,
    /// Google `SecOps` (Chronicle) through its unstructured log ingestion.
    Chronicle,
    /// Wazuh: an NDJSON file that the manager or an agent reads as a `localfile`.
    Wazuh,
    /// Any HTTP endpoint that accepts newline-delimited JSON.
    Http,
}

impl Target {
    /// Every target, in a stable order.
    pub const ALL: [Self; 6] = [
        Self::Splunk,
        Self::Elastic,
        Self::Sentinel,
        Self::Chronicle,
        Self::Wazuh,
        Self::Http,
    ];

    /// The name used on the command line and as the destination's key.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Splunk => "splunk",
            Self::Elastic => "elastic",
            Self::Sentinel => "sentinel",
            Self::Chronicle => "chronicle",
            Self::Wazuh => "wazuh",
            Self::Http => "http",
        }
    }

    /// The placeholder endpoint used when none is given.
    #[must_use]
    pub fn example_endpoint(self) -> &'static str {
        match self {
            Self::Splunk => "https://splunk.example.com:8088",
            Self::Elastic => "https://elastic.example.com:9200",
            Self::Sentinel => "https://dce-example.westeurope-1.ingest.monitor.azure.com",
            Self::Chronicle => "https://europe-malachiteingestion-pa.googleapis.com",
            Self::Wazuh => "/var/log/sluice/wazuh-%Y-%m-%d.ndjson",
            Self::Http => "https://logs.example.com/ingest",
        }
    }

    /// The secrets the sink reads from the [`SECRET_BACKEND`] backend, one file each under its
    /// directory. Vector 0.59 does not interpolate `${VAR}` by default, so credentials are never
    /// environment references.
    #[must_use]
    pub fn secrets(self) -> &'static [&'static str] {
        match self {
            Self::Splunk => &["splunk_hec_token"],
            Self::Elastic => &["elastic_password"],
            Self::Sentinel => &["azure_client_secret"],
            Self::Chronicle | Self::Wazuh | Self::Http => &[],
        }
    }

    /// The `vector_secrets` entry for the `sluice up` configuration, if the target has secrets:
    /// a directory backend with one file per secret (Docker and Kubernetes secrets mount so).
    #[must_use]
    pub fn secret_backend(self) -> Option<(String, Value)> {
        (!self.secrets().is_empty()).then(|| {
            (
                SECRET_BACKEND.to_owned(),
                json!({ "type": "directory", "path": SECRET_DIR }),
            )
        })
    }

    /// The destinations for the `sluice up` configuration, keyed by name, without `inputs`
    /// (Sluice sets them). `endpoint` is a URL, or for Wazuh the JSON file's path.
    ///
    /// Most targets take one sink. Wazuh takes two, because its syslog rules only match raw
    /// lines: JSON sources go to a JSON file and text sources, as their original lines, to a
    /// second file (selected with [`FORMATS_KEY`]).
    #[must_use]
    pub fn destinations(self, name: &str, endpoint: &str) -> Map<String, Value> {
        let mut destinations = Map::new();
        if self == Self::Wazuh {
            let mut json_file = self.sink(endpoint);
            json_file[FORMATS_KEY] = json!(["json"]);
            destinations.insert(name.to_owned(), json_file);
            destinations.insert(
                format!("{name}_lines"),
                json!({
                    "type": "file",
                    "path": wazuh_lines_path(endpoint),
                    // The text codec writes the `message` field: the original line.
                    "encoding": { "codec": "text" },
                    FORMATS_KEY: ["text"],
                }),
            );
        } else {
            destinations.insert(name.to_owned(), self.sink(endpoint));
        }
        destinations
    }

    fn sink(self, endpoint: &str) -> Value {
        let json_lines = json!({ "codec": "json" });
        match self {
            Self::Splunk => json!({
                "type": "splunk_hec_logs",
                "endpoint": endpoint,
                "default_token": secret("splunk_hec_token"),
                "encoding": json_lines,
            }),
            Self::Elastic => json!({
                "type": "elasticsearch",
                "endpoints": [endpoint],
                "mode": "bulk",
                "bulk": { "index": "sluice-%Y.%m.%d" },
                "auth": {
                    "strategy": "basic",
                    "user": "sluice",
                    "password": secret("elastic_password"),
                },
            }),
            Self::Sentinel => json!({
                "type": "azure_logs_ingestion",
                "endpoint": endpoint,
                "dcr_immutable_id": "dcr-00000000000000000000000000000000",
                "stream_name": "Custom-Sluice_CL",
                "auth": {
                    "azure_credential_kind": "client_secret_credential",
                    "azure_tenant_id": "00000000-0000-0000-0000-000000000000",
                    "azure_client_id": "00000000-0000-0000-0000-000000000000",
                    "azure_client_secret": secret("azure_client_secret"),
                },
            }),
            Self::Chronicle => json!({
                "type": "gcp_chronicle_unstructured",
                "endpoint": endpoint,
                "customer_id": "00000000-0000-0000-0000-000000000000",
                "credentials_path": "/run/secrets/siem/chronicle-credentials.json",
                "log_type": "UNSPECIFIED",
                "encoding": json_lines,
            }),
            Self::Wazuh => json!({
                "type": "file",
                "path": endpoint,
                "encoding": json_lines,
            }),
            Self::Http => json!({
                "type": "http",
                "uri": endpoint,
                "method": "post",
                "encoding": json_lines,
                "framing": { "method": "newline_delimited" },
            }),
        }
    }

    /// What else to set up, for people: where the rules come from and what to replace.
    /// `endpoint` is the one given to [`Target::destinations`].
    #[must_use]
    pub fn notes(self, endpoint: &str) -> String {
        match self {
            Self::Splunk => "Create a HEC token for the target index. Detections: give `sluice up \
                             --rules` the Sigma rules your Splunk searches come from (SPL parsing \
                             is planned)."
                .to_owned(),
            Self::Elastic => "Use a user that may write `sluice-*` indices. Detections: give \
                              `--rules` your Sigma rules (EQL and KQL parsing are planned)."
                .to_owned(),
            Self::Sentinel => "Replace `dcr_immutable_id` and `stream_name` with your data \
                               collection rule's; the app registration needs `Monitoring Metrics \
                               Publisher` on it. Detections: give `--rules` your Sigma rules \
                               (KQL parsing is planned)."
                .to_owned(),
            Self::Chronicle => "Set `log_type` to the parser for this source. Detections: give \
                                `--rules` your Sigma rules (YARA-L parsing is planned)."
                .to_owned(),
            Self::Wazuh => format!(
                "Add both files to the manager's or an agent's ossec.conf, each in its format:\n  \
                 <localfile>\n    <log_format>json</log_format>\n    <location>{endpoint}</location>\n  \
                 </localfile>\n  <localfile>\n    <log_format>syslog</log_format>\n    \
                 <location>{lines}</location>\n  </localfile>\nWindows events: keep them on the \
                 agent's eventchannel; Wazuh's Windows rules do not match them from a file \
                 (docs/notes/wazuh.md). Detections: copy /var/ossec/ruleset/rules and \
                 /var/ossec/etc/rules for `sluice up --wazuh-rules`, and add `--wazuh-api` to \
                 `sluice analyze` for exact logtest checks.",
                lines = wazuh_lines_path(endpoint)
            ),
            Self::Http => {
                "The endpoint receives batches of newline-delimited JSON objects.".to_owned()
            }
        }
    }
}

/// Name of the secret backend the destinations' credentials come from.
pub const SECRET_BACKEND: &str = "siem";
/// Where that backend reads secrets by default: one file per secret.
const SECRET_DIR: &str = "/run/secrets/siem";

/// A reference to secret `key` of [`SECRET_BACKEND`].
fn secret(key: &str) -> String {
    format!("SECRET[{SECRET_BACKEND}.{key}]")
}

/// The raw-line file next to Wazuh's JSON file: `x.ndjson` becomes `x.log`.
fn wazuh_lines_path(endpoint: &str) -> String {
    match endpoint.strip_suffix(".ndjson") {
        Some(stem) => format!("{stem}.log"),
        None => format!("{endpoint}.log"),
    }
}
