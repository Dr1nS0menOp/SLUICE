//! Destination sinks for common SIEMs (`sluice connect`).
//!
//! Each target is a Vector sink, written for the `destinations:` map of the `sluice up`
//! configuration. Secrets are never written: they are `${VAR}` references that Vector reads from
//! its environment. Every sink here is checked with `vector validate` against the Vector release
//! in `docs/compatibility.md` (`scripts/vector-check.sh`).

use serde_json::{Value, json};

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

    /// Environment variables the sink reads, which must be set for Vector.
    #[must_use]
    pub fn secrets(self) -> &'static [&'static str] {
        match self {
            Self::Splunk => &["SPLUNK_HEC_TOKEN"],
            Self::Elastic => &["ELASTIC_USER", "ELASTIC_PASSWORD"],
            Self::Sentinel => &["AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"],
            Self::Chronicle => &["CHRONICLE_CUSTOMER_ID", "GOOGLE_APPLICATION_CREDENTIALS"],
            Self::Wazuh | Self::Http => &[],
        }
    }

    /// The Vector sink, without `inputs` (Sluice sets them). `endpoint` is a URL, or for Wazuh
    /// the file path.
    #[must_use]
    pub fn sink(self, endpoint: &str) -> Value {
        let json_lines = json!({ "codec": "json" });
        match self {
            Self::Splunk => json!({
                "type": "splunk_hec_logs",
                "endpoint": endpoint,
                "default_token": "${SPLUNK_HEC_TOKEN}",
                "encoding": json_lines,
            }),
            Self::Elastic => json!({
                "type": "elasticsearch",
                "endpoints": [endpoint],
                "mode": "bulk",
                "bulk": { "index": "sluice-%Y.%m.%d" },
                "auth": {
                    "strategy": "basic",
                    "user": "${ELASTIC_USER}",
                    "password": "${ELASTIC_PASSWORD}",
                },
            }),
            Self::Sentinel => json!({
                "type": "azure_logs_ingestion",
                "endpoint": endpoint,
                "dcr_immutable_id": "dcr-00000000000000000000000000000000",
                "stream_name": "Custom-Sluice_CL",
                "auth": {
                    "azure_credential_kind": "client_secret_credential",
                    "azure_tenant_id": "${AZURE_TENANT_ID}",
                    "azure_client_id": "${AZURE_CLIENT_ID}",
                    "azure_client_secret": "${AZURE_CLIENT_SECRET}",
                },
            }),
            Self::Chronicle => json!({
                "type": "gcp_chronicle_unstructured",
                "endpoint": endpoint,
                "customer_id": "${CHRONICLE_CUSTOMER_ID}",
                "credentials_path": "${GOOGLE_APPLICATION_CREDENTIALS}",
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
    /// `endpoint` is the one given to [`Target::sink`].
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
                "Add to the manager's or an agent's ossec.conf:\n  <localfile>\n    \
                 <log_format>json</log_format>\n    <location>{endpoint}</location>\n  \
                 </localfile>\nDetections: copy /var/ossec/ruleset/rules and \
                 /var/ossec/etc/rules for `sluice up --wazuh-rules`, and add `--wazuh-api` to \
                 `sluice analyze` for exact logtest checks."
            ),
            Self::Http => {
                "The endpoint receives batches of newline-delimited JSON objects.".to_owned()
            }
        }
    }
}
