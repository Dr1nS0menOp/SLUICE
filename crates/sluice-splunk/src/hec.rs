//! Splunk's HTTP Event Collector, with a token of the proof's own: how the proof sends events.

use std::sync::atomic::Ordering;

use serde_json::{Map, Value, json};
use sluice_core::event::Event;

use crate::SplunkError;
use crate::client::{Rest, content};
use crate::engine::{EVENT_FIELD, NAMES, Proof, RUN_FIELD, SOURCETYPE, TIMEOUT};

/// The collector at its address, and the token the proof made.
#[derive(Debug)]
pub(crate) struct Hec {
    http: sluice_http::Client,
    url: String,
    token: String,
    /// The token's name, to remove it afterwards.
    name: String,
}

impl Hec {
    /// Makes a token for the proof on the collector Splunk reports, which must be on.
    pub(crate) fn create(rest: &Rest, proof: &Proof<'_>) -> Result<Self, SplunkError> {
        let settings = rest.json("GET", "/services/data/inputs/http/http", &[])?;
        let settings = content(&settings);
        if truthy(&settings["disabled"]) {
            return Err(SplunkError::Response(
                "the HTTP Event Collector is turned off: turn it on in Splunk (Settings, Data \
                 inputs, HTTP Event Collector, Global Settings)"
                    .to_owned(),
            ));
        }
        let url = if let Some(url) = proof.hec {
            url.trim_end_matches('/').to_owned()
        } else {
            let port = settings["port"]
                .as_str()
                .map(str::to_owned)
                .or_else(|| settings["port"].as_u64().map(|p| p.to_string()))
                .unwrap_or_else(|| "8088".to_owned());
            // Splunk's default is TLS.
            let tls = settings["enableSSL"].is_null() || truthy(&settings["enableSSL"]);
            collector_url(rest.base(), if tls { "https" } else { "http" }, &port)?
        };
        let name = format!(
            "sluice-proof-{}-{}",
            std::process::id(),
            NAMES.fetch_add(1, Ordering::Relaxed)
        );
        let created = rest.json("POST", "/services/data/inputs/http", &[("name", &name)])?;
        let token = content(&created)["token"]
            .as_str()
            .ok_or_else(|| SplunkError::Response("a collector token without its value".into()))?
            .to_owned();
        Ok(Self {
            http: sluice_http::Client::with(TIMEOUT, proof.insecure, sluice_http::MAX_ANSWER),
            url,
            token,
            name,
        })
    }

    /// Sends events, one JSON object after another. The collector accepts events for an index
    /// that does not exist and drops them, so only a count afterwards shows what arrived.
    pub(crate) fn send(&self, body: &str) -> Result<(), SplunkError> {
        let answer = self
            .http
            .send(
                "POST",
                &format!("{}/services/collector/event", self.url),
                &[("authorization", format!("Splunk {}", self.token))],
                Some(body),
            )
            .map_err(|e| SplunkError::Unreachable {
                url: self.url.clone(),
                reason: e.reason,
            })?;
        let code = serde_json::from_str::<Value>(&answer.body)
            .ok()
            .and_then(|a| a["code"].as_u64());
        if !answer.is_success() || code != Some(0) {
            return Err(SplunkError::Rejected {
                status: answer.status,
                message: answer.body,
            });
        }
        Ok(())
    }

    /// Removes the token; one left behind is only a leftover.
    pub(crate) fn remove(&self, rest: &Rest) {
        let path = format!(
            "/services/data/inputs/http/{}",
            sluice_http::percent_encode(&self.name)
        );
        let _ = rest.send("DELETE", &path, &[]);
    }
}

/// An event as the collector takes it: its body as it is, its time, its id and the evaluation
/// (`run`) beside it as indexed fields, and metadata that names the source.
pub(crate) fn event(index: &str, run: u64, event: &Event) -> Value {
    let mut fields = Map::new();
    fields.insert(
        EVENT_FIELD.to_owned(),
        Value::String(event.id.0.to_string()),
    );
    fields.insert(RUN_FIELD.to_owned(), Value::String(run.to_string()));
    json!({
        "time": event.timestamp.0,
        "index": index,
        "sourcetype": SOURCETYPE,
        "source": format!("sluice:{}", event.source),
        "host": "sluice",
        "fields": fields,
        "event": Value::Object(event.fields.clone()),
    })
}

/// Whether a Splunk setting is on: `true`, `1` or `"true"`.
pub(crate) fn truthy(value: &Value) -> bool {
    match value {
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_u64() == Some(1),
        Value::String(s) => matches!(s.to_ascii_lowercase().as_str(), "1" | "true" | "t" | "yes"),
        _ => false,
    }
}

/// The collector's address: the management port's host, with `scheme` and `port`.
pub(crate) fn collector_url(
    management: &str,
    scheme: &str,
    port: &str,
) -> Result<String, SplunkError> {
    let unclear = || {
        SplunkError::Response(format!(
            "cannot tell the collector's host from {management}: give its address"
        ))
    };
    let (_, rest) = management.split_once("://").ok_or_else(unclear)?;
    let authority = rest.split('/').next().unwrap_or(rest);
    // Credentials in the address are not the host.
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let host = match authority.strip_prefix('[') {
        // An IPv6 address: `[::1]:8089`.
        Some(v6) => format!("[{}]", v6.split(']').next().unwrap_or(v6)),
        None => authority.split(':').next().unwrap_or(authority).to_owned(),
    };
    if host.is_empty() || host == "[]" {
        return Err(unclear());
    }
    Ok(format!("{scheme}://{host}:{port}"))
}

#[cfg(test)]
mod tests {
    use sluice_core::event::Timestamp;
    use sluice_core::ids::{EventId, SourceId};

    use super::*;

    #[test]
    fn the_collector_is_on_the_management_port_s_host() {
        assert_eq!(
            collector_url("https://splunk.example:8089", "https", "8088").unwrap(),
            "https://splunk.example:8088"
        );
        assert_eq!(
            collector_url("https://127.0.0.1:18089/", "http", "18088").unwrap(),
            "http://127.0.0.1:18088"
        );
        assert_eq!(
            collector_url("https://[::1]:8089", "https", "8088").unwrap(),
            "https://[::1]:8088"
        );
        assert_eq!(
            collector_url("https://user@splunk/x", "https", "8088").unwrap(),
            "https://splunk:8088"
        );
        assert!(collector_url("splunk:8089", "https", "8088").is_err());
        assert!(collector_url("https://", "https", "8088").is_err());
    }

    #[test]
    fn settings_are_on_as_splunk_writes_them() {
        for on in [json!(true), json!(1), json!("1"), json!("true")] {
            assert!(truthy(&on), "{on}");
        }
        for off in [json!(false), json!(0), json!("0"), json!(null), json!("no")] {
            assert!(!truthy(&off), "{off}");
        }
    }

    #[test]
    fn an_event_is_sent_as_it_is_with_its_id_beside_it() {
        let mut fields = Map::new();
        fields.insert("EventID".into(), json!(4624));
        fields.insert(EVENT_FIELD.into(), json!("the event's own"));
        let event = Event {
            id: EventId(7),
            timestamp: Timestamp(1_767_225_600),
            source: SourceId::new("win"),
            fields: fields.clone(),
        };
        assert_eq!(
            super::event("p", 3, &event),
            json!({
                "time": 1_767_225_600,
                "index": "p",
                "sourcetype": SOURCETYPE,
                "source": "sluice:win",
                "host": "sluice",
                "fields": { EVENT_FIELD: "7", RUN_FIELD: "3" },
                "event": Value::Object(fields),
            })
        );
    }
}
