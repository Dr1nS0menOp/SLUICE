//! Field naming conventions (ADR 0018).
//!
//! A rule names the fields it reads in one convention, and a SIEM stores them in another: Sigma
//! says `Image`, Elastic's ECS says `process.executable`. Comparing the names as plain text would
//! make a rule look as if it read nothing of a record that carries its data under other names,
//! and the guardrails would cut what the rule reads. A [`Schema`] says which convention a source's
//! records follow, so the guardrails know when a rule's field names can be compared with them.

use std::fmt;

use serde::{Deserialize, Serialize};

/// The convention a source's field names follow, or that a rule's field names are written in.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum Schema {
    /// Not declared. Nothing is known about the names, so no rule's field names can be compared
    /// with them (safety contract rule 3 then keeps everything such a rule could read).
    #[default]
    Undeclared,
    /// The names Sigma rules use: Windows event data names (`Image`, `TargetUserName`) and the
    /// names the rule author chose for other products.
    Sigma,
    /// Elastic Common Schema (`process.executable`, `source.ip`).
    Ecs,
    /// Splunk's Common Information Model.
    Cim,
    /// Microsoft Sentinel's Advanced Security Information Model.
    Asim,
    /// The Open Cybersecurity Schema Framework.
    Ocsf,
    /// Google's Unified Data Model.
    Udm,
    /// The columns of a Microsoft Sentinel table that is not an ASIM table (`Syslog`,
    /// `CommonSecurityLog`).
    Sentinel,
    /// The fields as Splunk extracts them at search time: for a JSON event, its key paths
    /// joined by dots (`KV_MODE = json`). Aliases and calculated fields (`props.conf`) are not
    /// part of the record; given `props.conf`, Splunk searches are read through them.
    Splunk,
}

impl Schema {
    /// Whether a rule written in the `rule` convention can be compared with records that follow
    /// this one. Only a declared convention equal to the rule's qualifies: no mapping between
    /// conventions is known (yet), and a wrong guess about names would cut data a rule reads.
    #[must_use]
    pub fn can_read(self, rule: Schema) -> bool {
        self != Self::Undeclared && self == rule
    }

    /// Whether the convention is declared.
    #[must_use]
    pub fn is_declared(self) -> bool {
        self != Self::Undeclared
    }

    /// The roots of ECS's field sets, by which a record's names are recognised as ECS.
    const ECS_ROOTS: &[&str] = &[
        "event.",
        "process.",
        "host.",
        "source.",
        "destination.",
        "user.",
        "winlog.",
        "agent.",
        "network.",
        "file.",
        "url.",
        "dns.",
    ];

    /// The convention a record's field names most likely follow, from the names alone; `None`
    /// when they do not say. A guess for people to check (`sluice init`, the hint on a schema
    /// that does not fit), never a declaration: the guardrails only trust a declared `schema`.
    #[must_use]
    pub fn guess<'a>(fields: impl IntoIterator<Item = &'a str>) -> Option<Self> {
        let fields: Vec<&str> = fields.into_iter().collect();
        let has = |name: &str| fields.contains(&name);
        let share = |prefixes: &[&str]| -> usize {
            let hits = fields
                .iter()
                .filter(|f| prefixes.iter().any(|p| f.starts_with(p)))
                .count();
            hits * 100 / fields.len().max(1)
        };
        if has("class_uid") && has("activity_id") {
            Some(Self::Ocsf)
        } else if fields.iter().any(|f| f.starts_with("metadata.event_type")) {
            Some(Self::Udm)
        } else if has("EventSchema") || (has("EventProduct") && has("EventVendor")) {
            Some(Self::Asim)
        } else if has("TimeGenerated") || (has("TenantId") && has("SourceSystem")) {
            Some(Self::Sentinel)
        } else if has("EventID")
            && !has("event.code")
            && [
                "Image",
                "CommandLine",
                "TargetUserName",
                "SubjectUserName",
                "Channel",
            ]
            .iter()
            .any(|f| has(f))
        {
            // Windows' own names, even inside a Beats envelope that names its version.
            Some(Self::Sigma)
        } else if share(Self::ECS_ROOTS) >= 40
            || (has("ecs.version") && share(Self::ECS_ROOTS) >= 20)
        {
            Some(Self::Ecs)
        } else if ["src_ip", "dst_ip", "dst_port"].iter().any(|f| has(f)) {
            // Sigma's taxonomy for firewalls and proxies.
            Some(Self::Sigma)
        } else if has("sourcetype") && (has("_time") || has("host")) {
            Some(Self::Splunk)
        } else if has("EventID")
            && [
                "Image",
                "CommandLine",
                "TargetUserName",
                "SubjectUserName",
                "Channel",
            ]
            .iter()
            .any(|f| has(f))
        {
            Some(Self::Sigma)
        } else {
            None
        }
    }
}

impl fmt::Display for Schema {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Undeclared => "undeclared",
            Self::Sigma => "sigma",
            Self::Ecs => "ecs",
            Self::Cim => "cim",
            Self::Asim => "asim",
            Self::Ocsf => "ocsf",
            Self::Udm => "udm",
            Self::Sentinel => "sentinel",
            Self::Splunk => "splunk",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_declared_equal_convention_can_be_compared() {
        assert!(Schema::Sigma.can_read(Schema::Sigma));
        assert!(!Schema::Ecs.can_read(Schema::Sigma));
        assert!(!Schema::Undeclared.can_read(Schema::Sigma));
        assert!(
            !Schema::Undeclared.can_read(Schema::Undeclared),
            "an undeclared source matches nothing, not even an undeclared rule"
        );
    }

    const ALL: [Schema; 9] = [
        Schema::Undeclared,
        Schema::Sigma,
        Schema::Ecs,
        Schema::Cim,
        Schema::Asim,
        Schema::Ocsf,
        Schema::Udm,
        Schema::Sentinel,
        Schema::Splunk,
    ];

    #[test]
    fn can_read_holds_exactly_on_the_declared_diagonal() {
        for data in ALL {
            for rule in ALL {
                assert_eq!(
                    data.can_read(rule),
                    data == rule && data != Schema::Undeclared,
                    "{data} reading {rule}"
                );
            }
        }
    }

    #[test]
    fn a_guess_follows_the_names_each_convention_uses_and_admits_when_they_say_nothing() {
        let guess = |names: &[&str]| Schema::guess(names.iter().copied());
        assert_eq!(
            guess(&["EventID", "Image", "CommandLine"]),
            Some(Schema::Sigma)
        );
        assert_eq!(
            guess(&[
                "@timestamp",
                "event.code",
                "process.executable",
                "host.name"
            ]),
            Some(Schema::Ecs)
        );
        assert_eq!(
            guess(&["TimeGenerated", "Computer", "EventID", "Account"]),
            Some(Schema::Sentinel),
            "a Sentinel table, even with Windows columns"
        );
        assert_eq!(
            guess(&["TimeGenerated", "EventSchema", "SrcIpAddr"]),
            Some(Schema::Asim)
        );
        assert_eq!(
            guess(&["class_uid", "activity_id", "src_endpoint.ip"]),
            Some(Schema::Ocsf)
        );
        assert_eq!(
            guess(&["metadata.event_type", "principal.ip"]),
            Some(Schema::Udm)
        );
        assert_eq!(
            guess(&["ecs.version", "agent.type", "EventID", "Channel", "Image"]),
            Some(Schema::Sigma),
            "Windows names in a Beats envelope"
        );
        assert_eq!(guess(&["message", "host"]), None);
        assert_eq!(guess(&[]), None);
    }

    #[test]
    fn only_undeclared_is_undeclared() {
        for schema in ALL {
            assert_eq!(schema.is_declared(), schema != Schema::Undeclared);
        }
    }

    #[test]
    fn display_and_serde_use_the_same_name() {
        for schema in ALL {
            let json = serde_json::to_string(&schema).unwrap();
            assert_eq!(json, format!("\"{schema}\""));
            assert_eq!(serde_json::from_str::<Schema>(&json).unwrap(), schema);
        }
        assert!(
            serde_json::from_str::<Schema>("\"ECS\"").is_err(),
            "names are lowercase"
        );
    }

    #[test]
    fn names_round_trip_through_serde() {
        let parsed: Schema = serde_json::from_str("\"ecs\"").expect("a schema name");
        assert_eq!(parsed, Schema::Ecs);
        assert_eq!(Schema::default(), Schema::Undeclared);
    }
}
