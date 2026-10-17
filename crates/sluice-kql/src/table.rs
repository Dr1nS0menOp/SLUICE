//! The Sentinel tables Sluice loads records into: the standard ones it shapes records for, and
//! custom tables (`<Name>_CL`) a data collection rule fills from any source.

use std::sync::Arc;

use crate::schema;
/// A Sentinel table Sluice can load records into.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Table {
    /// Windows Security channel events.
    SecurityEvent,
    /// Windows events from every other channel.
    WindowsEvent,
    /// Syslog from Linux hosts and network devices.
    Syslog,
    /// Firewall and network device events (CEF).
    CommonSecurityLog,
    /// Network sessions in the ASIM schema.
    ASimNetworkSessionLogs,
    /// DNS queries in the ASIM schema.
    ASimDnsActivityLogs,
    /// Web sessions in the ASIM schema.
    ASimWebSessionLogs,
    /// A custom table (`<Name>_CL`), which a data collection rule fills from any source.
    Custom(CustomTable),
}

/// A custom table's name and columns, as the workspace declares them.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CustomTable {
    pub(crate) name: Arc<str>,
    pub(crate) columns: Arc<[CustomColumn]>,
}

/// A column of a custom table: its name and type, and the record field it holds (which the
/// data collection rule renamed when it is no valid column name).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CustomColumn {
    /// The column's name.
    pub name: String,
    /// Its Kusto type.
    pub kind: String,
    /// The record field it is filled from.
    pub field: String,
}

impl Table {
    /// The tables every workspace has that Sluice shapes records for.
    pub const STANDARD: [Self; 7] = [
        Self::SecurityEvent,
        Self::WindowsEvent,
        Self::Syslog,
        Self::CommonSecurityLog,
        Self::ASimNetworkSessionLogs,
        Self::ASimDnsActivityLogs,
        Self::ASimWebSessionLogs,
    ];

    /// The standard table with this name in a Log Analytics workspace, if Sluice can load it.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::STANDARD.into_iter().find(|t| t.name() == name)
    }

    /// A custom table `name` (ending in `_CL`) with `columns`; `None` for another name, a
    /// column name Log Analytics refuses (a letter, then letters, digits and `_`) or a type it
    /// does not have. Names go into management commands as they are, so nothing else passes.
    #[must_use]
    pub fn custom(name: &str, columns: Vec<CustomColumn>) -> Option<Self> {
        let valid = name.len() > 3
            && name.ends_with("_CL")
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            && columns
                .iter()
                .all(|c| is_column_name(&c.name) && is_type(&c.kind));
        valid.then(|| {
            Self::Custom(CustomTable {
                name: name.into(),
                columns: columns.into(),
            })
        })
    }

    /// The table's name in a Log Analytics workspace.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::SecurityEvent => "SecurityEvent",
            Self::WindowsEvent => "WindowsEvent",
            Self::Syslog => "Syslog",
            Self::CommonSecurityLog => "CommonSecurityLog",
            Self::ASimNetworkSessionLogs => "ASimNetworkSessionLogs",
            Self::ASimDnsActivityLogs => "ASimDnsActivityLogs",
            Self::ASimWebSessionLogs => "ASimWebSessionLogs",
            Self::Custom(custom) => &custom.name,
        }
    }

    /// The name of the stream a data flow writes into the table: `Microsoft-<Table>` for a
    /// standard table, `Custom-<Name>_CL` for a custom one.
    #[must_use]
    pub fn output_stream(&self) -> String {
        match self {
            Self::Custom(custom) => format!("Custom-{}", custom.name),
            other => format!("Microsoft-{}", other.name()),
        }
    }

    /// The table's columns, with the ones every workspace table has but the tables API does
    /// not list; rules project `_ResourceId` for entity mapping.
    pub(crate) fn columns(&self) -> impl Iterator<Item = (&str, &str)> {
        self.own_columns().chain(HIDDEN_COLUMNS.iter().copied())
    }

    /// The table's columns as the tables API lists them: what a data flow into the table
    /// carries when it has no stream of its own.
    #[must_use]
    pub fn column_names(&self) -> Vec<&str> {
        self.own_columns().map(|(name, _)| name).collect()
    }

    /// The columns a data flow's stream carries when its rule declares none: a standard
    /// table's own, a custom table's record fields (as `sluice connect sentinel` declares them,
    /// before its rule renames any).
    #[must_use]
    pub fn stream_columns(&self) -> Vec<(&str, &str)> {
        match self {
            Self::Custom(custom) => custom
                .columns
                .iter()
                .map(|c| (c.field.as_str(), c.kind.as_str()))
                .collect(),
            other => other.column_types(),
        }
    }

    /// [`Table::column_names`] with their types.
    #[must_use]
    pub fn column_types(&self) -> Vec<(&str, &str)> {
        self.own_columns().collect()
    }

    /// The columns the tables API lists, with their types.
    pub(crate) fn own_columns(&self) -> Box<dyn Iterator<Item = (&str, &str)> + '_> {
        let own = match self {
            Self::SecurityEvent => schema::SECURITY_EVENT,
            Self::WindowsEvent => schema::WINDOWS_EVENT,
            Self::Syslog => schema::SYSLOG,
            Self::CommonSecurityLog => schema::COMMON_SECURITY_LOG,
            Self::ASimNetworkSessionLogs => schema::ASIM_NETWORK_SESSION_LOGS,
            Self::ASimDnsActivityLogs => schema::ASIM_DNS_ACTIVITY_LOGS,
            Self::ASimWebSessionLogs => schema::ASIM_WEB_SESSION_LOGS,
            Self::Custom(custom) => {
                return Box::new(
                    custom
                        .columns
                        .iter()
                        .map(|c| (c.name.as_str(), c.kind.as_str())),
                );
            }
        };
        Box::new(own.iter().copied())
    }
}

/// Whether Log Analytics takes `name` as a column name.
fn is_column_name(name: &str) -> bool {
    name.starts_with(|c: char| c.is_ascii_alphabetic())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Whether `kind` is a column type a Log Analytics table takes.
fn is_type(kind: &str) -> bool {
    [
        "string", "int", "long", "real", "bool", "boolean", "datetime", "dynamic", "guid",
        "timespan",
    ]
    .contains(&kind)
}
const HIDDEN_COLUMNS: &[(&str, &str)] = &[
    ("Type", "string"),
    ("_ResourceId", "string"),
    ("_SubscriptionId", "string"),
];
