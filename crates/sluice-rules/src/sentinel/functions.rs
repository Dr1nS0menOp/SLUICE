//! ASIM parsers and other workspace functions whose source was read (ADR 0015, step 3).
//!
//! A rule that uses a parser reads whatever the parser reads. Parser files from
//! Azure/Azure-Sentinel (`Parsers/ASim*/Parsers/*.yaml`, helpers in `ASIM/lib/functions`) carry
//! the function's names and its KQL; a unifying parser such as `imProcessCreate` calls source
//! parsers, which read the tables.
//! Resolution follows those calls. A function that is not known, or that calls itself, keeps
//! the fail-closed reading: any table, any row, any column.

use std::cell::RefCell;
use std::collections::BTreeMap;

use serde_yaml_ng::Value;

use super::SentinelWorkspace;
use super::extract::{self, Reads};
use super::lexer;

/// Functions by name, with what each reads once resolved.
#[derive(Debug, Clone, Default)]
pub(super) struct Functions {
    queries: BTreeMap<String, String>,
    resolved: RefCell<BTreeMap<String, Reads>>,
}

impl Functions {
    /// Registers a parser document (`ParserName`, `EquivalentBuiltInParser`, `ParserQuery`) or
    /// an ASIM helper function (`ASIM/lib/functions`: `FunctionName`,
    /// `EquivalentBuiltInFunction`, `FunctionQuery`). Returns whether the document was one.
    pub(super) fn add(&mut self, doc: &Value) -> bool {
        let (query_key, name_keys) = if doc.get("ParserQuery").is_some() {
            ("ParserQuery", ["ParserName", "EquivalentBuiltInParser"])
        } else {
            (
                "FunctionQuery",
                ["FunctionName", "EquivalentBuiltInFunction"],
            )
        };
        let Some(query) = doc.get(query_key).and_then(Value::as_str) else {
            return false;
        };
        for key in name_keys {
            if let Some(name) = doc.get(key).and_then(Value::as_str) {
                self.queries.insert(name.to_owned(), query.to_owned());
            }
        }
        true
    }

    /// What `query` reads, with every known function it uses resolved.
    pub(super) fn reads(&self, query: &str, workspace: &SentinelWorkspace<'_>) -> Reads {
        self.resolve_query(query, &mut Vec::new(), workspace)
    }

    fn resolve_query(
        &self,
        query: &str,
        stack: &mut Vec<String>,
        workspace: &SentinelWorkspace<'_>,
    ) -> Reads {
        let known = |name: &str| self.queries.contains_key(name);
        let mut reads = extract::reads(&lexer::tokens(query), &known, workspace);
        for name in std::mem::take(&mut reads.calls) {
            let callee = self.resolve(&name, stack, workspace);
            // A function that reads no table a source may fill (a shaped one, a custom one, or
            // any) adds nothing a source must keep.
            if !callee.tables.is_empty() || !callee.custom_tables.is_empty() || callee.any_table {
                reads.merge(callee);
            }
        }
        reads
    }

    fn resolve(
        &self,
        name: &str,
        stack: &mut Vec<String>,
        workspace: &SentinelWorkspace<'_>,
    ) -> Reads {
        if let Some(done) = self.resolved.borrow().get(name) {
            return done.clone();
        }
        if stack.iter().any(|n| n == name) {
            return Reads::unknown(format!("`{name}` calls itself"));
        }
        let Some(query) = self.queries.get(name) else {
            return Reads::unknown(format!("`{name}` is not known"));
        };
        stack.push(name.to_owned());
        let reads = self.resolve_query(query, stack, workspace);
        stack.pop();
        self.resolved
            .borrow_mut()
            .insert(name.to_owned(), reads.clone());
        reads
    }
}
