//! The Model Context Protocol (MCP) for Sluice (ADR 0035): an AI assistant calls Sluice's tools
//! over stdio, one JSON-RPC 2.0 message per line.
//!
//! Only what a server that offers tools needs: `initialize`, `ping`, `tools/list` and
//! `tools/call`, for the protocol versions that open with `initialize` ([`PROTOCOL_VERSIONS`]).
//! The tools themselves are the caller's ([`Tools`]); this crate holds no state of Sluice's and
//! does no I/O but the two streams it is given, so every answer can be tested line by line.
//!
//! An assistant reads text that whoever writes a log line controls, so a tool must never act on
//! the world on an argument's say-so. That rule belongs to the tools; this crate only carries
//! the calls.

use std::io::{BufRead, Write};

use serde_json::{Map, Value, json};

#[cfg(test)]
mod tests;

/// The protocol versions served, newest first. A client that asks for another is answered with
/// the newest, as the protocol says, and decides itself whether it can go on.
pub const PROTOCOL_VERSIONS: [&str; 4] = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

/// JSON-RPC's error codes, as the protocol uses them.
const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;

/// A tool, as `tools/list` describes it.
#[derive(Debug, Clone, PartialEq)]
pub struct Tool {
    /// The name the assistant calls it by.
    pub name: &'static str,
    /// A short name for people.
    pub title: &'static str,
    /// What it does and when to call it, for the assistant.
    pub description: &'static str,
    /// The JSON Schema of its arguments: an object schema.
    pub input_schema: Value,
}

/// The tools a server offers, and what calling one gives.
pub trait Tools {
    /// Every tool, in a fixed order.
    fn list(&self) -> Vec<Tool>;

    /// Calls the tool `name` with `arguments`. `Ok` is the tool's answer; `Err` a failure the
    /// assistant should read (a missing argument, a proof that does not hold), not a protocol
    /// error. `name` is always one of [`Tools::list`].
    ///
    /// # Errors
    ///
    /// A message for the assistant when the tool could not do what was asked.
    fn call(&mut self, name: &str, arguments: &Map<String, Value>) -> Result<Value, String>;
}

/// Who the server is, for `initialize`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerInfo {
    /// The program's name.
    pub name: &'static str,
    /// Its version.
    pub version: &'static str,
    /// How to use the tools, which a client may hand the assistant.
    pub instructions: &'static str,
}

/// The connection could not be served.
#[derive(Debug, thiserror::Error)]
pub enum McpError {
    /// Reading a message or writing an answer failed.
    #[error("the MCP connection failed: {0}")]
    Io(#[from] std::io::Error),
}

/// Answers every message on `input` with `tools` until the client closes it.
///
/// # Errors
///
/// [`McpError::Io`] when a stream fails.
pub fn serve(
    info: &ServerInfo,
    tools: &mut impl Tools,
    input: impl BufRead,
    mut output: impl Write,
) -> Result<(), McpError> {
    for line in input.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if let Some(answer) = answer(info, tools, &line) {
            writeln!(output, "{answer}")?;
            output.flush()?;
        }
    }
    Ok(())
}

/// The answer to one message; `None` for a notification, which gets none.
#[must_use]
pub fn answer(info: &ServerInfo, tools: &mut impl Tools, line: &str) -> Option<Value> {
    let message: Value = match serde_json::from_str(line) {
        Ok(message) => message,
        Err(error) => return Some(failure(&Value::Null, PARSE_ERROR, &error.to_string())),
    };
    let Value::Object(message) = message else {
        // Batches were dropped from the protocol in 2025-06-18; a scalar is no message.
        return Some(failure(
            &Value::Null,
            INVALID_REQUEST,
            "one JSON-RPC message per line",
        ));
    };
    let Some(method) = message.get("method").and_then(Value::as_str) else {
        // A response to a request the server never sends, or no message at all.
        return message
            .get("id")
            .map(|id| failure(id, INVALID_REQUEST, "a request needs a method"));
    };
    let id = message.get("id")?;
    let params = message.get("params").and_then(Value::as_object);
    Some(match method {
        "initialize" => success(id, initialize(info, params)),
        "ping" => success(id, json!({})),
        "tools/list" => success(
            id,
            json!({ "tools": tools.list().iter().map(described).collect::<Vec<_>>() }),
        ),
        "tools/call" => call(tools, id, params),
        other => failure(id, METHOD_NOT_FOUND, &format!("no method {other}")),
    })
}

/// The answer to `initialize`: the version both speak, and that the server offers tools.
fn initialize(info: &ServerInfo, params: Option<&Map<String, Value>>) -> Value {
    let asked = params
        .and_then(|p| p.get("protocolVersion"))
        .and_then(Value::as_str);
    let version = asked
        .filter(|v| PROTOCOL_VERSIONS.contains(v))
        .unwrap_or(PROTOCOL_VERSIONS[0]);
    json!({
        "protocolVersion": version,
        "capabilities": { "tools": { "listChanged": false } },
        "serverInfo": { "name": info.name, "version": info.version },
        "instructions": info.instructions,
    })
}

/// A tool as `tools/list` gives it. Every Sluice tool reads, or proves on a local sample: none
/// changes anything, and none reaches beyond the engines the server was started with.
fn described(tool: &Tool) -> Value {
    json!({
        "name": tool.name,
        "title": tool.title,
        "description": tool.description,
        "inputSchema": tool.input_schema,
        "annotations": {
            "title": tool.title,
            "readOnlyHint": true,
            "destructiveHint": false,
            "openWorldHint": false,
        },
    })
}

/// The answer to `tools/call`: the tool's answer as text and, for an object, as structured
/// content too; a tool's failure is a result the assistant reads (`isError`), an unknown tool a
/// protocol error.
fn call(tools: &mut impl Tools, id: &Value, params: Option<&Map<String, Value>>) -> Value {
    let Some(name) = params.and_then(|p| p.get("name")).and_then(Value::as_str) else {
        return failure(id, INVALID_PARAMS, "tools/call needs the tool's name");
    };
    if !tools.list().iter().any(|tool| tool.name == name) {
        return failure(id, INVALID_PARAMS, &format!("no tool {name}"));
    }
    let empty = Map::new();
    let arguments = match params.and_then(|p| p.get("arguments")) {
        None | Some(Value::Null) => &empty,
        Some(Value::Object(arguments)) => arguments,
        Some(_) => return failure(id, INVALID_PARAMS, "arguments must be an object"),
    };
    let result = match tools.call(name, arguments) {
        Ok(answer) => {
            let text = serde_json::to_string_pretty(&answer).unwrap_or_else(|_| answer.to_string());
            let mut result = json!({
                "content": [{ "type": "text", "text": text }],
                "isError": false,
            });
            if answer.is_object() {
                result["structuredContent"] = answer;
            }
            result
        }
        Err(message) => json!({
            "content": [{ "type": "text", "text": message }],
            "isError": true,
        }),
    };
    success(id, result)
}

fn success(id: &Value, result: Value) -> Value {
    let mut answer = json!({ "jsonrpc": "2.0", "id": id });
    answer["result"] = result;
    answer
}

fn failure(id: &Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}
