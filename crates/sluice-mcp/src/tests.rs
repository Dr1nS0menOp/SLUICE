use serde_json::{Map, Value, json};

use super::*;

const INFO: ServerInfo = ServerInfo {
    name: "sluice",
    version: "0.1.0",
    instructions: "Read the advice first.",
};

/// One tool, `echo`, that gives its arguments back, and fails on `{"fail": true}`.
struct Echo {
    calls: usize,
}

impl Tools for Echo {
    fn list(&self) -> Vec<Tool> {
        vec![Tool {
            name: "echo",
            title: "Echo",
            description: "Gives the arguments back.",
            input_schema: json!({"type": "object"}),
        }]
    }

    fn call(&mut self, name: &str, arguments: &Map<String, Value>) -> Result<Value, String> {
        assert_eq!(name, "echo");
        self.calls += 1;
        if arguments.get("fail") == Some(&json!(true)) {
            return Err("it failed".to_owned());
        }
        Ok(Value::Object(arguments.clone()))
    }
}

fn ask(line: &Value) -> Option<Value> {
    answer(&INFO, &mut Echo { calls: 0 }, &line.to_string())
}

#[test]
fn initialize_agrees_on_a_version_and_offers_tools() {
    let answer = ask(&json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "c", "version": "1"}}}))
    .expect("an answer");
    assert_eq!(answer["id"], 1);
    assert_eq!(answer["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(
        answer["result"]["capabilities"],
        json!({"tools": {"listChanged": false}})
    );
    assert_eq!(
        answer["result"]["serverInfo"],
        json!({"name": "sluice", "version": "0.1.0"})
    );
    assert_eq!(answer["result"]["instructions"], "Read the advice first.");
}

#[test]
fn a_version_the_server_does_not_speak_is_answered_with_its_newest() {
    for asked in [json!("2099-01-01"), json!(null), json!(7)] {
        let answer = ask(&json!({"jsonrpc": "2.0", "id": "a", "method": "initialize",
            "params": {"protocolVersion": asked}}))
        .expect("an answer");
        assert_eq!(
            answer["result"]["protocolVersion"], PROTOCOL_VERSIONS[0],
            "{asked}"
        );
    }
    let bare = ask(&json!({"jsonrpc": "2.0", "id": 2, "method": "initialize"})).expect("an answer");
    assert_eq!(bare["result"]["protocolVersion"], PROTOCOL_VERSIONS[0]);
}

#[test]
fn notifications_get_no_answer() {
    assert_eq!(
        ask(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"})),
        None
    );
    assert_eq!(
        ask(&json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {}})),
        None
    );
    // A response from the client, to a request the server never sent: nothing to say.
    assert_eq!(ask(&json!({"jsonrpc": "2.0", "result": {}})), None);
}

#[test]
fn ping_and_the_tool_list() {
    assert_eq!(
        ask(&json!({"jsonrpc": "2.0", "id": 3, "method": "ping"})),
        Some(json!({"jsonrpc": "2.0", "id": 3, "result": {}}))
    );
    let list = ask(&json!({"jsonrpc": "2.0", "id": 4, "method": "tools/list"})).expect("an answer");
    let tool = &list["result"]["tools"][0];
    assert_eq!(tool["name"], "echo");
    assert_eq!(tool["title"], "Echo");
    assert_eq!(tool["inputSchema"], json!({"type": "object"}));
    assert_eq!(tool["annotations"]["readOnlyHint"], true);
    assert_eq!(tool["annotations"]["destructiveHint"], false);
    assert_eq!(tool["annotations"]["openWorldHint"], false);
}

#[test]
fn a_call_answers_as_text_and_structured_content() {
    let answer = ask(&json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
        "params": {"name": "echo", "arguments": {"a": 1}}}))
    .expect("an answer");
    let result = &answer["result"];
    assert_eq!(result["isError"], false);
    assert_eq!(result["structuredContent"], json!({"a": 1}));
    assert_eq!(result["content"][0]["type"], "text");
    let text: Value = serde_json::from_str(result["content"][0]["text"].as_str().expect("text"))
        .expect("the text is the same JSON");
    assert_eq!(text, json!({"a": 1}));
    // Without arguments the tool gets an empty object.
    let bare = ask(
        &json!({"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "echo"}}),
    )
    .expect("an answer");
    assert_eq!(bare["result"]["structuredContent"], json!({}));
}

#[test]
fn a_tools_failure_is_a_result_the_assistant_reads() {
    let answer = ask(&json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": "echo", "arguments": {"fail": true}}}))
    .expect("an answer");
    assert_eq!(answer["result"]["isError"], true);
    assert_eq!(answer["result"]["content"][0]["text"], "it failed");
    assert!(answer.get("error").is_none());
}

#[test]
fn protocol_errors_carry_json_rpc_codes() {
    let code = |answer: Option<Value>| answer.expect("an answer")["error"]["code"].clone();
    assert_eq!(
        code(answer(&INFO, &mut Echo { calls: 0 }, "{not json")),
        json!(-32700)
    );
    assert_eq!(
        code(answer(&INFO, &mut Echo { calls: 0 }, "[1, 2]")),
        json!(-32600)
    );
    assert_eq!(
        code(ask(&json!({"jsonrpc": "2.0", "id": 8}))),
        json!(-32600)
    );
    assert_eq!(
        code(ask(
            &json!({"jsonrpc": "2.0", "id": 9, "method": "resources/list"})
        )),
        json!(-32601)
    );
    for params in [
        json!({}),
        json!({"name": "nope"}),
        json!({"name": "echo", "arguments": [1]}),
    ] {
        assert_eq!(
            code(ask(
                &json!({"jsonrpc": "2.0", "id": 10, "method": "tools/call", "params": params})
            )),
            json!(-32602),
            "{params}"
        );
    }
}

#[test]
fn an_unknown_tool_is_never_called() {
    let mut echo = Echo { calls: 0 };
    let line =
        json!({"jsonrpc": "2.0", "id": 11, "method": "tools/call", "params": {"name": "rm"}});
    let _ = answer(&INFO, &mut echo, &line.to_string());
    assert_eq!(echo.calls, 0);
}

#[test]
fn serve_answers_line_by_line_and_skips_blank_lines_and_notifications() {
    let input = [
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}}).to_string(),
        String::new(),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}).to_string(),
        json!({"jsonrpc": "2.0", "id": 2, "method": "ping"}).to_string(),
    ]
    .join("\n");
    let mut output = Vec::new();
    serve(&INFO, &mut Echo { calls: 0 }, input.as_bytes(), &mut output).expect("served");
    let lines: Vec<Value> = String::from_utf8(output)
        .expect("UTF-8")
        .lines()
        .map(|l| serde_json::from_str(l).expect("one JSON message per line"))
        .collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0]["result"]["protocolVersion"], "2025-03-26");
    assert_eq!(lines[1], json!({"jsonrpc": "2.0", "id": 2, "result": {}}));
}
