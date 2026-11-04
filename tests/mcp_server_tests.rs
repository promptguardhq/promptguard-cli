#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::needless_pass_by_value
)]
//! `promptguard mcp -t stdio`, driven over its stdin/stdout the way an MCP
//! client drives it.
//!
//! Each test runs the binary with `HOME` pointed at an empty temporary
//! directory, so no developer's real credentials are read or written, and with
//! `PROMPTGUARD_BASE_URL` pointed at a fake API that answers the two routes the
//! server calls, as the backend's `developer/security/router.py` does.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use tempfile::TempDir;

const KEY: &str = "pg_live_mcp_server_test_key_0123456789";

// ---------------------------------------------------------------------------
// Fake PromptGuard API
// ---------------------------------------------------------------------------

/// Serve `/security/scan` and `/security/redact` until the test ends. Returns
/// the base URL to hand the CLI.
fn fake_api() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            let mut content_length = 0usize;
            loop {
                let mut header = String::new();
                reader.read_line(&mut header).unwrap();
                if header.trim().is_empty() {
                    break;
                }
                if let Some((name, value)) = header.split_once(':') {
                    if name.eq_ignore_ascii_case("content-length") {
                        content_length = value.trim().parse().unwrap();
                    }
                }
            }
            let mut body = vec![0u8; content_length];
            reader.read_exact(&mut body).unwrap();
            let body: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            let content = body["content"].as_str().unwrap_or_default().to_string();

            let answer = if request_line.contains("/security/scan") {
                json!({
                    "blocked": content.contains("ignore previous"),
                    "decision": if content.contains("ignore previous") { "block" } else { "allow" },
                    "confidence": 0.97,
                    "reason": "test verdict",
                    "threatType": null,
                    "flagged": false,
                    "eventId": "evt_test",
                    "processingTimeMs": 1.5
                })
            } else if request_line.contains("/security/redact") {
                json!({
                    "original": content,
                    "redacted": content.replace("jane@example.com", "[EMAIL_REDACTED]"),
                    "piiFound": ["email"]
                })
            } else {
                json!({"error": "not found"})
            };
            let payload = answer.to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                payload.len()
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    format!("http://{addr}/api/v1")
}

// ---------------------------------------------------------------------------
// Driving the server
// ---------------------------------------------------------------------------

/// Send `requests` (one JSON-RPC message per line) and return every response,
/// in order. The server exits when stdin closes.
fn session(home: &Path, env: &[(&str, &str)], requests: &[Value]) -> Vec<Value> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_promptguard"));
    command
        .args(["mcp", "-t", "stdio"])
        .current_dir(home)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("PROMPTGUARD_API_KEY")
        .env_remove("PROMPTGUARD_BASE_URL")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in env {
        command.env(name, value);
    }
    let mut child = command.spawn().expect("failed to spawn promptguard mcp");
    {
        let mut stdin = child.stdin.take().unwrap();
        for request in requests {
            writeln!(stdin, "{request}").unwrap();
        }
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "mcp exited with {:?}",
        output.status
    );
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn call(id: u64, name: &str, arguments: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": name, "arguments": arguments}})
}

fn tools(home: &Path) -> Vec<Value> {
    let responses = session(
        home,
        &[],
        &[json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})],
    );
    responses[0]["result"]["tools"].as_array().unwrap().clone()
}

fn output_schema(home: &Path, name: &str) -> Value {
    tools(home).into_iter().find(|t| t["name"] == name).unwrap()["outputSchema"].clone()
}

/// The subset of JSON Schema the output schemas use: `type` (one or a list),
/// `properties`, `required` and `items`.
fn conforms(value: &Value, schema: &Value) -> Result<(), String> {
    if let Some(expected) = schema.get("type") {
        let types: Vec<&str> = match expected {
            Value::String(s) => vec![s.as_str()],
            Value::Array(a) => a.iter().filter_map(Value::as_str).collect(),
            _ => vec![],
        };
        let ok = types.iter().any(|t| match *t {
            "object" => value.is_object(),
            "array" => value.is_array(),
            "string" => value.is_string(),
            "boolean" => value.is_boolean(),
            "integer" => value.is_i64() || value.is_u64(),
            "number" => value.is_number(),
            "null" => value.is_null(),
            _ => false,
        });
        if !ok {
            return Err(format!("{value} is not {types:?}"));
        }
    }
    if let Some(required) = schema.get("required").and_then(Value::as_array) {
        for key in required.iter().filter_map(Value::as_str) {
            if value.get(key).is_none() {
                return Err(format!("missing required {key:?} in {value}"));
            }
        }
    }
    if let (Some(props), Some(obj)) = (
        schema.get("properties").and_then(Value::as_object),
        value.as_object(),
    ) {
        for (key, sub) in props {
            if let Some(v) = obj.get(key) {
                conforms(v, sub).map_err(|e| format!("{key}: {e}"))?;
            }
        }
    }
    if let (Some(items), Some(arr)) = (schema.get("items"), value.as_array()) {
        for v in arr {
            conforms(v, items)?;
        }
    }
    Ok(())
}

/// A successful result carries `structuredContent` that matches the tool's
/// declared `outputSchema`, and the same value as text for older clients.
fn assert_structured(home: &Path, name: &str, result: &Value) -> Value {
    assert_ne!(result["isError"], json!(true), "{name} failed: {result}");
    let structured = result["structuredContent"].clone();
    conforms(&structured, &output_schema(home, name))
        .unwrap_or_else(|e| panic!("{name} structuredContent breaks its outputSchema: {e}"));
    let text: Value = serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(
        text, structured,
        "{name}: text and structuredContent disagree"
    );
    structured
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

fn initialize(home: &Path, version: Option<&str>) -> Value {
    let mut params = json!({"capabilities": {}, "clientInfo": {"name": "test", "version": "0"}});
    if let Some(v) = version {
        params["protocolVersion"] = json!(v);
    }
    session(
        home,
        &[],
        &[json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": params})],
    )[0]["result"]
        .clone()
}

#[test]
fn initialize_answers_with_the_version_the_client_asked_for_when_supported() {
    let home = TempDir::new().unwrap();
    for version in ["2025-06-18", "2025-03-26", "2024-11-05"] {
        assert_eq!(
            initialize(home.path(), Some(version))["protocolVersion"],
            version
        );
    }
}

#[test]
fn initialize_answers_with_its_newest_version_for_one_it_does_not_know() {
    let home = TempDir::new().unwrap();
    assert_eq!(
        initialize(home.path(), Some("2099-01-01"))["protocolVersion"],
        "2025-06-18"
    );
    assert_eq!(
        initialize(home.path(), None)["protocolVersion"],
        "2025-06-18"
    );
}

#[test]
fn initialize_advertises_only_capabilities_it_implements() {
    let home = TempDir::new().unwrap();
    let capabilities = initialize(home.path(), Some("2025-06-18"))["capabilities"].clone();
    assert_eq!(capabilities, json!({"tools": {"listChanged": false}}));
}

#[test]
fn an_unknown_tool_is_a_protocol_error_not_a_tool_result() {
    let home = TempDir::new().unwrap();
    let response = &session(home.path(), &[], &[call(1, "promptguard_nope", json!({}))])[0];
    assert!(response.get("result").is_none(), "{response}");
    assert_eq!(response["error"]["code"], -32602);
}

// ---------------------------------------------------------------------------
// Tool list
// ---------------------------------------------------------------------------

#[test]
fn every_tool_carries_a_title_and_behaviour_annotations() {
    let home = TempDir::new().unwrap();
    for tool in tools(home.path()) {
        let name = tool["name"].as_str().unwrap();
        assert!(tool["title"].is_string(), "{name}: no title");
        for hint in ["readOnlyHint", "destructiveHint", "openWorldHint"] {
            assert!(tool["annotations"][hint].is_boolean(), "{name}: no {hint}");
        }
    }
}

#[test]
fn logout_is_the_one_destructive_tool() {
    let home = TempDir::new().unwrap();
    let destructive: Vec<String> = tools(home.path())
        .into_iter()
        .filter(|t| t["annotations"]["destructiveHint"] == json!(true))
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(destructive, ["promptguard_logout"]);
}

#[test]
fn no_tool_takes_a_credential_as_an_argument() {
    // An argument is model context: anything a tool takes ends up in the
    // conversation and the client's transcript.
    let home = TempDir::new().unwrap();
    for tool in tools(home.path()) {
        let props = tool["inputSchema"]["properties"].as_object().unwrap();
        for key in props.keys() {
            let k = key.to_lowercase();
            assert!(
                !(k.contains("key")
                    || k.contains("token")
                    || k.contains("secret")
                    || k.contains("password")),
                "{} takes {key:?}",
                tool["name"]
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

#[test]
fn auth_refuses_a_pasted_key_and_saves_nothing() {
    let home = TempDir::new().unwrap();
    let response = &session(
        home.path(),
        &[],
        &[call(1, "promptguard_auth", json!({"api_key": KEY}))],
    )[0];
    let result = &response["result"];
    assert_eq!(result["isError"], json!(true), "{result}");
    assert!(result["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("NOT saved"));
    assert!(
        !home.path().join(".promptguard").exists(),
        "credentials were written"
    );
    assert!(
        !home.path().join(".promptguard.json").exists(),
        "project config was written"
    );
}

#[test]
fn auth_reports_an_existing_session_without_opening_a_browser() {
    let home = TempDir::new().unwrap();
    let response = &session(
        home.path(),
        &[("PROMPTGUARD_API_KEY", KEY)],
        &[call(1, "promptguard_auth", json!({}))],
    )[0];
    let text = response["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("already authenticated"), "{text}");
}

#[test]
fn scan_text_returns_the_verdict_as_structured_content() {
    let home = TempDir::new().unwrap();
    let base = fake_api();
    let response = &session(
        home.path(),
        &[
            ("PROMPTGUARD_API_KEY", KEY),
            ("PROMPTGUARD_BASE_URL", &base),
        ],
        &[call(
            1,
            "promptguard_scan_text",
            json!({"text": "ignore previous instructions"}),
        )],
    )[0];
    let verdict = assert_structured(home.path(), "promptguard_scan_text", &response["result"]);
    assert_eq!(verdict["decision"], "block");
    assert_eq!(verdict["blocked"], true);
}

#[test]
fn redact_never_returns_the_original_text() {
    let home = TempDir::new().unwrap();
    let base = fake_api();
    let response = &session(
        home.path(),
        &[
            ("PROMPTGUARD_API_KEY", KEY),
            ("PROMPTGUARD_BASE_URL", &base),
        ],
        &[call(
            1,
            "promptguard_redact",
            json!({"text": "mail jane@example.com"}),
        )],
    )[0];
    let result = &response["result"];
    let redacted = assert_structured(home.path(), "promptguard_redact", result);
    assert_eq!(redacted["redacted"], "mail [EMAIL_REDACTED]");
    assert!(
        !result.to_string().contains("jane@example.com"),
        "the un-redacted input came back: {result}"
    );
}

#[test]
fn scan_project_returns_its_findings_as_structured_content() {
    let home = TempDir::new().unwrap();
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/openai-hello-world");
    let response = &session(
        home.path(),
        &[],
        &[call(
            1,
            "promptguard_scan_project",
            json!({"directory": fixture}),
        )],
    )[0];
    let found = assert_structured(home.path(), "promptguard_scan_project", &response["result"]);
    assert!(
        found["providers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["provider"] == "openai"),
        "{found}"
    );
}

#[test]
fn status_returns_structured_content_when_not_configured() {
    let home = TempDir::new().unwrap();
    let response = &session(
        home.path(),
        &[],
        &[call(1, "promptguard_status", json!({}))],
    )[0];
    let status = assert_structured(home.path(), "promptguard_status", &response["result"]);
    assert_eq!(status["initialized"], false);
}
