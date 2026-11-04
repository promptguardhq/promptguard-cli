#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! The tools `promptguard mcp` serves against the published tool manifest.
//!
//! `tests/mcp-tool-definitions.json` is a byte copy of the platform repo's
//! `mcp-server/tool-definitions.json`, which the platform generates from its
//! hosted MCP server. Its `shared_tools` belong to the platform and
//! `cli_only_tools` to this repo; the platform's
//! `scripts/utils/check_mcp_tool_manifest.py` compares the two files byte for
//! byte. A tool both servers serve must look the same in both, so this test
//! fails when the CLI drifts from the manifest. To change a shared tool,
//! change the hosted server, regenerate the platform manifest and copy it
//! here; to change a CLI-only tool, change `src/commands/mcp.rs` and its
//! `cli_only_tools` entry together, and copy that entry back to the platform.

use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::io::Write;
use std::process::{Command, Stdio};
use tempfile::TempDir;

const FIELDS: [&str; 4] = ["title", "description", "inputSchema", "annotations"];

fn manifest() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/mcp-tool-definitions.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn served_tools() -> Vec<Value> {
    let home = TempDir::new().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_promptguard"))
        .args(["mcp", "-t", "stdio"])
        .current_dir(home.path())
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .env_remove("PROMPTGUARD_API_KEY")
        .env_remove("PROMPTGUARD_BASE_URL")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(
        child.stdin.take().unwrap(),
        "{}",
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    )
    .unwrap();
    let output = child.wait_with_output().unwrap();
    let response: Value =
        serde_json::from_str(String::from_utf8(output.stdout).unwrap().trim()).unwrap();
    response["result"]["tools"].as_array().unwrap().clone()
}

fn entries<'a>(manifest: &'a Value, section: &str) -> &'a Vec<Value> {
    manifest[section]
        .as_array()
        .unwrap_or_else(|| panic!("manifest has no {section} array"))
}

fn names(tools: &[Value]) -> BTreeSet<String> {
    tools
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn the_served_tools_are_the_shared_and_cli_only_tools_of_the_manifest() {
    let manifest = manifest();
    let mut expected = names(entries(&manifest, "shared_tools"));
    expected.extend(names(entries(&manifest, "cli_only_tools")));
    assert_eq!(names(&served_tools()), expected);
}

#[test]
fn every_served_tool_matches_its_manifest_entry_exactly() {
    let manifest = manifest();
    let declared: Vec<&Value> = entries(&manifest, "shared_tools")
        .iter()
        .chain(entries(&manifest, "cli_only_tools"))
        .collect();
    for tool in served_tools() {
        let name = tool["name"].as_str().unwrap();
        let entry = declared
            .iter()
            .find(|e| e["name"] == name)
            .unwrap_or_else(|| panic!("{name} is served but not in the manifest"));
        for field in FIELDS {
            assert!(
                entry.get(field).is_some(),
                "the manifest entry for {name} has no {field}"
            );
            assert_eq!(
                tool[field], entry[field],
                "{name}.{field} differs from tests/mcp-tool-definitions.json"
            );
        }
    }
}
