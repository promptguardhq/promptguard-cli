use crate::api::PromptGuardClient;
use crate::config::ConfigManager;
use crate::detector::detect_all_providers;
use crate::error::{PromptGuardError, Result};
use crate::scanner::FileScanner;
use crate::types::{DetectionInstance, Provider};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// JSON-RPC 2.0 types (MCP transport layer)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    #[allow(dead_code)]
    jsonrpc: String,
    id: Option<serde_json::Value>,
    method: String,
    #[serde(default)]
    params: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    id: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
struct JsonRpcError {
    code: i64,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
}

/// JSON-RPC "invalid params": what MCP answers for a `tools/call` naming a
/// tool the server does not have, or for a request missing a required field.
/// An argument the model got wrong is a tool result with `isError` instead,
/// so the model can read it and retry (spec 2025-11-25 and 2026-07-28,
/// server/tools "Error Handling").
const INVALID_PARAMS: i64 = -32602;
const METHOD_NOT_FOUND: i64 = -32601;
const PARSE_ERROR: i64 = -32700;
/// `UnsupportedProtocolVersionError` (spec 2026-07-28, basic "Error Codes"
/// and basic/versioning "Protocol Version Negotiation").
const UNSUPPORTED_PROTOCOL_VERSION: i64 = -32022;

/// A protocol error before it is tied to a request id.
struct ProtocolError {
    code: i64,
    message: String,
    data: Option<serde_json::Value>,
}

impl ProtocolError {
    fn new(code: i64, message: String) -> Self {
        Self {
            code,
            message,
            data: None,
        }
    }
}

impl JsonRpcResponse {
    fn success(id: serde_json::Value, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    fn error(id: serde_json::Value, code: i64, message: String) -> Self {
        Self::failure(id, ProtocolError::new(code, message))
    }

    fn failure(id: serde_json::Value, error: ProtocolError) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code: error.code,
                message: error.message,
                data: error.data,
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Protocol versions: one dual-era server
// ---------------------------------------------------------------------------
//
// Spec 2026-07-28 (basic/versioning) splits revisions into two eras:
//
// - Modern (2026-07-28 and later): no handshake. Every request names its
//   revision in `_meta["io.modelcontextprotocol/protocolVersion"]`, and the
//   server accepts or rejects each request on its own.
// - Legacy (2025-11-25 and earlier): an `initialize` handshake picks the
//   revision for the life of the stdio process.
//
// This server is "dual-era" in the spec's sense ("Backward Compatibility with
// Initialization-Based Versions"): a request carrying the modern `_meta`
// field is served statelessly under 2026-07-28, and `initialize` selects
// legacy semantics.

/// Stateless revisions this server speaks, newest first.
const MODERN_PROTOCOL_VERSIONS: &[&str] = &["2026-07-28"];

/// Handshake revisions `initialize` can agree on, newest first. `initialize`
/// answers with the client's requested revision when it is one of these, and
/// with the newest otherwise, as the 2025-11-25 lifecycle page asks; the
/// client then decides whether it can continue. The same answers serve every
/// entry: `structuredContent` and `outputSchema` arrived in 2025-06-18, and an
/// older client ignores fields it does not know. 2025-11-25 adds nothing a
/// tools-only stdio server must do: `icons`, `Implementation.description` and
/// tasks are optional, and its one tools change (input validation errors are
/// tool results) is how this server already reports them.
const HANDSHAKE_PROTOCOL_VERSIONS: &[&str] =
    &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

/// Every revision this server speaks, newest first: what `server/discover`
/// and `UnsupportedProtocolVersionError` list.
fn supported_protocol_versions() -> Vec<&'static str> {
    MODERN_PROTOCOL_VERSIONS
        .iter()
        .chain(HANDSHAKE_PROTOCOL_VERSIONS)
        .copied()
        .collect()
}

/// Reserved `_meta` keys (spec 2026-07-28, basic "`_meta`").
const META_PROTOCOL_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
const META_CLIENT_CAPABILITIES: &str = "io.modelcontextprotocol/clientCapabilities";
const META_SERVER_INFO: &str = "io.modelcontextprotocol/serverInfo";

/// How long a client may treat `tools/list` and `server/discover` as fresh
/// (spec 2026-07-28, server/utilities/caching). Both are compiled into the
/// binary and only change with an upgrade, which restarts the process.
const CACHE_TTL_MS: u64 = 3_600_000;

fn negotiate_protocol_version(params: &serde_json::Value) -> &'static str {
    let requested = params
        .get("protocolVersion")
        .and_then(serde_json::Value::as_str);
    HANDSHAKE_PROTOCOL_VERSIONS
        .iter()
        .copied()
        .find(|v| Some(*v) == requested)
        .unwrap_or(HANDSHAKE_PROTOCOL_VERSIONS[0])
}

/// Which semantics a request is served under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Era {
    /// No per-request revision, or a handshake revision: served as the
    /// handshake revisions define, as before.
    Legacy,
    /// A stateless revision named in `_meta`.
    Modern,
}

fn server_info() -> serde_json::Value {
    serde_json::json!({
        "name": "promptguard",
        "title": "PromptGuard",
        "version": env!("CARGO_PKG_VERSION"),
    })
}

fn server_capabilities() -> serde_json::Value {
    // Tools only. `logging` used to be advertised with no `logging/setLevel`
    // behind it, so a client that took the capability at its word got
    // "method not found".
    serde_json::json!({ "tools": { "listChanged": false } })
}

/// Read the era from the request's `_meta`.
///
/// - No `io.modelcontextprotocol/protocolVersion`: legacy, as every request
///   from a handshake client is.
/// - A stateless revision this server speaks: modern, once the other
///   required field, `io.modelcontextprotocol/clientCapabilities`, is there.
///   A request missing it is malformed and gets `-32602` (spec 2026-07-28,
///   basic "`_meta`", per-request protocol fields).
/// - A handshake revision: legacy. Those revisions define no per-request
///   version, so this is the conservative reading: serve it as a handshake
///   server would, which ignores `_meta`. Rejecting it would contradict the
///   `supported` list, which names it.
/// - Anything else: `UnsupportedProtocolVersionError` listing every revision
///   this server speaks (spec 2026-07-28, basic/versioning "Protocol Version
///   Negotiation": "MUST respond with an `UnsupportedProtocolVersionError`").
fn request_era(params: &serde_json::Value) -> std::result::Result<Era, ProtocolError> {
    let meta = params.get("_meta");
    let Some(requested) = meta.and_then(|m| m.get(META_PROTOCOL_VERSION)) else {
        return Ok(Era::Legacy);
    };
    let Some(requested) = requested.as_str() else {
        return Err(ProtocolError::new(
            INVALID_PARAMS,
            format!("_meta[\"{META_PROTOCOL_VERSION}\"] must be a string"),
        ));
    };
    if MODERN_PROTOCOL_VERSIONS.contains(&requested) {
        let has_capabilities = meta
            .and_then(|m| m.get(META_CLIENT_CAPABILITIES))
            .is_some_and(serde_json::Value::is_object);
        if !has_capabilities {
            return Err(ProtocolError::new(
                INVALID_PARAMS,
                format!("Missing required _meta[\"{META_CLIENT_CAPABILITIES}\"] object"),
            ));
        }
        return Ok(Era::Modern);
    }
    if HANDSHAKE_PROTOCOL_VERSIONS.contains(&requested) {
        return Ok(Era::Legacy);
    }
    Err(ProtocolError {
        code: UNSUPPORTED_PROTOCOL_VERSION,
        message: "Unsupported protocol version".to_string(),
        data: Some(serde_json::json!({
            "supported": supported_protocol_versions(),
            "requested": requested,
        })),
    })
}

// ---------------------------------------------------------------------------
// MCP tool definitions
// ---------------------------------------------------------------------------

/// Where `promptguard_auth` sends the user for a key.
const API_KEYS_URL: &str = "https://app.promptguard.co/settings/api-keys";

fn scan_output_schema() -> serde_json::Value {
    // The `/security/scan` response (backend `developer/security/router.py`,
    // `ScanResponse`). Only the fields every server version sends are
    // required; newer fields are allowed through.
    serde_json::json!({
        "type": "object",
        "properties": {
            "blocked": {"type": "boolean"},
            "decision": {"type": "string"},
            "confidence": {"type": "number"},
            "reason": {"type": "string"},
            "threatType": {"type": ["string", "null"]},
            "flagged": {"type": "boolean"},
            "eventId": {"type": ["string", "null"]},
            "processingTimeMs": {"type": ["number", "null"]}
        },
        "required": ["blocked", "decision", "confidence", "reason"]
    })
}

fn redact_output_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "redacted": {"type": "string"},
            "piiFound": {"type": "array", "items": {"type": "string"}}
        },
        "required": ["redacted", "piiFound"]
    })
}

fn scan_project_output_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "summary": {"type": "string"},
            "files_scanned": {"type": "integer"},
            "providers": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "provider": {"type": "string"},
                        "count": {"type": "integer"},
                        "instances": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "file": {"type": "string"},
                                    "line": {"type": "integer"},
                                    "column": {"type": "integer"},
                                    "has_base_url": {"type": "boolean"}
                                },
                                "required": ["file", "line", "column", "has_base_url"]
                            }
                        }
                    },
                    "required": ["provider", "count", "instances"]
                }
            }
        },
        "required": ["summary", "files_scanned", "providers"]
    })
}

fn status_output_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "initialized": {"type": "boolean"},
            "api_key_type": {"type": "string"},
            "proxy_url": {"type": "string"},
            "providers": {"type": "array", "items": {"type": "string"}},
            "version": {"type": "string"},
            "message": {"type": "string"}
        },
        "required": ["initialized", "version"]
    })
}

/// The tools `tools/list` serves, in a fixed order (spec 2026-07-28,
/// server/tools asks for a deterministic one).
///
/// The three tools the hosted server also serves (`scan_text`, `redact`,
/// `status`) carry the platform's `title`, `description`, `inputSchema` and
/// `annotations` exactly: `tests/mcp-tool-definitions.json` is a byte copy of
/// the platform's published manifest, and `tests/mcp_tool_manifest_tests.rs`
/// fails on any drift. Change a shared tool in the platform first.
fn tool_definitions() -> serde_json::Value {
    serde_json::json!([
            {
                "name": "promptguard_auth",
                "title": "Connect PromptGuard",
                "description": "Check whether PromptGuard is authenticated, and if not, open the PromptGuard dashboard so the user can create an API key. This tool never takes the key itself: the user saves it outside the chat, by running `promptguard login` in a terminal or by setting PROMPTGUARD_API_KEY in this MCP server's configuration. Never ask the user to paste an API key into the conversation.\nWhen to use: When any other promptguard tool reports that the user is not authenticated or not initialized, or when the user asks to log in to PromptGuard.",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "additionalProperties": false
                },
                "annotations": {
                    "readOnlyHint": true,
                    "destructiveHint": false,
                    "idempotentHint": true,
                    "openWorldHint": false
                }
            },
            {
                "name": "promptguard_logout",
                "title": "Log out of PromptGuard",
                "description": "Log out of PromptGuard by removing the project-local configuration (.promptguard.json) and the globally stored API key (~/.promptguard/credentials.json).\nWhen to use: When the user wants to switch PromptGuard accounts, clear credentials, or ensure a clean state by removing existing authentication.",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "additionalProperties": false
                },
                "annotations": {
                    "readOnlyHint": false,
                    "destructiveHint": true,
                    "idempotentHint": true,
                    "openWorldHint": false
                }
            },
            {
                "name": "promptguard_scan_text",
                "title": "Scan text for threats",
                "description": "Scan text for security threats including prompt injection, jailbreaks, PII leakage, and toxic content. Returns a decision (allow/block), confidence score, threat type, and reason. Each call counts as one Request on your PromptGuard plan.\nWhen to use: When reviewing user-facing prompts, testing LLM inputs for safety, or verifying that content is free of injection attacks before sending to an LLM.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "text": {
                            "type": "string",
                            "description": "The text content to scan for security threats"
                        },
                        "content_type": {
                            "type": "string",
                            "enum": SCAN_CONTENT_TYPES,
                            "default": "prompt",
                            "description": "Whether the text is a prompt sent to a model or a model's response"
                        }
                    },
                    "required": ["text"],
                    "additionalProperties": false
                },
                "outputSchema": scan_output_schema(),
                "annotations": {
                    "readOnlyHint": true,
                    "destructiveHint": false,
                    "openWorldHint": false
                }
            },
            {
                "name": "promptguard_scan_project",
                "title": "Find unprotected LLM calls",
                "description": "Performs static analysis on a project directory to detect unprotected LLM SDK usage (OpenAI, Anthropic, Cohere, Gemini, Bedrock, etc.). Returns detected providers, file locations (line/column), and instance count.\nWhen to use: During local development to find LLM calls that are not routed through PromptGuard, after generating new code that uses LLM SDKs, or when auditing an existing project for security coverage.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "directory": {
                            "type": "string",
                            "description": "Absolute path to the project directory to scan (defaults to current directory)"
                        },
                        "provider": {
                            "type": "string",
                            "description": "Filter results to a specific provider (e.g. 'openai', 'anthropic')"
                        }
                    },
                    "additionalProperties": false
                },
                "outputSchema": scan_project_output_schema(),
                "annotations": {
                    "readOnlyHint": true,
                    "destructiveHint": false,
                    "idempotentHint": true,
                    "openWorldHint": false
                }
            },
            {
                "name": "promptguard_redact",
                "title": "Redact PII",
                "description": "Redact PII (emails, phone numbers, SSNs, credit cards, API keys) from text. Returns sanitized text with each entity replaced by a labeled placeholder, e.g. [EMAIL_REDACTED], [PHONE_REDACTED], [SSN_REDACTED], and the PII types found. Never returns the original text. Each call counts as one Request on your PromptGuard plan.\nWhen to use: Before including user data in LLM prompts, when processing customer messages, or when building RAG pipelines that ingest documents containing personal information.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "text": {
                            "type": "string",
                            "description": "The text content to redact PII from"
                        }
                    },
                    "required": ["text"],
                    "additionalProperties": false
                },
                "outputSchema": redact_output_schema(),
                "annotations": {
                    "readOnlyHint": true,
                    "destructiveHint": false,
                    "openWorldHint": false
                }
            },
            {
                "name": "promptguard_status",
                "title": "PromptGuard status",
                "description": "Show whether PromptGuard is set up and signed in, with this server's version and the account or configuration details it knows (the hosted server reports your plan; the local CLI server reports its key type, proxy URL and providers).\nWhen to use: To verify PromptGuard is properly configured, or to confirm which version is running.",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "additionalProperties": false
                },
                "outputSchema": status_output_schema(),
                "annotations": {
                    "readOnlyHint": true,
                    "destructiveHint": false,
                    "idempotentHint": true,
                    "openWorldHint": false
                }
            }
    ])
}

/// The `type` values `POST /security/scan` accepts (backend
/// `developer/security/router.py`, `ScanRequest.type`, pattern
/// `^(prompt|response)$`), first the default.
const SCAN_CONTENT_TYPES: [&str; 2] = ["prompt", "response"];

// ---------------------------------------------------------------------------
// Tool results
// ---------------------------------------------------------------------------

/// A successful tool result: the structured value for clients that read
/// `structuredContent`, and the same value as JSON text for those that only
/// read `content` (the spec asks for both).
fn tool_ok(value: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "content": [{"type": "text", "text": serde_json::to_string_pretty(value).unwrap_or_default()}],
        "structuredContent": value
    })
}

/// A plain-text successful result, for tools with no output schema.
fn tool_text(text: &str) -> serde_json::Value {
    serde_json::json!({
        "content": [{"type": "text", "text": text}]
    })
}

/// A tool-execution error the model can read and act on.
fn tool_error(message: &str) -> serde_json::Value {
    serde_json::json!({
        "content": [{"type": "text", "text": message}],
        "isError": true
    })
}

// ---------------------------------------------------------------------------
// Tool handlers
// ---------------------------------------------------------------------------

fn resolve_project_id(config: Option<&crate::config::PromptGuardConfig>) -> Option<String> {
    if let Some(pid) = config.and_then(|c| c.project_id.as_ref()) {
        if !pid.is_empty() {
            return Some(pid.clone());
        }
    }
    if let Ok(Some(creds)) = crate::auth::load_credentials() {
        return creds.active_project;
    }
    None
}

/// POST `body` (plus the resolved `project_id`) to `path` with the session's
/// credentials.
fn post_with_session(path: &str, mut body: serde_json::Value) -> Result<serde_json::Value> {
    // Project config is OPTIONAL here: it only contributes a project_id.
    // Requiring it meant the tool failed with "not initialized" even though
    // global credentials were perfectly sufficient.
    let config = ConfigManager::new(None).ok().and_then(|cm| cm.load().ok());
    // Resolve via the shared precedence (env > project > global) and the
    // key-exfiltration guard rather than reading project config directly.
    let (api_key, base_url) = crate::auth::resolve_session()?;
    let client = PromptGuardClient::new(api_key, Some(base_url))?;
    if let Some(pid) = resolve_project_id(config.as_ref()) {
        body["project_id"] = serde_json::Value::String(pid);
    }
    client.post(path, &body)
}

fn required_text(params: &serde_json::Value) -> std::result::Result<String, serde_json::Value> {
    params
        .get("text")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| tool_error("Error: 'text' parameter is required"))
}

fn handle_scan_text(params: &serde_json::Value) -> serde_json::Value {
    let text = match required_text(params) {
        Ok(t) => t,
        Err(e) => return e,
    };
    // An invalid value is an input validation error, so a tool result the
    // model can correct, not a protocol error (spec 2025-11-25, server/tools
    // "Error Handling").
    let content_type = match params.get("content_type") {
        None => SCAN_CONTENT_TYPES[0],
        Some(value) => match SCAN_CONTENT_TYPES
            .iter()
            .find(|t| value.as_str() == Some(**t))
        {
            Some(t) => t,
            None => {
                return tool_error(&format!(
                    "Error: 'content_type' must be \"prompt\" or \"response\", got {value}"
                ))
            },
        },
    };
    match post_with_session(
        "/security/scan",
        serde_json::json!({ "content": text, "type": content_type }),
    ) {
        Ok(response) => tool_ok(&response),
        Err(e) => tool_error(&format!("Error: {e}")),
    }
}

fn handle_scan_project(params: &serde_json::Value) -> serde_json::Value {
    let dir = params
        .get("directory")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(".");
    let provider_filter = params
        .get("provider")
        .and_then(serde_json::Value::as_str)
        .map(std::string::ToString::to_string);

    let root_path = PathBuf::from(dir);
    let scanner = match FileScanner::new(&root_path, None) {
        Ok(s) => s,
        Err(e) => return tool_error(&format!("Error creating scanner: {e}")),
    };
    let files = match scanner.scan_files(None) {
        Ok(f) => f,
        Err(e) => return tool_error(&format!("Error scanning files: {e}")),
    };

    let mut all_detections: HashMap<Provider, Vec<DetectionInstance>> = HashMap::new();

    for file_path in &files {
        if let Ok(results) = detect_all_providers(file_path) {
            for (provider, result) in results {
                if let Some(ref filter) = provider_filter {
                    if provider.as_str() != filter {
                        continue;
                    }
                }
                if !result.instances.is_empty() {
                    all_detections
                        .entry(provider)
                        .or_default()
                        .extend(result.instances);
                }
            }
        }
    }

    let mut results = Vec::new();
    for (provider, instances) in &all_detections {
        let instance_data: Vec<serde_json::Value> = instances
            .iter()
            .map(|inst| {
                serde_json::json!({
                    "file": inst.file_path.strip_prefix(&root_path)
                        .unwrap_or(&inst.file_path)
                        .to_string_lossy(),
                    "line": inst.line,
                    "column": inst.column,
                    "has_base_url": inst.has_base_url,
                })
            })
            .collect();

        results.push(serde_json::json!({
            "provider": provider.as_str(),
            "count": instances.len(),
            "instances": instance_data,
        }));
    }

    let summary = if results.is_empty() {
        "No LLM SDK usage detected in this project.".to_string()
    } else {
        let total: usize = all_detections.values().map(Vec::len).sum();
        format!(
            "Found {} LLM SDK usage(s) across {} provider(s) in {} files scanned.",
            total,
            all_detections.len(),
            files.len()
        )
    };

    tool_ok(&serde_json::json!({
        "summary": summary,
        "files_scanned": files.len(),
        "providers": results,
    }))
}

fn handle_redact(params: &serde_json::Value) -> serde_json::Value {
    let text = match required_text(params) {
        Ok(t) => t,
        Err(e) => return e,
    };
    match post_with_session("/security/redact", serde_json::json!({ "content": text })) {
        // The API echoes the un-redacted input back as `original`. A tool
        // result goes into the model's context and the client's transcript,
        // so returning it would re-introduce the very PII this tool removes.
        // The hosted server drops it for the same reason.
        Ok(response) => match response.get("redacted").and_then(serde_json::Value::as_str) {
            Some(redacted) => tool_ok(&serde_json::json!({
                "redacted": redacted,
                "piiFound": response
                    .get("piiFound")
                    .filter(|v| v.is_array())
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!([])),
            })),
            None => tool_error("Error: the PromptGuard API returned no redacted text"),
        },
        Err(e) => tool_error(&format!("Error: {e}")),
    }
}

fn handle_status(_params: &serde_json::Value) -> serde_json::Value {
    let result = (|| -> Result<serde_json::Value> {
        let config_manager = ConfigManager::new(None)?;
        let config = config_manager.load()?;

        // Report the effective credential/base URL (env > project > global,
        // with the exfiltration guard) rather than the raw project config.
        let (api_key, base_url) = crate::auth::resolve_session()?;

        let key_type = if api_key.starts_with("pg_live_") {
            "live"
        } else {
            "unknown"
        };

        Ok(serde_json::json!({
            "initialized": true,
            "api_key_type": key_type,
            "proxy_url": base_url,
            "providers": config.providers,
            "version": env!("CARGO_PKG_VERSION"),
        }))
    })();

    match result {
        Ok(info) => tool_ok(&info),
        Err(_) => tool_ok(&serde_json::json!({
            "initialized": false,
            "message": "PromptGuard is not configured. Run 'promptguard init' first.",
            "version": env!("CARGO_PKG_VERSION"),
        })),
    }
}

/// `promptguard_auth` used to accept the key as an argument and save it. A
/// tool argument is model context: the key sat in the conversation, the
/// client's transcript and any log of tool calls. A client holding the old
/// schema may still send one, so it is refused without being saved, with a
/// message that says why (rather than the generic unknown-argument one).
fn pasted_key_refusal() -> serde_json::Value {
    tool_error(
        "Refused: this tool no longer accepts an API key, and the key was NOT saved. \
         An API key pasted into a chat ends up in the conversation history. \
         Ask the user to run `promptguard login` in a terminal (or set \
         PROMPTGUARD_API_KEY in this MCP server's configuration), and to revoke \
         the key they shared if it was a real one.",
    )
}

fn handle_auth(_params: &serde_json::Value) -> serde_json::Value {
    if crate::auth::resolve_session().is_ok() {
        return tool_text(
            "PromptGuard is already authenticated. Run `promptguard whoami` in a terminal \
             to see which account, or `promptguard login` to switch keys.",
        );
    }

    let opened = open::that(API_KEYS_URL).is_ok();
    let lead = if opened {
        format!("Opened {API_KEYS_URL} in the browser.")
    } else {
        format!("Open {API_KEYS_URL} in a browser.")
    };
    tool_text(&format!(
        "{lead} PromptGuard is not authenticated yet. Ask the user to copy an API key \
         from that page and save it OUTSIDE this chat, either by running \
         `promptguard login` in a terminal or by setting PROMPTGUARD_API_KEY in this \
         MCP server's configuration. Do not ask them to paste the key here. Call \
         this tool again afterwards to confirm."
    ))
}

fn handle_logout(_params: &serde_json::Value) -> serde_json::Value {
    let result = (|| -> Result<()> {
        // Remove both credential stores, matching the tool description:
        // the project-local config AND the global credentials file.
        let config_manager = ConfigManager::new(None)?;
        config_manager.delete()?;
        crate::auth::delete_credentials()?;
        Ok(())
    })();

    match result {
        Ok(()) => tool_text(
            "Logged out. Removed the project-local PromptGuard configuration (.promptguard.json) and the globally stored API key (~/.promptguard/credentials.json).",
        ),
        Err(e) => tool_error(&format!("Logout failed: {e}")),
    }
}

// ---------------------------------------------------------------------------
// Request dispatch
// ---------------------------------------------------------------------------

/// Run a `tools/call`. A protocol error is a malformed request or an unknown
/// tool; anything the model can fix is a tool result with `isError` (spec
/// 2025-11-25 and 2026-07-28, server/tools "Error Handling").
fn call_tool(params: &serde_json::Value) -> std::result::Result<serde_json::Value, ProtocolError> {
    let tool_name = params
        .get("name")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let arguments = match params.get("arguments") {
        None | Some(serde_json::Value::Null) => serde_json::json!({}),
        Some(a) if a.is_object() => a.clone(),
        Some(_) => {
            return Err(ProtocolError::new(
                INVALID_PARAMS,
                "'arguments' must be an object".to_string(),
            ))
        },
    };
    let definitions = tool_definitions();
    let Some(definition) = definitions
        .as_array()
        .and_then(|tools| tools.iter().find(|t| t["name"] == tool_name))
    else {
        return Err(ProtocolError::new(
            INVALID_PARAMS,
            format!("Unknown tool: {tool_name}"),
        ));
    };

    if tool_name == "promptguard_auth" && arguments.get("api_key").is_some() {
        return Ok(pasted_key_refusal());
    }
    // Every input schema says `additionalProperties: false`; hold the
    // arguments to it, so a misspelt parameter is reported, not ignored.
    let declared = definition["inputSchema"]["properties"].as_object();
    let unknown: Vec<&str> = arguments
        .as_object()
        .into_iter()
        .flat_map(|args| args.keys())
        .filter(|key| !declared.is_some_and(|props| props.contains_key(*key)))
        .map(String::as_str)
        .collect();
    if !unknown.is_empty() {
        return Ok(tool_error(&format!(
            "Error: {tool_name} does not take {}",
            unknown
                .iter()
                .map(|k| format!("'{k}'"))
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }

    Ok(match tool_name {
        "promptguard_scan_text" => handle_scan_text(&arguments),
        "promptguard_scan_project" => handle_scan_project(&arguments),
        "promptguard_redact" => handle_redact(&arguments),
        "promptguard_status" => handle_status(&arguments),
        "promptguard_auth" => handle_auth(&arguments),
        "promptguard_logout" => handle_logout(&arguments),
        _ => {
            return Err(ProtocolError::new(
                INVALID_PARAMS,
                format!("Unknown tool: {tool_name}"),
            ))
        },
    })
}

fn method_not_found(method: &str) -> ProtocolError {
    ProtocolError::new(METHOD_NOT_FOUND, format!("Method not found: {method}"))
}

/// A handshake-era request: served as 2025-11-25 and earlier define.
fn handle_legacy(
    method: &str,
    params: &serde_json::Value,
) -> std::result::Result<serde_json::Value, ProtocolError> {
    match method {
        "initialize" => Ok(serde_json::json!({
            "protocolVersion": negotiate_protocol_version(params),
            "capabilities": server_capabilities(),
            "serverInfo": server_info(),
        })),
        "ping" => Ok(serde_json::json!({})),
        "tools/list" => Ok(serde_json::json!({ "tools": tool_definitions() })),
        "tools/call" => call_tool(params),
        // `server/discover` exists only in the stateless era, whose requests
        // must name their revision: without one the request is malformed
        // (spec 2026-07-28, basic "`_meta`").
        "server/discover" => Err(ProtocolError::new(
            INVALID_PARAMS,
            format!(
                "server/discover needs _meta[\"{META_PROTOCOL_VERSION}\"] set to one of: {}",
                MODERN_PROTOCOL_VERSIONS.join(", ")
            ),
        )),
        _ => Err(method_not_found(method)),
    }
}

/// A stateless-era request (spec 2026-07-28). Every result carries
/// `resultType` (basic "Result Responses": MUST) and the server's identity
/// in `_meta` (basic "`_meta`", per-response fields: SHOULD); the two
/// cacheable results carry `ttlMs` and `cacheScope` (server/utilities/caching:
/// MUST). `ping` and `logging/setLevel` were removed in this revision
/// (changelog, major change 5), so they are unknown methods here.
fn handle_modern(
    method: &str,
    params: &serde_json::Value,
) -> std::result::Result<serde_json::Value, ProtocolError> {
    let mut result = match method {
        "server/discover" => serde_json::json!({
            "supportedVersions": supported_protocol_versions(),
            "capabilities": server_capabilities(),
        }),
        "tools/list" => serde_json::json!({ "tools": tool_definitions() }),
        "tools/call" => call_tool(params)?,
        _ => return Err(method_not_found(method)),
    };
    if matches!(method, "server/discover" | "tools/list") {
        // The same for every caller: no user data, so any cache may share it.
        result["ttlMs"] = serde_json::json!(CACHE_TTL_MS);
        result["cacheScope"] = serde_json::json!("public");
    }
    result["resultType"] = serde_json::json!("complete");
    result["_meta"] = serde_json::json!({ META_SERVER_INFO: server_info() });
    Ok(result)
}

fn handle_request(request: &JsonRpcRequest) -> JsonRpcResponse {
    let id = request.id.clone().unwrap_or(serde_json::Value::Null);

    // Notifications (requests without an id) never reach this function:
    // `execute` drops them before dispatch, as JSON-RPC notifications expect
    // no response.
    //
    // `initialize` always selects handshake semantics: it is how a legacy
    // client opens, and its own `protocolVersion` picks the revision (spec
    // 2026-07-28, basic/versioning: "An initialize request selects legacy
    // semantics").
    let era = if request.method == "initialize" {
        Ok(Era::Legacy)
    } else {
        request_era(&request.params)
    };
    let result = era.and_then(|era| match era {
        Era::Legacy => handle_legacy(&request.method, &request.params),
        Era::Modern => handle_modern(&request.method, &request.params),
    });
    match result {
        Ok(result) => JsonRpcResponse::success(id, result),
        Err(error) => JsonRpcResponse::failure(id, error),
    }
}

// ---------------------------------------------------------------------------
// MCP command entry point
// ---------------------------------------------------------------------------

pub struct McpCommand {
    pub transport: String,
}

impl McpCommand {
    pub fn execute(&self) -> Result<()> {
        if self.transport != "stdio" {
            return Err(PromptGuardError::Custom(format!(
                "Unsupported transport '{}'. Only 'stdio' is supported.",
                self.transport
            )));
        }

        let stdin = io::stdin();
        let mut stdout = io::stdout();

        for line in stdin.lock().lines() {
            let line = line.map_err(PromptGuardError::Io)?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            let request: JsonRpcRequest = match serde_json::from_str(trimmed) {
                Ok(r) => r,
                Err(e) => {
                    let err_response = JsonRpcResponse::error(
                        serde_json::Value::Null,
                        PARSE_ERROR,
                        format!("Parse error: {e}"),
                    );
                    let out = serde_json::to_string(&err_response).unwrap_or_default();
                    writeln!(stdout, "{out}").map_err(|e| {
                        PromptGuardError::Io(io::Error::new(io::ErrorKind::BrokenPipe, e))
                    })?;
                    stdout.flush().map_err(PromptGuardError::Io)?;
                    continue;
                },
            };

            // Notifications have no id and expect no response
            if request.id.is_none() {
                continue;
            }

            let response = handle_request(&request);
            let out = serde_json::to_string(&response).unwrap_or_default();
            writeln!(stdout, "{out}")
                .map_err(|e| PromptGuardError::Io(io::Error::new(io::ErrorKind::BrokenPipe, e)))?;
            stdout.flush().map_err(PromptGuardError::Io)?;
        }

        Ok(())
    }
}
