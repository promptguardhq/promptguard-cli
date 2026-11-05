//! `promptguard mcp install`: add `PromptGuard`'s MCP server to every AI client
//! on the machine.
//!
//! Two kinds of client. Claude Code and Codex are configured through their own
//! CLIs (`claude mcp add`, `codex mcp add`), so the client owns its file
//! format. Cursor, VS Code, Windsurf and (for the local server) Claude Desktop
//! are configured by editing a JSON file, and that edit is the part a security
//! vendor's installer must get right:
//!
//! - The file is never replaced wholesale. The new entry is spliced into the
//!   original text, so every other entry, the key order, the indentation and
//!   anything else in the file stay byte-for-byte as they were.
//! - The write is atomic (a temp file in the same directory, then a rename),
//!   and the first time a file is changed its original is kept as `<file>.bak`.
//! - An existing `promptguard` entry that points elsewhere is left alone
//!   unless `--force`, and a file that does not parse is reported and left
//!   alone.
//! - Nothing secret is written: the hosted server signs in through the client
//!   (OAuth), and the local server reads the key `promptguard login` stored.

use crate::error::{PromptGuardError, Result};
use clap::ValueEnum;
use serde_json::Value;
use std::ffi::OsString;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// `PromptGuard`'s hosted MCP server (streamable HTTP).
pub const HOSTED_MCP_URL: &str = "https://api.promptguard.co/mcp";

/// The server's name in every client's configuration.
const SERVER_NAME: &str = "promptguard";

/// The arguments that start the local stdio server.
const LOCAL_ARGS: [&str; 3] = ["mcp", "-t", "stdio"];

const SIGN_IN_LINE: &str = "Sign in when your client asks: each client opens PromptGuard's \
                            sign-in the first time a tool needs your account.";

const LOCAL_SIGN_IN_LINE: &str = "The local server uses the API key stored by \
                                  `promptguard login`; run it first if you have not.";

/// An AI client `mcp install` knows how to configure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum McpClient {
    ClaudeCode,
    Codex,
    Cursor,
    #[value(name = "vscode")]
    VsCode,
    Windsurf,
    ClaudeDesktop,
}

impl McpClient {
    const ALL: [Self; 6] = [
        Self::ClaudeCode,
        Self::Codex,
        Self::Cursor,
        Self::VsCode,
        Self::Windsurf,
        Self::ClaudeDesktop,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::ClaudeCode => "Claude Code",
            Self::Codex => "Codex",
            Self::Cursor => "Cursor",
            Self::VsCode => "VS Code",
            Self::Windsurf => "Windsurf",
            Self::ClaudeDesktop => "Claude Desktop",
        }
    }
}

/// What the server entry points at.
#[derive(Debug, Clone)]
enum Target {
    Hosted(String),
    Local(String),
}

/// What happened to one client.
#[derive(Debug)]
enum Outcome {
    Configured(String),
    AlreadyConfigured,
    NotInstalled,
    NeedsAction(String),
    Failed(String),
}

impl Outcome {
    fn render(&self) -> String {
        match self {
            Self::Configured(how) => how.clone(),
            Self::AlreadyConfigured => "already configured".to_string(),
            Self::NotInstalled => "skipped: not installed".to_string(),
            Self::NeedsAction(what) => format!("needs action: {what}"),
            Self::Failed(why) => format!("failed: {why}"),
        }
    }
}

pub struct McpInstallCommand {
    /// Clients named with `--clients`; empty means every detected client.
    pub clients: Vec<McpClient>,
    pub dry_run: bool,
    pub local: bool,
    pub url: Option<String>,
    pub force: bool,
}

impl McpInstallCommand {
    /// Runs the install and returns the process exit code: 0, or 1 when a
    /// client that was asked for could not be configured.
    pub fn execute(&self) -> Result<i32> {
        let target = self.target()?;
        let home = home_dir()?;
        let named = !self.clients.is_empty();
        let clients: Vec<McpClient> = if named {
            let mut seen = Vec::new();
            for c in &self.clients {
                if !seen.contains(c) {
                    seen.push(*c);
                }
            }
            seen
        } else {
            McpClient::ALL.to_vec()
        };

        match &target {
            Target::Hosted(url) => println!("Adding PromptGuard's MCP server ({url}):"),
            Target::Local(_) => println!("Adding PromptGuard's local MCP server (stdio):"),
        }
        if self.dry_run {
            println!("Dry run: nothing will be changed.");
        }
        println!();

        let mut failed = false;
        for client in clients {
            let outcome = self.install_one(client, &target, &home);
            if matches!(outcome, Outcome::Failed(_))
                || (named && matches!(outcome, Outcome::NotInstalled))
            {
                failed = true;
            }
            println!("  {:<16} {}", client.label(), outcome.render());
        }

        println!();
        match target {
            Target::Hosted(_) => println!("{SIGN_IN_LINE}"),
            Target::Local(_) => println!("{LOCAL_SIGN_IN_LINE}"),
        }
        Ok(i32::from(failed))
    }

    fn target(&self) -> Result<Target> {
        if self.local {
            let exe = std::env::current_exe().map_err(|e| {
                PromptGuardError::Custom(format!("Cannot find the path of this binary: {e}"))
            })?;
            return Ok(Target::Local(exe.to_string_lossy().into_owned()));
        }
        let url = self.url.as_deref().unwrap_or(HOSTED_MCP_URL);
        let parsed = url::Url::parse(url)
            .map_err(|e| PromptGuardError::Config(format!("--url '{url}' is not a URL: {e}")))?;
        if !matches!(parsed.scheme(), "https" | "http") || parsed.host_str().is_none() {
            return Err(PromptGuardError::Config(format!(
                "--url '{url}' must be an http(s) URL"
            )));
        }
        Ok(Target::Hosted(url.to_string()))
    }

    fn install_one(&self, client: McpClient, target: &Target, home: &Path) -> Outcome {
        match client {
            McpClient::ClaudeCode => self.via_cli(&ClaudeCli, target),
            McpClient::Codex => self.via_cli(&CodexCli, target),
            McpClient::Cursor => {
                let dir = home.join(".cursor");
                self.via_file(&dir, &dir.join("mcp.json"), JsonShape::Cursor, target)
            },
            McpClient::VsCode => {
                let dir = vscode_user_dir(home);
                self.via_file(&dir, &dir.join("mcp.json"), JsonShape::VsCode, target)
            },
            McpClient::Windsurf => {
                let dir = home.join(".codeium").join("windsurf");
                self.via_file(
                    &dir,
                    &dir.join("mcp_config.json"),
                    JsonShape::Windsurf,
                    target,
                )
            },
            McpClient::ClaudeDesktop => {
                let dir = claude_desktop_dir(home);
                if !dir.is_dir() {
                    return Outcome::NotInstalled;
                }
                match target {
                    Target::Hosted(url) => Outcome::NeedsAction(format!(
                        "in Settings → Connectors, choose Add custom connector and enter \
                         {url} (Claude Desktop takes remote servers only as connectors)"
                    )),
                    Target::Local(_) => self.via_file(
                        &dir,
                        &dir.join("claude_desktop_config.json"),
                        JsonShape::ClaudeDesktop,
                        target,
                    ),
                }
            },
        }
    }

    // -----------------------------------------------------------------------
    // Clients configured through their own CLI
    // -----------------------------------------------------------------------

    fn via_cli(&self, cli: &dyn ClientCli, target: &Target) -> Outcome {
        let Some(program) = find_on_path(cli.program()) else {
            return Outcome::NotInstalled;
        };

        // `<cli> mcp get promptguard` succeeds only when the server exists.
        let existing = Command::new(&program)
            .args(["mcp", "get", SERVER_NAME])
            .stdin(Stdio::null())
            .output();
        let mut replace = false;
        if let Ok(out) = existing {
            if out.status.success() {
                let shown = String::from_utf8_lossy(&out.stdout);
                if cli_shows_target(&shown, target) {
                    return Outcome::AlreadyConfigured;
                }
                if !self.force {
                    return Outcome::NeedsAction(format!(
                        "a '{SERVER_NAME}' server is already set up in {} with a different \
                         {}; rerun with --force to replace it",
                        cli.label(),
                        target_noun(target)
                    ));
                }
                replace = true;
            }
        }

        let add = cli.add_args(target);
        if self.dry_run {
            let verb = if replace {
                "would replace it: "
            } else {
                "would run: "
            };
            return Outcome::Configured(format!("{verb}{} {}", cli.program(), add.join(" ")));
        }

        if replace {
            // Best effort: a server in another scope is not ours to remove, and
            // `add` reports it if it is still in the way.
            let _ = Command::new(&program)
                .args(cli.remove_args())
                .stdin(Stdio::null())
                .output();
        }

        match cli.run_add(&program, &add) {
            Ok(()) => Outcome::Configured(format!("configured ({} mcp add)", cli.program())),
            Err(why) => Outcome::Failed(why),
        }
    }

    // -----------------------------------------------------------------------
    // Clients configured by editing a JSON file
    // -----------------------------------------------------------------------

    fn via_file(&self, dir: &Path, file: &Path, shape: JsonShape, target: &Target) -> Outcome {
        if !dir.is_dir() {
            return Outcome::NotInstalled;
        }
        let shown = display_path(file);

        let original = match fs::read(file) {
            Ok(bytes) => Some(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Outcome::Failed(format!("cannot read {shown}: {}", e.kind())),
        };
        let text = match &original {
            None => String::new(),
            Some(bytes) => match String::from_utf8(bytes.clone()) {
                Ok(t) => t,
                Err(_) => {
                    return Outcome::Failed(format!("{shown} is not valid JSON; left it alone"))
                },
            },
        };

        let entry = shape.entry(target);
        let plan = match plan_edit(&text, &entry, shape, target, self.force) {
            Ok(plan) => plan,
            Err(EditError::Invalid(why)) => {
                return Outcome::Failed(format!("{shown} {why}; left it alone"))
            },
        };

        let new_text = match plan {
            Plan::Unchanged => return Outcome::AlreadyConfigured,
            Plan::Conflict(existing) => {
                return Outcome::NeedsAction(format!(
                    "{shown} already has a '{SERVER_NAME}' server ({existing}); rerun with \
                     --force to replace it"
                ))
            },
            Plan::Write(text) => text,
        };

        if self.dry_run {
            let verb = if original.is_none() {
                "would create"
            } else {
                "would update"
            };
            return Outcome::Configured(format!("{verb} {shown}"));
        }

        if let Some(bytes) = &original {
            let backup = with_suffix(file, ".bak");
            if !backup.exists() {
                if let Err(e) = fs::write(&backup, bytes) {
                    return Outcome::Failed(format!(
                        "cannot back up {shown}: {}; left it alone",
                        e.kind()
                    ));
                }
            }
        }

        match write_atomic(file, new_text.as_bytes()) {
            Ok(()) => Outcome::Configured(format!("configured ({shown})")),
            Err(e) => Outcome::Failed(format!("cannot write {shown}: {}", e.kind())),
        }
    }
}

// ---------------------------------------------------------------------------
// CLI-configured clients
// ---------------------------------------------------------------------------

trait ClientCli {
    fn program(&self) -> &'static str;
    fn label(&self) -> &'static str;
    fn add_args(&self, target: &Target) -> Vec<String>;
    fn remove_args(&self) -> Vec<String>;
    fn run_add(&self, program: &Path, args: &[String]) -> std::result::Result<(), String>;
}

struct ClaudeCli;

impl ClientCli for ClaudeCli {
    fn program(&self) -> &'static str {
        "claude"
    }

    fn label(&self) -> &'static str {
        "Claude Code"
    }

    fn add_args(&self, target: &Target) -> Vec<String> {
        let mut args: Vec<String> = vec!["mcp".into(), "add".into()];
        match target {
            Target::Hosted(url) => {
                args.extend(
                    ["--transport", "http", "--scope", "user", SERVER_NAME, url]
                        .map(str::to_string),
                );
            },
            Target::Local(exe) => {
                args.extend(["--scope", "user", SERVER_NAME, "--", exe].map(str::to_string));
                args.extend(LOCAL_ARGS.map(str::to_string));
            },
        }
        args
    }

    fn remove_args(&self) -> Vec<String> {
        ["mcp", "remove", SERVER_NAME, "--scope", "user"]
            .map(str::to_string)
            .to_vec()
    }

    fn run_add(&self, program: &Path, args: &[String]) -> std::result::Result<(), String> {
        let out = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| format!("cannot run claude: {}", e.kind()))?;
        if out.status.success() {
            return Ok(());
        }
        Err(format!(
            "`claude mcp add` exited with {}: {}",
            out.status,
            first_line(&out.stderr)
                .or_else(|| first_line(&out.stdout))
                .unwrap_or_default()
        ))
    }
}

struct CodexCli;

impl ClientCli for CodexCli {
    fn program(&self) -> &'static str {
        "codex"
    }

    fn label(&self) -> &'static str {
        "Codex"
    }

    fn add_args(&self, target: &Target) -> Vec<String> {
        let mut args: Vec<String> = vec!["mcp".into(), "add".into(), SERVER_NAME.into()];
        match target {
            Target::Hosted(url) => args.extend(["--url".to_string(), url.clone()]),
            Target::Local(exe) => {
                args.extend(["--".to_string(), exe.clone()]);
                args.extend(LOCAL_ARGS.map(str::to_string));
            },
        }
        args
    }

    fn remove_args(&self) -> Vec<String> {
        ["mcp", "remove", SERVER_NAME].map(str::to_string).to_vec()
    }

    /// `codex mcp add` starts the server's OAuth sign-in itself when the server
    /// advertises one, so it gets the terminal instead of a pipe.
    fn run_add(&self, program: &Path, args: &[String]) -> std::result::Result<(), String> {
        let status = Command::new(program)
            .args(args)
            .status()
            .map_err(|e| format!("cannot run codex: {}", e.kind()))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!(
                "`codex mcp add` exited with {status} (its output is above)"
            ))
        }
    }
}

/// Whether `<cli> mcp get promptguard` output shows the server pointing at
/// `target`: the URL as a whole word, or the local binary with its arguments.
fn cli_shows_target(shown: &str, target: &Target) -> bool {
    let words: Vec<&str> = shown.split_whitespace().collect();
    match target {
        Target::Hosted(url) => words
            .iter()
            .any(|w| w.trim_end_matches('/') == url.trim_end_matches('/')),
        Target::Local(exe) => {
            words.iter().any(|w| *w == exe || is_promptguard_command(w))
                && LOCAL_ARGS.iter().all(|a| words.contains(a))
        },
    }
}

fn target_noun(target: &Target) -> &'static str {
    match target {
        Target::Hosted(_) => "URL",
        Target::Local(_) => "command",
    }
}

fn first_line(bytes: &[u8]) -> Option<String> {
    String::from_utf8_lossy(bytes)
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .map(str::to_owned)
}

// ---------------------------------------------------------------------------
// JSON-configured clients
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
enum JsonShape {
    Cursor,
    VsCode,
    Windsurf,
    ClaudeDesktop,
}

/// A JSON value small enough to render by hand with its keys in a chosen
/// order (`serde_json::Value` sorts them).
enum J {
    Str(String),
    Arr(Vec<String>),
    Obj(Vec<(String, J)>),
}

impl JsonShape {
    fn container(self) -> &'static str {
        match self {
            Self::VsCode => "servers",
            Self::Cursor | Self::Windsurf | Self::ClaudeDesktop => "mcpServers",
        }
    }

    /// The key that holds a remote server's URL.
    fn url_key(self) -> &'static str {
        match self {
            Self::Windsurf => "serverUrl",
            Self::Cursor | Self::VsCode | Self::ClaudeDesktop => "url",
        }
    }

    fn entry(self, target: &Target) -> J {
        let mut fields = Vec::new();
        match target {
            Target::Hosted(url) => {
                if matches!(self, Self::VsCode) {
                    fields.push(("type".to_string(), J::Str("http".to_string())));
                }
                fields.push((self.url_key().to_string(), J::Str(url.clone())));
            },
            Target::Local(exe) => {
                if matches!(self, Self::VsCode) {
                    fields.push(("type".to_string(), J::Str("stdio".to_string())));
                }
                fields.push(("command".to_string(), J::Str(exe.clone())));
                fields.push((
                    "args".to_string(),
                    J::Arr(LOCAL_ARGS.map(str::to_string).to_vec()),
                ));
            },
        }
        J::Obj(fields)
    }

    /// Whether an existing entry already points at `target`. Other fields the
    /// person added (headers, env, disabled flags) do not make it different.
    fn matches(self, existing: &Value, target: &Target) -> bool {
        match target {
            Target::Hosted(url) => existing
                .get(self.url_key())
                .and_then(Value::as_str)
                .is_some_and(|u| u.trim_end_matches('/') == url.trim_end_matches('/')),
            Target::Local(exe) => {
                let command_ok = existing
                    .get("command")
                    .and_then(Value::as_str)
                    .is_some_and(|c| c == exe || is_promptguard_command(c));
                let args_ok = existing
                    .get("args")
                    .and_then(Value::as_array)
                    .is_some_and(|a| {
                        a.iter()
                            .map(Value::as_str)
                            .eq(LOCAL_ARGS.iter().map(|s| Some(*s)))
                    });
                command_ok && args_ok
            },
        }
    }

    fn describe(self, existing: &Value) -> String {
        for key in [self.url_key(), "url", "serverUrl", "command"] {
            if let Some(v) = existing.get(key).and_then(Value::as_str) {
                return v.to_string();
            }
        }
        "a different server".to_string()
    }
}

/// `promptguard` or a path to it, the way the README's manual setup writes it.
fn is_promptguard_command(command: &str) -> bool {
    Path::new(command)
        .file_stem()
        .is_some_and(|s| s == "promptguard")
}

enum Plan {
    Unchanged,
    Conflict(String),
    Write(String),
}

enum EditError {
    Invalid(&'static str),
}

/// Works out the new file text: `text` with the `promptguard` entry added to
/// (or, under `--force`, replaced in) the shape's servers object, and nothing
/// else changed.
fn plan_edit(
    text: &str,
    entry: &J,
    shape: JsonShape,
    target: &Target,
    force: bool,
) -> std::result::Result<Plan, EditError> {
    let container = shape.container();
    if text.trim().is_empty() {
        let doc = J::Obj(vec![(
            container.to_string(),
            J::Obj(vec![(SERVER_NAME.to_string(), clone_j(entry))]),
        )]);
        return Ok(Plan::Write(format!("{}\n", render(&doc, "", "  ", false))));
    }

    // Validate with a real parser first; the span scanner below then only
    // ever walks text that is known to be valid JSON.
    let parsed: Value = serde_json::from_str(text).map_err(|_| {
        EditError::Invalid("is not valid JSON (comments and trailing commas are not supported)")
    })?;
    let Some(root) = parsed.as_object() else {
        return Err(EditError::Invalid("is not a JSON object"));
    };

    let bytes = text.as_bytes();
    let root_open = skip_ws(bytes, 0);
    let root_span = object_span(text, root_open)?;
    let style = Style {
        unit: indent_unit(text, &root_span),
        compact: !text[root_span.open..=root_span.close].contains('\n'),
    };

    let Some(servers) = root.get(container) else {
        // No servers object yet: add one holding our entry.
        let member = J::Obj(vec![(SERVER_NAME.to_string(), clone_j(entry))]);
        let new = insert_member(text, &root_span, container, &member, "", &style);
        return Ok(Plan::Write(new));
    };
    let Some(servers_obj) = servers.as_object() else {
        return Err(EditError::Invalid(
            "has a servers key that is not an object",
        ));
    };
    let container_member = unique_member(&root_span, container)?;
    let container_span = object_span(text, container_member.value_start)?;
    let container_indent = line_indent(text, container_member.key_start);

    let Some(existing) = servers_obj.get(SERVER_NAME) else {
        let new = insert_member(
            text,
            &container_span,
            SERVER_NAME,
            entry,
            &container_indent,
            &style,
        );
        return Ok(Plan::Write(new));
    };

    if shape.matches(existing, target) {
        return Ok(Plan::Unchanged);
    }
    if !force {
        return Ok(Plan::Conflict(shape.describe(existing)));
    }
    let ours = unique_member(&container_span, SERVER_NAME)?;
    let member_indent = line_indent(text, ours.key_start);
    let rendered = render(entry, &member_indent, &style.unit, style.compact);
    let mut new = String::with_capacity(text.len() + rendered.len());
    new.push_str(&text[..ours.value_start]);
    new.push_str(&rendered);
    new.push_str(&text[ours.value_end..]);
    Ok(Plan::Write(new))
}

fn clone_j(j: &J) -> J {
    match j {
        J::Str(s) => J::Str(s.clone()),
        J::Arr(a) => J::Arr(a.clone()),
        J::Obj(o) => J::Obj(o.iter().map(|(k, v)| (k.clone(), clone_j(v))).collect()),
    }
}

/// Renders `j`. Pretty output puts nested lines at `base` plus one `unit` per
/// level; the first line is not indented (it follows a key or a `[`).
fn render(j: &J, base: &str, unit: &str, compact: bool) -> String {
    let quote = |s: &str| serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string());
    match j {
        J::Str(s) => quote(s),
        J::Arr(items) => {
            let parts: Vec<String> = items.iter().map(|s| quote(s)).collect();
            if compact {
                format!("[{}]", parts.join(","))
            } else {
                format!("[{}]", parts.join(", "))
            }
        },
        J::Obj(fields) => {
            if fields.is_empty() {
                return "{}".to_string();
            }
            if compact {
                let parts: Vec<String> = fields
                    .iter()
                    .map(|(k, v)| format!("{}:{}", quote(k), render(v, base, unit, true)))
                    .collect();
                return format!("{{{}}}", parts.join(","));
            }
            let inner = format!("{base}{unit}");
            let parts: Vec<String> = fields
                .iter()
                .map(|(k, v)| format!("{inner}{}: {}", quote(k), render(v, &inner, unit, false)))
                .collect();
            format!("{{\n{}\n{base}}}", parts.join(",\n"))
        },
    }
}

/// How the file lays out JSON: its indentation step, and whether it is all on
/// one line.
struct Style {
    unit: String,
    compact: bool,
}

/// Inserts `"key": value` as the last member of the object at `span`, whose
/// own line is indented `obj_indent`.
fn insert_member(
    text: &str,
    span: &ObjectSpan,
    key: &str,
    value: &J,
    obj_indent: &str,
    style: &Style,
) -> String {
    let quoted = serde_json::to_string(key).unwrap_or_default();
    let Style { unit, compact } = style;
    if let Some(last) = span.members.last() {
        let (before, after) = text.split_at(last.value_end);
        if *compact {
            let rendered = render(value, "", unit, true);
            return format!("{before},{quoted}:{rendered}{after}");
        }
        let member_indent = line_indent(text, last.key_start);
        let rendered = render(value, &member_indent, unit, false);
        return format!("{before},\n{member_indent}{quoted}: {rendered}{after}");
    }
    let before = &text[..=span.open];
    let after = &text[span.close..];
    if *compact {
        let rendered = render(value, "", unit, true);
        return format!("{before}{quoted}:{rendered}{after}");
    }
    let member_indent = format!("{obj_indent}{unit}");
    let rendered = render(value, &member_indent, unit, false);
    format!("{before}\n{member_indent}{quoted}: {rendered}\n{obj_indent}{after}")
}

// --- A span scanner for JSON text already validated by serde_json ----------

struct Member {
    key: String,
    key_start: usize,
    value_start: usize,
    value_end: usize,
}

struct ObjectSpan {
    open: usize,
    close: usize,
    members: Vec<Member>,
}

fn skip_ws(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && matches!(b[i], b' ' | b'\t' | b'\n' | b'\r') {
        i += 1;
    }
    i
}

/// `i` is at an opening quote; returns the index just past the closing one.
fn scan_string(b: &[u8], mut i: usize) -> usize {
    i += 1;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b'"' => return i + 1,
            _ => i += 1,
        }
    }
    i
}

/// `i` is at the first byte of a value; returns the index just past it.
fn scan_value(b: &[u8], i: usize) -> usize {
    match b.get(i) {
        Some(b'"') => scan_string(b, i),
        Some(b'{' | b'[') => {
            let mut depth = 0usize;
            let mut j = i;
            while j < b.len() {
                match b[j] {
                    b'"' => {
                        j = scan_string(b, j);
                        continue;
                    },
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => {
                        depth -= 1;
                        if depth == 0 {
                            return j + 1;
                        }
                    },
                    _ => {},
                }
                j += 1;
            }
            j
        },
        _ => {
            let mut j = i;
            while j < b.len() && !matches!(b[j], b',' | b'}' | b']' | b' ' | b'\t' | b'\n' | b'\r')
            {
                j += 1;
            }
            j
        },
    }
}

fn object_span(text: &str, open: usize) -> std::result::Result<ObjectSpan, EditError> {
    let b = text.as_bytes();
    if b.get(open) != Some(&b'{') {
        return Err(EditError::Invalid("is not a JSON object"));
    }
    let mut members = Vec::new();
    let mut i = skip_ws(b, open + 1);
    loop {
        match b.get(i) {
            Some(b'}') => {
                return Ok(ObjectSpan {
                    open,
                    close: i,
                    members,
                })
            },
            Some(b',') => i = skip_ws(b, i + 1),
            Some(b'"') => {
                let key_start = i;
                let key_end = scan_string(b, i);
                let key: String = serde_json::from_str(&text[key_start..key_end])
                    .map_err(|_| EditError::Invalid("is not valid JSON"))?;
                i = skip_ws(b, key_end);
                if b.get(i) != Some(&b':') {
                    return Err(EditError::Invalid("is not valid JSON"));
                }
                let value_start = skip_ws(b, i + 1);
                let value_end = scan_value(b, value_start);
                members.push(Member {
                    key,
                    key_start,
                    value_start,
                    value_end,
                });
                i = skip_ws(b, value_end);
            },
            _ => return Err(EditError::Invalid("is not valid JSON")),
        }
    }
}

/// The one member named `key`. A key that appears twice is ambiguous (parsers
/// disagree on which wins), so the file is left alone.
fn unique_member<'a>(
    span: &'a ObjectSpan,
    key: &str,
) -> std::result::Result<&'a Member, EditError> {
    let mut found = span.members.iter().filter(|m| m.key == key);
    match (found.next(), found.next()) {
        (Some(m), None) => Ok(m),
        (Some(_), Some(_)) => Err(EditError::Invalid("has a duplicate key")),
        (None, _) => Err(EditError::Invalid("is not valid JSON")),
    }
}

/// The whitespace that starts the line holding `pos`.
fn line_indent(text: &str, pos: usize) -> String {
    let line_start = text[..pos].rfind('\n').map_or(0, |n| n + 1);
    text[line_start..pos]
        .chars()
        .take_while(|c| *c == ' ' || *c == '\t')
        .collect()
}

/// The file's indentation step, from its first top-level member; two spaces
/// when there is none to copy.
fn indent_unit(text: &str, root: &ObjectSpan) -> String {
    root.members
        .first()
        .map(|m| line_indent(text, m.key_start))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "  ".to_string())
}

// ---------------------------------------------------------------------------
// Filesystem
// ---------------------------------------------------------------------------

fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| PromptGuardError::Config("Cannot determine home directory".to_string()))
}

/// VS Code's user directory, where its user-level `mcp.json` lives.
fn vscode_user_dir(home: &Path) -> PathBuf {
    app_config_dir(home).join("Code").join("User")
}

/// Claude Desktop's directory, where `claude_desktop_config.json` lives.
fn claude_desktop_dir(home: &Path) -> PathBuf {
    app_config_dir(home).join("Claude")
}

/// The per-user application config directory: `~/Library/Application Support`
/// on macOS, `%APPDATA%` on Windows, `$XDG_CONFIG_HOME` or `~/.config`
/// elsewhere.
fn app_config_dir(home: &Path) -> PathBuf {
    if cfg!(target_os = "macos") {
        home.join("Library").join("Application Support")
    } else if cfg!(windows) {
        std::env::var_os("APPDATA")
            .map_or_else(|| home.join("AppData").join("Roaming"), PathBuf::from)
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .filter(|v| !v.is_empty())
            .map_or_else(|| home.join(".config"), PathBuf::from)
    }
}

/// `~/…` for paths under the home directory, which reads better in output.
fn display_path(path: &Path) -> String {
    if let Ok(home) = home_dir() {
        if let Ok(rest) = path.strip_prefix(&home) {
            return format!("~/{}", rest.display());
        }
    }
    path.display().to_string()
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name: OsString = path.file_name().unwrap_or_default().to_os_string();
    name.push(suffix);
    path.with_file_name(name)
}

/// Writes `bytes` to a temp file beside `path` and renames it over `path`,
/// so a reader never sees a half-written file. An existing file's permissions
/// are kept.
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = with_suffix(path, &format!(".promptguard-{}.tmp", std::process::id()));
    let result = (|| {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        if let Ok(meta) = fs::metadata(path) {
            fs::set_permissions(&tmp, meta.permissions())?;
        }
        fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// The full path of `program` on `PATH`, if it is there.
fn find_on_path(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let exts: Vec<String> = if cfg!(windows) {
        std::env::var("PATHEXT")
            .unwrap_or_else(|_| ".EXE;.CMD;.BAT;.COM".to_string())
            .split(';')
            .filter(|e| !e.is_empty())
            .map(str::to_string)
            .collect()
    } else {
        vec![String::new()]
    };
    for dir in std::env::split_paths(&path) {
        for ext in &exts {
            let candidate = dir.join(format!("{program}{ext}"));
            if is_executable(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}
