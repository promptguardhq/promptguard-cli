#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! `promptguard mcp install` adds `PromptGuard`'s MCP server to the AI clients on
//! the machine.
//!
//! Each test runs the binary with `HOME` pointed at an empty temporary
//! directory and `PATH` at a directory of its own, so which clients look
//! "installed" is exactly what the test creates: a client's config directory
//! for the file-based clients, a fake `claude` or `codex` script for the two
//! that are configured through their own CLI. The installer edits other
//! people's config files, so most of these tests are about what it must not
//! do: replace a file, drop or reorder an entry, overwrite a server it did not
//! write, or touch a file it cannot parse.

use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const HOSTED: &str = "https://api.promptguard.co/mcp";

struct Env {
    home: tempfile::TempDir,
    bin: tempfile::TempDir,
}

impl Env {
    fn new() -> Self {
        Self {
            home: tempfile::tempdir().unwrap(),
            bin: tempfile::tempdir().unwrap(),
        }
    }

    fn home(&self) -> &Path {
        self.home.path()
    }

    fn run(&self, args: &[&str]) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_promptguard"));
        cmd.arg("mcp")
            .arg("install")
            .args(args)
            .env_clear()
            .env("HOME", self.home())
            .env("PATH", self.bin.path())
            .env("NO_COLOR", "1")
            .current_dir(self.home());
        cmd.output().unwrap()
    }

    fn cursor_dir(&self) -> PathBuf {
        let dir = self.home().join(".cursor");
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn windsurf_dir(&self) -> PathBuf {
        let dir = self.home().join(".codeium").join("windsurf");
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn vscode_dir(&self) -> PathBuf {
        let dir = if cfg!(target_os = "macos") {
            self.home()
                .join("Library")
                .join("Application Support")
                .join("Code")
                .join("User")
        } else {
            self.home().join(".config").join("Code").join("User")
        };
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn claude_desktop_dir(&self) -> PathBuf {
        let dir = if cfg!(target_os = "macos") {
            self.home()
                .join("Library")
                .join("Application Support")
                .join("Claude")
        } else {
            self.home().join(".config").join("Claude")
        };
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A fake client CLI named `name` on `PATH`. It appends its arguments to
    /// `<name>.log` beside itself. `<name> mcp get ...` prints `<name>.state`
    /// and succeeds when that file exists, and fails as the real CLIs do when
    /// it does not; every other call succeeds. `PATH` holds only the shims, so
    /// the script uses shell builtins alone.
    #[cfg(unix)]
    fn shim(&self, name: &str) {
        use std::os::unix::fs::PermissionsExt;
        let path = self.bin.path().join(name);
        let script = format!(
            "#!/bin/sh\n\
             dir=\"${{0%/*}}\"\n\
             echo \"$*\" >> \"$dir/{name}.log\"\n\
             if [ \"$1\" = mcp ] && [ \"$2\" = get ]; then\n\
             \x20 if [ -f \"$dir/{name}.state\" ]; then while IFS= read -r l; do echo \"$l\"; done < \"$dir/{name}.state\"; exit 0; fi\n\
             \x20 echo \"No MCP server named promptguard\" >&2; exit 1\n\
             fi\n\
             exit 0\n"
        );
        fs::write(&path, script).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[cfg(unix)]
    fn shim_state(&self, name: &str, state: &str) {
        fs::write(self.bin.path().join(format!("{name}.state")), state).unwrap();
    }

    #[cfg(unix)]
    fn shim_log(&self, name: &str) -> Vec<String> {
        fs::read_to_string(self.bin.path().join(format!("{name}.log")))
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn read_json(path: &Path) -> Value {
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

/// The line the installer printed for one client.
fn line_for<'a>(text: &'a str, client: &str) -> &'a str {
    text.lines()
        .find(|l| l.trim_start().starts_with(client))
        .unwrap_or_else(|| panic!("no line for {client} in:\n{text}"))
}

fn bak(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap().to_os_string();
    name.push(".bak");
    path.with_file_name(name)
}

// ---------------------------------------------------------------------------
// File-based clients: merge, never replace
// ---------------------------------------------------------------------------

#[test]
fn cursor_merge_keeps_other_entries_and_key_order() {
    let env = Env::new();
    let file = env.cursor_dir().join("mcp.json");
    let original = r#"{
  "zeta": 1,
  "mcpServers": {
    "other": {
      "command": "other-server",
      "args": ["--flag"]
    }
  },
  "alpha": true
}
"#;
    fs::write(&file, original).unwrap();

    let out = env.run(&["--clients", "cursor"]);
    assert!(out.status.success(), "{}", stdout(&out));
    assert!(line_for(&stdout(&out), "Cursor").contains("configured"));

    let text = fs::read_to_string(&file).unwrap();
    let json: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(json["mcpServers"]["promptguard"]["url"], HOSTED);
    assert_eq!(
        json["mcpServers"]["other"]["command"], "other-server",
        "another server's entry was changed"
    );
    assert_eq!(json["mcpServers"]["other"]["args"][0], "--flag");
    assert_eq!(json["zeta"], 1);
    assert_eq!(json["alpha"], true);

    // Key order is the file's own, not alphabetical.
    let zeta = text.find("\"zeta\"").unwrap();
    let servers = text.find("\"mcpServers\"").unwrap();
    let alpha = text.find("\"alpha\"").unwrap();
    assert!(
        zeta < servers && servers < alpha,
        "key order changed:\n{text}"
    );
    let other = text.find("\"other\"").unwrap();
    let ours = text.find("\"promptguard\"").unwrap();
    assert!(other < ours, "existing server no longer first:\n{text}");

    // The original is kept, byte for byte.
    assert_eq!(fs::read_to_string(bak(&file)).unwrap(), original);
}

#[test]
fn cursor_file_is_created_when_missing_and_needs_no_backup() {
    let env = Env::new();
    let file = env.cursor_dir().join("mcp.json");

    let out = env.run(&["--clients", "cursor"]);
    assert!(out.status.success(), "{}", stdout(&out));
    assert_eq!(read_json(&file)["mcpServers"]["promptguard"]["url"], HOSTED);
    assert!(!bak(&file).exists(), "backed up a file that did not exist");
}

#[test]
fn cursor_adds_the_servers_object_when_the_file_has_none() {
    let env = Env::new();
    let file = env.cursor_dir().join("mcp.json");
    fs::write(&file, "{\n  \"keep\": \"me\"\n}\n").unwrap();

    let out = env.run(&["--clients", "cursor"]);
    assert!(out.status.success(), "{}", stdout(&out));
    let json = read_json(&file);
    assert_eq!(json["keep"], "me");
    assert_eq!(json["mcpServers"]["promptguard"]["url"], HOSTED);
}

#[test]
fn a_one_line_file_stays_one_line_and_other_formatting_is_kept() {
    let env = Env::new();
    let file = env.windsurf_dir().join("mcp_config.json");
    fs::write(
        &file,
        r#"{"mcpServers":{"a":{"serverUrl":"x"}},"z":[1, 2]}"#,
    )
    .unwrap();

    assert!(env.run(&["--clients", "windsurf"]).status.success());
    assert_eq!(
        fs::read_to_string(&file).unwrap(),
        format!(
            r#"{{"mcpServers":{{"a":{{"serverUrl":"x"}},"promptguard":{{"serverUrl":"{HOSTED}"}}}},"z":[1, 2]}}"#
        )
    );
}

#[test]
fn a_duplicate_servers_key_is_left_alone() {
    let env = Env::new();
    let file = env.cursor_dir().join("mcp.json");
    let original = r#"{"mcpServers":{},"mcpServers":{}}"#;
    fs::write(&file, original).unwrap();

    let out = env.run(&["--clients", "cursor"]);
    assert!(!out.status.success());
    assert_eq!(fs::read_to_string(&file).unwrap(), original);
}

#[test]
fn second_run_is_already_configured_and_changes_nothing() {
    let env = Env::new();
    let file = env.cursor_dir().join("mcp.json");
    fs::write(
        &file,
        r#"{"mcpServers":{"other":{"url":"https://x.example/mcp"}}}"#,
    )
    .unwrap();

    assert!(env.run(&["--clients", "cursor"]).status.success());
    let after_first = fs::read(&file).unwrap();
    let bak_first = fs::read(bak(&file)).unwrap();

    let out = env.run(&["--clients", "cursor"]);
    assert!(out.status.success(), "{}", stdout(&out));
    assert!(
        line_for(&stdout(&out), "Cursor").contains("already configured"),
        "{}",
        stdout(&out)
    );
    assert_eq!(fs::read(&file).unwrap(), after_first, "file rewritten");
    assert_eq!(fs::read(bak(&file)).unwrap(), bak_first, "backup rewritten");
}

#[test]
fn a_different_url_is_not_overwritten_without_force() {
    let env = Env::new();
    let file = env.cursor_dir().join("mcp.json");
    let original = r#"{
  "mcpServers": {
    "promptguard": { "url": "https://self-hosted.example/mcp" },
    "other": { "command": "x" }
  }
}
"#;
    fs::write(&file, original).unwrap();

    let out = env.run(&["--clients", "cursor"]);
    let line = line_for(&stdout(&out), "Cursor").to_owned();
    assert!(line.contains("--force"), "{line}");
    assert!(line.contains("https://self-hosted.example/mcp"), "{line}");
    assert_eq!(fs::read_to_string(&file).unwrap(), original, "file changed");
    assert!(!bak(&file).exists());

    let out = env.run(&["--clients", "cursor", "--force"]);
    assert!(out.status.success(), "{}", stdout(&out));
    let json = read_json(&file);
    assert_eq!(json["mcpServers"]["promptguard"]["url"], HOSTED);
    assert_eq!(json["mcpServers"]["other"]["command"], "x");
    assert_eq!(fs::read_to_string(bak(&file)).unwrap(), original);
}

#[test]
fn invalid_json_is_reported_and_left_alone() {
    let env = Env::new();
    let file = env.cursor_dir().join("mcp.json");
    let original = "{ \"mcpServers\": { // a comment\n } }\n";
    fs::write(&file, original).unwrap();

    let out = env.run(&["--clients", "cursor"]);
    assert!(!out.status.success(), "a failed client must fail the run");
    let line = line_for(&stdout(&out), "Cursor").to_owned();
    assert!(line.contains("not valid JSON"), "{line}");
    assert_eq!(fs::read_to_string(&file).unwrap(), original);
    assert!(!bak(&file).exists());
}

#[test]
fn a_servers_key_that_is_not_an_object_is_left_alone() {
    let env = Env::new();
    let file = env.cursor_dir().join("mcp.json");
    let original = r#"{"mcpServers": []}"#;
    fs::write(&file, original).unwrap();

    let out = env.run(&["--clients", "cursor"]);
    assert!(!out.status.success());
    assert_eq!(fs::read_to_string(&file).unwrap(), original);
}

#[test]
fn dry_run_writes_nothing() {
    let env = Env::new();
    let cursor = env.cursor_dir().join("mcp.json");
    let windsurf = env.windsurf_dir().join("mcp_config.json");
    let vscode = env.vscode_dir().join("mcp.json");
    fs::write(&windsurf, r#"{"mcpServers":{}}"#).unwrap();

    let out = env.run(&["--dry-run"]);
    assert!(out.status.success(), "{}", stdout(&out));
    let text = stdout(&out);
    assert!(line_for(&text, "Cursor").contains("would"), "{text}");
    assert!(line_for(&text, "Windsurf").contains("would"), "{text}");
    assert!(line_for(&text, "VS Code").contains("would"), "{text}");
    assert!(!cursor.exists());
    assert!(!vscode.exists());
    assert_eq!(
        fs::read_to_string(&windsurf).unwrap(),
        r#"{"mcpServers":{}}"#
    );
    assert!(!bak(&windsurf).exists());
}

#[test]
fn vscode_uses_servers_with_an_http_type() {
    let env = Env::new();
    let file = env.vscode_dir().join("mcp.json");
    fs::write(&file, "{\n\t\"servers\": {},\n\t\"inputs\": []\n}\n").unwrap();

    let out = env.run(&["--clients", "vscode"]);
    assert!(out.status.success(), "{}", stdout(&out));
    let json = read_json(&file);
    assert_eq!(json["servers"]["promptguard"]["type"], "http");
    assert_eq!(json["servers"]["promptguard"]["url"], HOSTED);
    assert!(json["inputs"].is_array());
}

#[test]
fn windsurf_uses_server_url() {
    let env = Env::new();
    let file = env.windsurf_dir().join("mcp_config.json");

    let out = env.run(&["--clients", "windsurf"]);
    assert!(out.status.success(), "{}", stdout(&out));
    assert_eq!(
        read_json(&file)["mcpServers"]["promptguard"]["serverUrl"],
        HOSTED
    );
}

#[test]
fn url_flag_overrides_the_hosted_server() {
    let env = Env::new();
    let file = env.cursor_dir().join("mcp.json");
    let staging = "https://staging-api.promptguard.co/mcp";

    let out = env.run(&["--clients", "cursor", "--url", staging]);
    assert!(out.status.success(), "{}", stdout(&out));
    assert_eq!(
        read_json(&file)["mcpServers"]["promptguard"]["url"],
        staging
    );
}

#[test]
fn a_url_that_is_not_http_is_refused() {
    let env = Env::new();
    let file = env.cursor_dir().join("mcp.json");
    let out = env.run(&["--clients", "cursor", "--url", "file:///etc/passwd"]);
    assert!(!out.status.success());
    assert!(!file.exists());
}

#[test]
fn local_installs_the_stdio_server() {
    let env = Env::new();
    let file = env.cursor_dir().join("mcp.json");

    let out = env.run(&["--clients", "cursor", "--local"]);
    assert!(out.status.success(), "{}", stdout(&out));
    let entry = &read_json(&file)["mcpServers"]["promptguard"];
    assert!(entry.get("url").is_none());
    let command = entry["command"].as_str().unwrap();
    assert!(
        Path::new(command)
            .file_stem()
            .is_some_and(|s| s == "promptguard"),
        "{command}"
    );
    assert_eq!(entry["args"], serde_json::json!(["mcp", "-t", "stdio"]));

    // Idempotent in local mode too.
    let out = env.run(&["--clients", "cursor", "--local"]);
    assert!(line_for(&stdout(&out), "Cursor").contains("already configured"));
}

#[test]
fn local_and_url_conflict() {
    let env = Env::new();
    let out = env.run(&["--local", "--url", HOSTED]);
    assert!(!out.status.success());
}

#[test]
fn the_written_entry_holds_no_secret() {
    let env = Env::new();
    let file = env.cursor_dir().join("mcp.json");
    // A stored key must not find its way into a client's config.
    let creds = env.home().join(".promptguard");
    fs::create_dir_all(&creds).unwrap();
    fs::write(
        creds.join("credentials.json"),
        r#"{"api_key":"pg_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}"#,
    )
    .unwrap();

    assert!(env.run(&["--clients", "cursor"]).status.success());
    let text = fs::read_to_string(&file).unwrap();
    assert!(!text.contains("pg_live"), "{text}");
    let entry = &read_json(&file)["mcpServers"]["promptguard"];
    assert_eq!(entry.as_object().unwrap().len(), 1, "{entry}");
}

// ---------------------------------------------------------------------------
// Detection and output
// ---------------------------------------------------------------------------

#[test]
fn nothing_installed_is_skipped_and_succeeds() {
    let env = Env::new();
    let out = env.run(&[]);
    assert!(out.status.success(), "{}", stdout(&out));
    let text = stdout(&out);
    for client in [
        "Claude Code",
        "Codex",
        "Cursor",
        "VS Code",
        "Windsurf",
        "Claude Desktop",
    ] {
        assert!(
            line_for(&text, client).contains("skipped: not installed"),
            "{text}"
        );
    }
}

#[test]
fn a_named_client_that_is_not_installed_fails_the_run() {
    let env = Env::new();
    let out = env.run(&["--clients", "cursor"]);
    assert!(!out.status.success());
    assert!(line_for(&stdout(&out), "Cursor").contains("not installed"));
}

#[test]
fn clients_limits_the_run_to_the_named_ones() {
    let env = Env::new();
    let cursor = env.cursor_dir().join("mcp.json");
    let windsurf = env.windsurf_dir().join("mcp_config.json");

    let out = env.run(&["--clients", "windsurf"]);
    assert!(out.status.success(), "{}", stdout(&out));
    assert!(windsurf.exists());
    assert!(!cursor.exists());
    assert!(!stdout(&out).contains("Cursor"), "{}", stdout(&out));
}

#[test]
fn an_unknown_client_name_is_a_usage_error() {
    let env = Env::new();
    let out = env.run(&["--clients", "notepad"]);
    assert!(!out.status.success());
}

#[test]
fn output_ends_with_the_sign_in_line() {
    let env = Env::new();
    env.cursor_dir();
    let out = env.run(&[]);
    assert!(
        stdout(&out).contains(
            "Sign in when your client asks: each client opens PromptGuard's sign-in \
             the first time a tool needs your account."
        ),
        "{}",
        stdout(&out)
    );
}

#[test]
fn claude_desktop_gets_connector_instructions_not_a_file_edit() {
    let env = Env::new();
    let dir = env.claude_desktop_dir();

    let out = env.run(&["--clients", "claude-desktop"]);
    assert!(out.status.success(), "{}", stdout(&out));
    let line = line_for(&stdout(&out), "Claude Desktop").to_owned();
    assert!(line.contains("needs action"), "{line}");
    assert!(line.contains("Connectors"), "{line}");
    assert!(line.contains(HOSTED), "{line}");
    assert!(!dir.join("claude_desktop_config.json").exists());
}

#[test]
fn claude_desktop_local_merges_its_config_file() {
    let env = Env::new();
    let file = env.claude_desktop_dir().join("claude_desktop_config.json");
    fs::write(&file, r#"{"preferences":{"x":1}}"#).unwrap();

    let out = env.run(&["--clients", "claude-desktop", "--local"]);
    assert!(out.status.success(), "{}", stdout(&out));
    let json = read_json(&file);
    assert_eq!(json["preferences"]["x"], 1);
    assert_eq!(
        json["mcpServers"]["promptguard"]["args"],
        serde_json::json!(["mcp", "-t", "stdio"])
    );
}

// ---------------------------------------------------------------------------
// CLI-based clients: Claude Code and Codex
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn claude_code_is_added_at_user_scope_over_http() {
    let env = Env::new();
    env.shim("claude");

    let out = env.run(&["--clients", "claude-code"]);
    assert!(out.status.success(), "{}", stdout(&out));
    assert!(line_for(&stdout(&out), "Claude Code").contains("configured"));
    assert_eq!(
        env.shim_log("claude"),
        vec![
            "mcp get promptguard".to_owned(),
            format!("mcp add --transport http --scope user promptguard {HOSTED}"),
        ]
    );
}

#[cfg(unix)]
#[test]
fn claude_code_already_configured_is_not_added_again() {
    let env = Env::new();
    env.shim("claude");
    env.shim_state(
        "claude",
        &format!("promptguard:\n  Scope: User config\n  Type: http\n  URL: {HOSTED}\n"),
    );

    let out = env.run(&["--clients", "claude-code"]);
    assert!(out.status.success(), "{}", stdout(&out));
    assert!(line_for(&stdout(&out), "Claude Code").contains("already configured"));
    assert_eq!(
        env.shim_log("claude"),
        vec!["mcp get promptguard".to_owned()]
    );
}

#[cfg(unix)]
#[test]
fn claude_code_with_another_url_needs_force() {
    let env = Env::new();
    env.shim("claude");
    env.shim_state(
        "claude",
        "promptguard:\n  Type: http\n  URL: https://old.example/mcp\n",
    );

    let out = env.run(&["--clients", "claude-code"]);
    assert!(line_for(&stdout(&out), "Claude Code").contains("--force"));
    assert_eq!(
        env.shim_log("claude"),
        vec!["mcp get promptguard".to_owned()]
    );

    let out = env.run(&["--clients", "claude-code", "--force"]);
    assert!(out.status.success(), "{}", stdout(&out));
    let log = env.shim_log("claude");
    assert!(
        log.contains(&"mcp remove promptguard --scope user".to_owned()),
        "{log:?}"
    );
    assert_eq!(
        log.last().unwrap(),
        &format!("mcp add --transport http --scope user promptguard {HOSTED}")
    );
}

#[cfg(unix)]
#[test]
fn claude_code_local_adds_the_stdio_server() {
    let env = Env::new();
    env.shim("claude");

    let out = env.run(&["--clients", "claude-code", "--local"]);
    assert!(out.status.success(), "{}", stdout(&out));
    let log = env.shim_log("claude");
    let add = log.last().unwrap();
    assert!(
        add.starts_with("mcp add --scope user promptguard -- "),
        "{add}"
    );
    assert!(add.ends_with("promptguard mcp -t stdio"), "{add}");
}

#[cfg(unix)]
#[test]
fn codex_is_added_with_its_url_flag() {
    let env = Env::new();
    env.shim("codex");

    let out = env.run(&["--clients", "codex"]);
    assert!(out.status.success(), "{}", stdout(&out));
    assert!(line_for(&stdout(&out), "Codex").contains("configured"));
    assert_eq!(
        env.shim_log("codex"),
        vec![
            "mcp get promptguard".to_owned(),
            format!("mcp add promptguard --url {HOSTED}"),
        ]
    );
}

#[cfg(unix)]
#[test]
fn codex_already_configured_is_not_added_again() {
    let env = Env::new();
    env.shim("codex");
    env.shim_state(
        "codex",
        &format!("promptguard\n  enabled: true\n  transport: streamable_http\n  url: {HOSTED}\n"),
    );

    let out = env.run(&["--clients", "codex"]);
    assert!(out.status.success(), "{}", stdout(&out));
    assert!(line_for(&stdout(&out), "Codex").contains("already configured"));
    assert_eq!(
        env.shim_log("codex"),
        vec!["mcp get promptguard".to_owned()]
    );
}

#[cfg(unix)]
#[test]
fn dry_run_does_not_call_add() {
    let env = Env::new();
    env.shim("claude");
    env.shim("codex");

    let out = env.run(&["--dry-run"]);
    assert!(out.status.success(), "{}", stdout(&out));
    let text = stdout(&out);
    assert!(line_for(&text, "Claude Code").contains("would"), "{text}");
    assert!(line_for(&text, "Codex").contains("would"), "{text}");
    for name in ["claude", "codex"] {
        assert!(
            env.shim_log(name).iter().all(|l| !l.starts_with("mcp add")),
            "{name}: {:?}",
            env.shim_log(name)
        );
    }
}

#[cfg(unix)]
#[test]
fn a_failing_client_cli_fails_the_run() {
    use std::os::unix::fs::PermissionsExt;
    let env = Env::new();
    let path = env.bin.path().join("claude");
    fs::write(
        &path,
        "#!/bin/sh\nif [ \"$2\" = get ]; then exit 1; fi\necho boom >&2\nexit 3\n",
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();

    let out = env.run(&["--clients", "claude-code"]);
    assert!(!out.status.success());
    let line = line_for(&stdout(&out), "Claude Code").to_owned();
    assert!(line.contains("failed"), "{line}");
    assert!(line.contains("boom"), "{line}");
}
