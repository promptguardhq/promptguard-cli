#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Every `promptguard <command>` the CLI's own source mentions must be a real
//! subcommand.
//!
//! `init` and `test` used to end with "View logs: promptguard logs", a command
//! that never existed (promptguard-cli#59). A user who followed the advice got
//! an "unrecognized subcommand" error from the tool that had just told them to
//! run it. This test reads the subcommands from `promptguard --help` and fails
//! on any suggestion in `src/` that names something else.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::process::Command;

/// Words that follow "promptguard " in prose rather than in a suggested
/// command ("this promptguard understands", "upgrade promptguard to ...",
/// "any other promptguard tool").
const PROSE: &[&str] = &["understands", "to", "tool"];

fn subcommands() -> BTreeSet<String> {
    let out = Command::new(env!("CARGO_BIN_EXE_promptguard"))
        .arg("--help")
        .output()
        .expect("run promptguard --help");
    let help = String::from_utf8(out.stdout).expect("utf-8 help");
    let commands = help
        .split("Commands:")
        .nth(1)
        .and_then(|rest| rest.split("Run 'promptguard").next())
        .expect("help has a Commands section");
    // Command rows are indented four spaces: "    init       Initialize ...".
    // Group headings ("  Setup") are indented two and are skipped.
    commands
        .lines()
        .filter_map(|line| line.strip_prefix("    "))
        .filter_map(|line| line.split_whitespace().next())
        .map(str::to_owned)
        .collect()
}

fn rust_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in fs::read_dir(dir).expect("read src dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Each word that follows a standalone "promptguard " in `text`.
fn mentioned(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    let needle = "promptguard ";
    let mut from = 0;
    while let Some(at) = text[from..].find(needle) {
        let start = from + at;
        from = start + needle.len();
        // Skip "promptguard-cli", ".promptguard ", "pg_promptguard " and the like.
        let standalone = text[..start]
            .chars()
            .next_back()
            .is_none_or(|c| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '/' | '-')));
        if !standalone {
            continue;
        }
        let word: String = text[from..]
            .chars()
            .take_while(|c| c.is_ascii_lowercase() || *c == '-')
            .collect();
        // A flag ("promptguard --help") is not a subcommand.
        if word.starts_with(|c: char| c.is_ascii_lowercase()) {
            found.push(word);
        }
    }
    found
}

#[test]
fn every_suggested_command_exists() {
    let real = subcommands();
    assert!(
        real.contains("init") && real.contains("verify"),
        "could not read subcommands from --help: {real:?}"
    );

    let mut files = Vec::new();
    rust_files(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );

    let mut unknown = Vec::new();
    for file in files {
        let text = fs::read_to_string(&file).expect("read source file");
        for word in mentioned(&text) {
            if !real.contains(&word) && !PROSE.contains(&word.as_str()) {
                unknown.push(format!("{}: promptguard {word}", file.display()));
            }
        }
    }
    assert_eq!(
        unknown,
        Vec::<String>::new(),
        "source suggests commands the CLI does not have:\n{}",
        unknown.join("\n")
    );
}

#[test]
fn the_scanner_finds_a_bad_suggestion() {
    assert_eq!(
        mentioned(r#"println!("  • View logs: promptguard logs");"#),
        ["logs"]
    );
    assert_eq!(
        mentioned("promptguard-cli/2.2.3 and .promptguard file"),
        Vec::<String>::new()
    );
}
