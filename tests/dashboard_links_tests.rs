#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Every dashboard link the CLI prints or opens must be a page the dashboard serves.
//!
//! `promptguard key`, `init`, `login`, `test`, the MCP server's `promptguard_auth`
//! and `install.sh` all sent people to `https://app.promptguard.co/settings/api-keys`,
//! and `init` to `/signup`. Neither page exists: both return 404, so the step that
//! tells a new user where to get a key led nowhere. The routes below are the
//! dashboard's (`apps/dashboard/app` in the platform repo); add one here only once
//! the dashboard serves it.

use std::fs;
use std::path::Path;

const DASHBOARD: &str = "https://app.promptguard.co";

const SERVED_ROUTES: &[&str] = &[
    "",
    "/dashboard",
    "/dashboard/api-keys",
    "/dashboard/billing",
    "/register",
    "/login",
];

fn sources() -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut stack = vec![Path::new(env!("CARGO_MANIFEST_DIR")).join("src")];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).expect("read src") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push((
                    path.display().to_string(),
                    fs::read_to_string(&path).expect("read"),
                ));
            }
        }
    }
    let install = Path::new(env!("CARGO_MANIFEST_DIR")).join("install.sh");
    out.push((
        install.display().to_string(),
        fs::read_to_string(&install).expect("read install.sh"),
    ));
    out
}

fn dashboard_paths(text: &str) -> Vec<String> {
    let mut paths = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find(DASHBOARD) {
        let tail = &rest[at + DASHBOARD.len()..];
        let end = tail
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '/' || c == '-' || c == '_'))
            .unwrap_or(tail.len());
        paths.push(tail[..end].trim_end_matches('/').to_string());
        rest = &tail[end..];
    }
    paths
}

#[test]
fn every_dashboard_link_is_a_page_the_dashboard_serves() {
    let mut broken = Vec::new();
    for (file, text) in sources() {
        for path in dashboard_paths(&text) {
            if !SERVED_ROUTES.contains(&path.as_str()) {
                broken.push(format!("{file}: {DASHBOARD}{path}"));
            }
        }
    }
    assert!(
        broken.is_empty(),
        "links to dashboard pages that do not exist:\n{}",
        broken.join("\n")
    );
}

#[test]
fn the_scanner_finds_links_and_their_paths() {
    let found = dashboard_paths(
        "see https://app.promptguard.co/settings/api-keys, or https://app.promptguard.co.",
    );
    assert_eq!(found, vec!["/settings/api-keys".to_string(), String::new()]);
}
