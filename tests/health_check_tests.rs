#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! `verify`'s connectivity check, run against the real binary.
//!
//! The API serves `/health` at the host root, not under `/api/v1`. The stub
//! below answers only that route, as production does, and records every path
//! it is asked for, so a probe of `/api/v1/health` shows up as a failed check.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::process::Command;
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

/// A loopback HTTP stub: `GET /health` answers 200, every other path 404.
fn start_stub() -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let paths = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&paths);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            if reader.read_line(&mut request_line).is_err() {
                continue;
            }
            // Drain the headers so the client sees a complete exchange.
            let mut line = String::new();
            while reader.read_line(&mut line).is_ok() && line != "\r\n" && !line.is_empty() {
                line.clear();
            }
            let path = request_line
                .split_whitespace()
                .nth(1)
                .unwrap_or("")
                .to_string();
            seen.lock().unwrap().push(path.clone());
            let (status, body) = if path == "/health" {
                ("200 OK", r#"{"status":"healthy"}"#)
            } else {
                ("404 Not Found", r#"{"detail":"Not Found"}"#)
            };
            let _ = write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    (url, paths)
}

fn verify_json(base_url: &str) -> serde_json::Value {
    let home = TempDir::new().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_promptguard"))
        .args(["verify", "--json"])
        .current_dir(home.path())
        .env("HOME", home.path())
        .env("PROMPTGUARD_API_KEY", "pg_live_test_key")
        .env("PROMPTGUARD_BASE_URL", base_url)
        .env_remove("HTTPS_PROXY")
        .env_remove("HTTP_PROXY")
        .env_remove("https_proxy")
        .env_remove("http_proxy")
        .env("NO_PROXY", "127.0.0.1")
        .output()
        .unwrap();
    serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "verify --json printed no JSON ({e}): {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

#[test]
fn connectivity_probes_the_host_root_health_route() {
    let (url, paths) = start_stub();
    let report = verify_json(&format!("{url}/api/v1"));

    let paths = paths.lock().unwrap().clone();
    assert!(
        paths.iter().any(|p| p == "/health"),
        "expected a probe of /health, saw {paths:?}"
    );
    assert!(
        !paths.iter().any(|p| p == "/api/v1/health"),
        "probed the non-existent /api/v1/health: {paths:?}"
    );
    // Connectivity passing is what lets verify go on to the key check.
    assert!(
        report["checks_passed"].as_u64().unwrap() >= 2,
        "connectivity failed against a healthy API: {report}"
    );
}

#[test]
fn a_base_url_with_a_trailing_slash_probes_the_same_route() {
    let (url, paths) = start_stub();
    verify_json(&format!("{url}/api/v1/"));
    assert!(paths.lock().unwrap().iter().any(|p| p == "/health"));
}
