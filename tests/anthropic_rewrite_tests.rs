#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! The Anthropic rewrite behind `init` / `apply` (#66).
//!
//! The Anthropic SDK sends its own key in `X-Api-Key`, the header the proxy
//! authenticates on, and appends `/v1` to its base URL itself. So the rewrite
//! sets both headers in `default_headers` (the proxy's key as `X-API-Key`, the
//! Anthropic key as `Authorization: Bearer`, which the proxy forwards to
//! Anthropic), moves the Anthropic key out of `api_key`, and points the base
//! URL at the proxy URL without its trailing `/v1`.
use std::fs;
use tempfile::TempDir;

use promptguard::transformer;
use promptguard::types::{Provider, TransformResult};

const PROXY: &str = "https://api.promptguard.co/api/v1";
const BASE: &str = "https://api.promptguard.co/api";

fn transform_at(file_name: &str, input: &str, proxy: &str) -> (TransformResult, String) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join(file_name);
    fs::write(&path, input).unwrap();
    let result = transformer::transform_file(
        &path,
        Provider::Anthropic,
        proxy,
        "PROMPTGUARD_API_KEY",
        false,
    )
    .unwrap();
    (result, fs::read_to_string(&path).unwrap())
}

fn transform(file_name: &str, input: &str) -> (TransformResult, String) {
    transform_at(file_name, input, PROXY)
}

fn assert_parses(source: &str, language: &tree_sitter::Language) {
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(language).unwrap();
    let tree = parser.parse(source, None).unwrap();
    assert!(
        !tree.root_node().has_error(),
        "rewrite does not parse:\n{source}"
    );
}

fn assert_python_parses(source: &str) {
    assert_parses(source, &tree_sitter_python::LANGUAGE.into());
}

fn assert_ts_parses(source: &str) {
    assert_parses(source, &tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into());
}

fn assert_untouched(file_name: &str, src: &str, manual: usize) {
    let (result, out) = transform(file_name, src);
    assert!(!result.modified, "must be left untouched:\n{out}");
    assert_eq!(result.needs_manual_routing, manual, "{src}");
    assert_eq!(out, src);
}

const PY_PG_HEADER: &str = r#""X-API-Key": os.environ.get("PROMPTGUARD_API_KEY", ""),"#;

// ---- Python ---------------------------------------------------------------

#[test]
fn python_empty_client_sends_both_headers() {
    let (result, out) = transform(
        "app.py",
        "from anthropic import Anthropic\nclient = Anthropic()\n",
    );
    assert!(result.modified);
    assert!(out.contains(&format!("base_url=\"{BASE}\",")), "{out}");
    assert!(out.contains("default_headers={"), "{out}");
    assert!(out.contains(PY_PG_HEADER), "{out}");
    assert!(
        out.contains(r#""Authorization": "Bearer " + os.environ.get("ANTHROPIC_API_KEY", ""),"#),
        "{out}"
    );
    assert!(!out.contains("api_key="), "{out}");
    assert!(out.contains("import os"), "{out}");
    assert_python_parses(&out);
}

#[test]
fn python_api_key_moves_into_the_bearer_header() {
    let src = "import os\nfrom anthropic import Anthropic\nclient = Anthropic(\n    api_key=os.environ.get(\"ANTHROPIC_API_KEY\"),\n    max_retries=3,\n)\n";
    let (result, out) = transform("app.py", src);
    assert!(result.modified);
    assert!(
        out.contains(
            r#""Authorization": "Bearer " + (os.environ.get("ANTHROPIC_API_KEY") or ""),"#
        ),
        "{out}"
    );
    assert!(
        !out.contains("api_key="),
        "SDKs refuse api_key with the bearer header:\n{out}"
    );
    assert!(
        out.contains("max_retries=3,"),
        "other arguments are kept:\n{out}"
    );
    assert!(out.contains(PY_PG_HEADER), "{out}");
    assert_python_parses(&out);
}

#[test]
fn python_async_client_is_rewritten() {
    let (result, out) = transform(
        "app.py",
        "from anthropic import AsyncAnthropic\nclient = AsyncAnthropic()\n",
    );
    assert!(result.modified);
    assert!(out.contains(&format!("base_url=\"{BASE}\"")), "{out}");
    assert_python_parses(&out);
}

#[test]
fn python_comments_survive() {
    let src = "from anthropic import Anthropic\nclient = Anthropic(\n    max_retries=3,  # flaky network\n)\n";
    let (_, out) = transform("app.py", src);
    assert!(out.contains("# flaky network"), "{out}");
    assert_python_parses(&out);
}

/// v2.5.1 rewrote `Anthropic()` to the proxy key as `api_key` and the
/// `/api/v1` base URL. Re-running fixes both, and the proxy key must
/// not end up as the Anthropic bearer token.
#[test]
fn python_earlier_rewrite_is_repaired_once() {
    let src = format!(
        "import os\nfrom anthropic import Anthropic\n\nclient = Anthropic(\n    api_key=os.environ.get(\"PROMPTGUARD_API_KEY\"),\n    base_url=\"{PROXY}\"\n)\n"
    );
    let (result, out) = transform("app.py", &src);
    assert!(result.modified, "{out}");
    assert!(out.contains(&format!("base_url=\"{BASE}\",")), "{out}");
    assert!(!out.contains(PROXY), "the /api/v1 base URL must go:\n{out}");
    assert!(
        out.contains(r#""Authorization": "Bearer " + os.environ.get("ANTHROPIC_API_KEY", ""),"#),
        "{out}"
    );
    assert!(!out.contains("api_key="), "{out}");
    assert_python_parses(&out);

    let (again, out2) = transform("app.py", &out);
    assert!(!again.modified, "second run must be a no-op:\n{out2}");
    assert_eq!(again.needs_manual_routing, 0);
}

#[test]
fn python_earlier_rewrite_keeps_the_anthropic_key() {
    let src = format!(
        "from anthropic import Anthropic\nclient = Anthropic(api_key=key, base_url=\"{PROXY}\")\n"
    );
    let (result, out) = transform("app.py", &src);
    assert!(result.modified, "{out}");
    assert!(
        out.contains(r#""Authorization": "Bearer " + (key or ""),"#),
        "{out}"
    );
    assert_python_parses(&out);
}

#[test]
fn python_proxy_url_without_v1_is_used_as_given() {
    let (_, out) = transform_at(
        "app.py",
        "from anthropic import Anthropic\nclient = Anthropic()\n",
        "https://pg.example.com/gateway",
    );
    assert!(
        out.contains("base_url=\"https://pg.example.com/gateway\","),
        "{out}"
    );
}

#[test]
fn python_proxy_url_trailing_slash_is_trimmed() {
    let (_, out) = transform_at(
        "app.py",
        "from anthropic import Anthropic\nclient = Anthropic()\n",
        "https://pg.example.com/api/v1/",
    );
    assert!(
        out.contains("base_url=\"https://pg.example.com/api\","),
        "{out}"
    );
}

#[test]
fn python_calls_the_rewrite_cannot_own_are_reported() {
    for call in [
        "Anthropic(auth_token=t)",
        "Anthropic(credentials=c)",
        "Anthropic(profile=\"work\")",
        "Anthropic(default_headers={\"X-Team\": \"a\"})",
        "Anthropic(**cfg)",
    ] {
        let src = format!("from anthropic import Anthropic\nclient = {call}\n");
        assert_untouched("app.py", &src, 1);
    }
}

#[test]
fn python_other_base_urls_are_left_alone() {
    assert_untouched(
        "app.py",
        "from anthropic import Anthropic\nclient = Anthropic(base_url=\"https://gw.example.com\")\n",
        0,
    );
}

// ---- TypeScript -----------------------------------------------------------

const TS_PG_HEADER: &str = r#""X-API-Key": process.env.PROMPTGUARD_API_KEY,"#;

#[test]
fn typescript_empty_client_sends_both_headers() {
    let (result, out) = transform(
        "app.ts",
        "import Anthropic from \"@anthropic-ai/sdk\";\nconst c = new Anthropic();\n",
    );
    assert!(result.modified);
    assert!(out.contains(&format!("baseURL: \"{BASE}\",")), "{out}");
    assert!(out.contains("defaultHeaders: {"), "{out}");
    assert!(out.contains(TS_PG_HEADER), "{out}");
    assert!(
        out.contains("Authorization: `Bearer ${process.env.ANTHROPIC_API_KEY ?? \"\"}`"),
        "{out}"
    );
    assert!(!out.contains("apiKey"), "{out}");
    assert_ts_parses(&out);
}

#[test]
fn typescript_api_key_moves_into_the_bearer_header() {
    let src = "import Anthropic from \"@anthropic-ai/sdk\";\nconst c = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY, maxRetries: 3 });\n";
    let (result, out) = transform("app.ts", src);
    assert!(result.modified);
    assert!(
        out.contains("Authorization: `Bearer ${process.env.ANTHROPIC_API_KEY ?? \"\"}`"),
        "{out}"
    );
    assert!(!out.contains("apiKey"), "{out}");
    assert!(out.contains("maxRetries: 3,"), "{out}");
    assert_ts_parses(&out);
}

#[test]
fn typescript_shorthand_api_key_moves_into_the_bearer_header() {
    let src =
        "import Anthropic from \"@anthropic-ai/sdk\";\nconst c = new Anthropic({ apiKey });\n";
    let (result, out) = transform("app.ts", src);
    assert!(result.modified);
    assert!(
        out.contains("Authorization: `Bearer ${apiKey ?? \"\"}`"),
        "{out}"
    );
    assert!(!out.contains("apiKey,"), "{out}");
    assert_ts_parses(&out);
}

#[test]
fn typescript_earlier_rewrite_is_repaired_once() {
    let src = format!(
        "import Anthropic from \"@anthropic-ai/sdk\";\nconst c = new Anthropic({{\n  apiKey: process.env.PROMPTGUARD_API_KEY,\n  baseURL: \"{PROXY}\"\n}});\n"
    );
    let (result, out) = transform("app.ts", &src);
    assert!(result.modified, "{out}");
    assert!(out.contains(&format!("baseURL: \"{BASE}\",")), "{out}");
    assert!(!out.contains(PROXY), "{out}");
    assert!(
        out.contains("Authorization: `Bearer ${process.env.ANTHROPIC_API_KEY ?? \"\"}`"),
        "the PromptGuard key must not become the Anthropic key:\n{out}"
    );
    assert_ts_parses(&out);

    let (again, out2) = transform("app.ts", &out);
    assert!(!again.modified, "second run must be a no-op:\n{out2}");
    assert_eq!(again.needs_manual_routing, 0);
}

#[test]
fn typescript_calls_the_rewrite_cannot_own_are_reported() {
    for args in [
        "{ authToken: t }",
        "{ defaultHeaders: { \"X-Team\": \"a\" } }",
        "{ ...shared }",
        "{ [\"apiKey\"]: k }",
        "config",
    ] {
        let src = format!(
            "import Anthropic from \"@anthropic-ai/sdk\";\nconst c = new Anthropic({args});\n"
        );
        assert_untouched("app.ts", &src, 1);
    }
}

#[test]
fn typescript_other_base_urls_are_left_alone() {
    assert_untouched(
        "app.ts",
        "import Anthropic from \"@anthropic-ai/sdk\";\nconst c = new Anthropic({ baseURL: \"https://gw.example.com\" });\n",
        0,
    );
}
