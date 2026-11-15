#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! The rewrite behind `init` / `apply` must authenticate to the proxy (#60).
//!
//! The proxy reads its key only from `X-API-Key`; `Authorization`
//! (what an SDK's `api_key` becomes) is forwarded to the provider. A rewrite
//! that adds a base URL without that header is refused with 401
//! `missing_api_key`, so every rewritten client must carry it, and the
//! provider key must stay in the SDK's own `api_key`.
use std::fs;
use tempfile::TempDir;

use promptguard::transformer;
use promptguard::types::{Provider, TransformResult};

const PROXY: &str = "https://api.promptguard.co/api/v1";

fn transform(file_name: &str, provider: Provider, input: &str) -> (TransformResult, String) {
    transform_with_env(file_name, provider, input, "PROMPTGUARD_API_KEY")
}

fn transform_with_env(
    file_name: &str,
    provider: Provider,
    input: &str,
    env_var: &str,
) -> (TransformResult, String) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join(file_name);
    fs::write(&path, input).unwrap();
    let result = transformer::transform_file(&path, provider, PROXY, env_var, false).unwrap();
    (result, fs::read_to_string(&path).unwrap())
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

const PY_HEADER: &str =
    r#"default_headers={"X-API-Key": os.environ.get("PROMPTGUARD_API_KEY", "")}"#;
const TS_HEADER: &str = r#"defaultHeaders: { "X-API-Key": process.env.PROMPTGUARD_API_KEY }"#;

#[test]
fn python_empty_client_sends_x_api_key_and_keeps_provider_key_default() {
    let (result, out) = transform(
        "app.py",
        Provider::OpenAI,
        "from openai import OpenAI\nclient = OpenAI()\n",
    );
    assert!(result.modified);
    assert!(out.contains(&format!("base_url=\"{PROXY}\"")), "{out}");
    assert!(out.contains(PY_HEADER), "X-API-Key header missing:\n{out}");
    // The PromptGuard key as `api_key` goes to OpenAI as `Authorization` and
    // fails there; leaving `api_key` out keeps the SDK's OPENAI_API_KEY default.
    assert!(
        !out.contains("api_key="),
        "PromptGuard key must not be the provider key:\n{out}"
    );
    assert_python_parses(&out);
}

#[test]
fn python_client_with_provider_key_keeps_it_and_adds_header() {
    let input = "import os\nfrom openai import OpenAI\nclient = OpenAI(api_key=os.environ.get(\"OPENAI_API_KEY\"))\n";
    let (result, out) = transform("app.py", Provider::OpenAI, input);
    assert!(result.modified);
    assert!(
        out.contains("api_key=os.environ.get(\"OPENAI_API_KEY\")"),
        "{out}"
    );
    assert!(out.contains(PY_HEADER), "X-API-Key header missing:\n{out}");
    assert_python_parses(&out);
}

#[test]
fn python_header_uses_the_configured_env_var() {
    let (_, out) = transform_with_env(
        "app.py",
        Provider::OpenAI,
        "from openai import OpenAI\nclient = OpenAI()\n",
        "PG_KEY",
    );
    assert!(
        out.contains(r#"{"X-API-Key": os.environ.get("PG_KEY", "")}"#),
        "{out}"
    );
}

#[test]
fn python_async_and_groq_get_the_header() {
    for (provider, src) in [
        (
            Provider::OpenAI,
            "from openai import AsyncOpenAI\nclient = AsyncOpenAI()\n",
        ),
        (Provider::Groq, "from groq import Groq\nclient = Groq()\n"),
    ] {
        let (result, out) = transform("app.py", provider, src);
        assert!(result.modified, "{src}");
        assert!(out.contains(PY_HEADER), "X-API-Key header missing:\n{out}");
        assert_python_parses(&out);
    }
}

#[test]
fn python_huggingface_uses_its_headers_kwarg() {
    let src = "from huggingface_hub import InferenceClient\nclient = InferenceClient()\n";
    let (result, out) = transform("app.py", Provider::HuggingFace, src);
    assert!(result.modified);
    assert!(
        out.contains(r#"headers={"X-API-Key": os.environ.get("PROMPTGUARD_API_KEY", "")}"#),
        "{out}"
    );
    assert!(!out.contains("default_headers"), "{out}");
    assert_python_parses(&out);
}

/// `cohere.Client` takes no header argument, so a rewrite could only add a
/// base URL that the proxy then refuses. Report it for manual routing.
#[test]
fn python_cohere_cannot_carry_the_header_and_is_reported() {
    let src = "import cohere\nclient = cohere.Client(api_key=key)\n";
    let (result, out) = transform("app.py", Provider::Cohere, src);
    assert!(!result.modified, "{out}");
    assert_eq!(result.needs_manual_routing, 1);
    assert_eq!(out, src);
}

/// A second `default_headers=` would be a syntax error; merging into an
/// existing one is left to the developer.
#[test]
fn python_existing_default_headers_is_reported_not_rewritten() {
    let src = "from openai import OpenAI\nclient = OpenAI(default_headers={\"X-Team\": \"a\"})\n";
    let (result, out) = transform("app.py", Provider::OpenAI, src);
    assert!(!result.modified, "{out}");
    assert_eq!(result.needs_manual_routing, 1);
    assert_eq!(out, src);
}

#[test]
fn typescript_empty_client_sends_x_api_key_and_keeps_provider_key_default() {
    let (result, out) = transform(
        "app.ts",
        Provider::OpenAI,
        "import OpenAI from \"openai\";\nconst c = new OpenAI();\n",
    );
    assert!(result.modified);
    assert!(out.contains(&format!("baseURL: \"{PROXY}\"")), "{out}");
    assert!(out.contains(TS_HEADER), "X-API-Key header missing:\n{out}");
    assert!(
        !out.contains("apiKey"),
        "PromptGuard key must not be the provider key:\n{out}"
    );
    assert_ts_parses(&out);
}

#[test]
fn typescript_client_with_provider_key_keeps_it_and_adds_header() {
    let src = "import OpenAI from \"openai\";\nconst c = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });\n";
    let (result, out) = transform("app.ts", Provider::OpenAI, src);
    assert!(result.modified);
    assert!(out.contains("apiKey: process.env.OPENAI_API_KEY"), "{out}");
    assert!(out.contains(TS_HEADER), "X-API-Key header missing:\n{out}");
    assert_ts_parses(&out);
}

#[test]
fn typescript_empty_options_object_gets_the_header() {
    let (result, out) = transform(
        "app.ts",
        Provider::Groq,
        "import Groq from \"groq-sdk\";\nconst c = new Groq({});\n",
    );
    assert!(result.modified);
    assert!(out.contains(TS_HEADER), "{out}");
    assert!(!out.contains("apiKey"), "{out}");
    assert_ts_parses(&out);
}

#[test]
fn typescript_existing_default_headers_is_reported_not_rewritten() {
    let src = "import OpenAI from \"openai\";\nconst c = new OpenAI({ apiKey: k, defaultHeaders: { \"X-Team\": \"a\" } });\n";
    let (result, out) = transform("app.ts", Provider::OpenAI, src);
    assert!(!result.modified, "{out}");
    assert_eq!(result.needs_manual_routing, 1);
    assert_eq!(out, src);
}

#[test]
fn typescript_existing_shorthand_default_headers_is_reported_not_rewritten() {
    let src =
        "import OpenAI from \"openai\";\nconst c = new OpenAI({ apiKey: k, defaultHeaders });\n";
    let (result, out) = transform("app.ts", Provider::OpenAI, src);
    assert!(!result.modified, "{out}");
    assert_eq!(result.needs_manual_routing, 1);
}

#[test]
fn typescript_providers_without_a_header_option_are_reported() {
    let src = "import { HfInference } from \"@huggingface/inference\";\nconst c = new HfInference({ accessToken: t });\n";
    let (result, out) = transform("app.ts", Provider::HuggingFace, src);
    assert!(!result.modified, "{out}");
    assert_eq!(result.needs_manual_routing, 1);
}

#[test]
fn typescript_earlier_rewrite_gets_the_header_added_once() {
    let src = format!(
        "import OpenAI from \"openai\";\nconst c = new OpenAI({{\n  apiKey: process.env.OPENAI_API_KEY,\n  baseURL: \"{PROXY}\"\n}});\n"
    );
    let (result, out) = transform("app.ts", Provider::OpenAI, &src);
    assert!(result.modified, "{out}");
    assert!(out.contains(TS_HEADER), "{out}");
    assert_eq!(out.matches("baseURL").count(), 1, "{out}");
    assert_ts_parses(&out);

    let (again, out2) = transform("app.ts", Provider::OpenAI, &out);
    assert!(!again.modified, "second run must be a no-op:\n{out2}");
}

/// A base URL that is not the proxy is the developer's own gateway: leave it.
#[test]
fn other_base_urls_are_left_alone() {
    let py = "from openai import OpenAI\nclient = OpenAI(base_url=\"https://gw.example.com/v1\")\n";
    let (result, out) = transform("app.py", Provider::OpenAI, py);
    assert!(!result.modified, "{out}");
    assert_eq!(result.needs_manual_routing, 0);
    let ts = "import OpenAI from \"openai\";\nconst c = new OpenAI({ baseURL: \"https://gw.example.com/v1\" });\n";
    let (result, out) = transform("app.ts", Provider::OpenAI, ts);
    assert!(!result.modified, "{out}");
    assert_eq!(result.needs_manual_routing, 0);
}

/// A spread or computed key may carry headers; an appended `defaultHeaders`
/// would silently override them.
#[test]
fn typescript_spread_and_computed_keys_are_reported() {
    for src in [
        "import OpenAI from \"openai\";\nconst c = new OpenAI({ ...shared });\n",
        "import OpenAI from \"openai\";\nconst c = new OpenAI({ apiKey: k, [\"defaultHeaders\"]: h });\n",
    ] {
        let (result, out) = transform("app.ts", Provider::OpenAI, src);
        assert!(!result.modified, "{out}");
        assert_eq!(result.needs_manual_routing, 1, "{src}");
        assert_eq!(out, src);
    }
}
