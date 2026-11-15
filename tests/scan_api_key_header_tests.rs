#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! `scan --json` reports, per SDK instance, whether the call sets an
//! `X-API-Key` header (`has_api_key_header`).
//!
//! `has_base_url` alone cannot tell a client that works through the proxy
//! from one that points at it and gets 401, since the proxy reads its key only
//! from `X-API-Key`. The VS Code extension needs both to say which calls are
//! protected.
use std::fs;
use std::process::Command;
use tempfile::TempDir;

fn scan_instances(files: &[(&str, &str)]) -> Vec<serde_json::Value> {
    let dir = TempDir::new().unwrap();
    for (name, body) in files {
        fs::write(dir.path().join(name), body).unwrap();
    }
    let out = Command::new(env!("CARGO_BIN_EXE_promptguard"))
        .args(["scan", "--json"])
        .current_dir(dir.path())
        .env_remove("PROMPTGUARD_API_KEY")
        .env("HOME", dir.path())
        .env("USERPROFILE", dir.path())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("scan --json was not JSON: {e}\n{stdout}"));
    let mut instances: Vec<serde_json::Value> = parsed["providers"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|p| p["instances"].as_array().unwrap().clone())
        .collect();
    instances.sort_by_key(|i| i["file"].as_str().unwrap().to_string());
    instances
}

fn flags(instance: &serde_json::Value) -> (bool, bool) {
    (
        instance["has_base_url"].as_bool().unwrap(),
        instance["has_api_key_header"]
            .as_bool()
            .unwrap_or_else(|| panic!("has_api_key_header missing: {instance}")),
    )
}

#[test]
fn python_instances_report_the_header() {
    let instances = scan_instances(&[
        ("a_bare.py", "from openai import OpenAI\nclient = OpenAI()\n"),
        (
            "b_base_only.py",
            "from openai import OpenAI\nclient = OpenAI(base_url=\"https://api.promptguard.co/api/v1\")\n",
        ),
        (
            "c_routed.py",
            "import os\nfrom openai import OpenAI\nclient = OpenAI(\n    base_url=\"https://api.promptguard.co/api/v1\",\n    default_headers={\"X-API-Key\": os.environ.get(\"PROMPTGUARD_API_KEY\", \"\")},\n)\n",
        ),
    ]);
    assert_eq!(instances.len(), 3, "{instances:?}");
    assert_eq!(flags(&instances[0]), (false, false));
    assert_eq!(flags(&instances[1]), (true, false));
    assert_eq!(flags(&instances[2]), (true, true));
}

#[test]
fn typescript_instances_report_the_header_in_any_case() {
    let instances = scan_instances(&[
        (
            "a_base_only.ts",
            "import OpenAI from \"openai\";\nconst c = new OpenAI({ baseURL: \"https://api.promptguard.co/api/v1\" });\n",
        ),
        (
            "b_routed.ts",
            "import OpenAI from \"openai\";\nconst c = new OpenAI({ baseURL: \"https://api.promptguard.co/api/v1\", defaultHeaders: { 'x-api-key': process.env.PROMPTGUARD_API_KEY } });\n",
        ),
    ]);
    assert_eq!(instances.len(), 2, "{instances:?}");
    assert_eq!(flags(&instances[0]), (true, false));
    assert_eq!(flags(&instances[1]), (true, true));
}

/// The SDK's own `api_key` / `apiKey` is not the proxy header.
#[test]
fn an_api_key_argument_is_not_the_header() {
    let instances = scan_instances(&[(
        "a.py",
        "from openai import OpenAI\nclient = OpenAI(api_key=k, base_url=\"https://api.promptguard.co/api/v1\")\n",
    )]);
    assert_eq!(flags(&instances[0]), (true, false));
}

fn header_state(instance: &serde_json::Value) -> Option<bool> {
    assert!(
        instance.get("has_api_key_header").is_some(),
        "has_api_key_header missing: {instance}"
    );
    instance["has_api_key_header"].as_bool()
}

/// Headers the scan cannot see (a variable, a splat, a spread) are unknown,
/// `null`, never "no header": the call may well send it.
#[test]
fn headers_from_elsewhere_are_unknown() {
    let instances = scan_instances(&[
        (
            "a_var.py",
            "from openai import OpenAI\nclient = OpenAI(base_url=\"https://api.promptguard.co/api/v1\", default_headers=pg_headers)\n",
        ),
        (
            "b_splat.py",
            "from openai import OpenAI\nclient = OpenAI(base_url=\"https://api.promptguard.co/api/v1\", **cfg)\n",
        ),
        (
            "c_var.ts",
            "import OpenAI from \"openai\";\nconst c = new OpenAI({ baseURL: \"https://api.promptguard.co/api/v1\", defaultHeaders: headers });\n",
        ),
        (
            "d_spread.ts",
            "import OpenAI from \"openai\";\nconst c = new OpenAI({ baseURL: \"https://api.promptguard.co/api/v1\", defaultHeaders: { ...shared } });\n",
        ),
    ]);
    assert_eq!(instances.len(), 4, "{instances:?}");
    for instance in &instances {
        assert_eq!(header_state(instance), None, "{instance}");
    }
}

/// Only a header key counts: the name in a comment or a value does not.
#[test]
fn the_name_outside_a_header_key_does_not_count() {
    let instances = scan_instances(&[
        (
            "a_comment.py",
            "from openai import OpenAI\nclient = OpenAI(\n    base_url=\"https://api.promptguard.co/api/v1\",  # TODO add \"X-API-Key\"\n)\n",
        ),
        (
            "b_value.ts",
            "import OpenAI from \"openai\";\nconst c = new OpenAI({ baseURL: \"https://api.promptguard.co/api/v1\", defaultHeaders: { \"X-Note\": \"x-api-key\" } });\n",
        ),
    ]);
    for instance in &instances {
        assert_eq!(header_state(instance), Some(false), "{instance}");
    }
}

/// A positional argument (an api key, a model id) is not where headers go.
#[test]
fn python_positional_arguments_are_not_unknown_headers() {
    let instances = scan_instances(&[(
        "a.py",
        "from huggingface_hub import InferenceClient\nclient = InferenceClient(model_id, base_url=\"https://api.promptguard.co/api/v1\")\n",
    )]);
    assert_eq!(
        header_state(&instances[0]),
        Some(false),
        "{:?}",
        instances[0]
    );
}
