use super::core::{
    anthropic_base_url, anthropic_decision, expr_names_env_var, transform_file_generic, unquote,
    AnthropicRewrite,
};
use crate::detector::{typescript_object_has_base_url, Grammar, ProviderInfo};
use crate::transformer::Transformer;
use crate::types::{Provider, TransformResult};
use std::fmt::Write;
use std::path::Path;

pub struct TypeScriptTransformer;

impl Default for TypeScriptTransformer {
    fn default() -> Self {
        Self::new()
    }
}

impl TypeScriptTransformer {
    pub fn new() -> Self {
        Self
    }
}

fn ts_has_base_url(source: &str, object_node: tree_sitter::Node, provider: Provider) -> bool {
    let Some(info) = ProviderInfo::get(provider) else {
        return false;
    };
    let object_text = &source[object_node.start_byte()..object_node.end_byte()];
    typescript_object_has_base_url(object_text, info)
}

/// Why a call cannot be rewritten to authenticate to the proxy, so must be
/// reported for manual routing rather than left half-routed.
fn ts_needs_manual_routing(
    source: &str,
    object_node: Option<tree_sitter::Node>,
    info: &ProviderInfo,
) -> bool {
    // No header option: a base URL alone gets 401 from the proxy, which reads
    // the PromptGuard key only from `X-API-Key`.
    if info.ts_headers_param.is_empty() {
        return true;
    }
    // A second `defaultHeaders` key would replace the first (or fail to type
    // check); merging into the existing one is left to the developer. A
    // spread or computed key may carry headers the rewrite cannot see, and an
    // appended key would silently override them.
    object_node.is_some_and(|node| {
        ts_object_has_dynamic_keys(node)
            || ts_object_has_property(source, node, info.ts_headers_param)
    })
}

/// Whether the object literal has a spread (`...cfg`) or a computed key
/// (`[name]: …`), whose properties are unknown until run time.
fn ts_object_has_dynamic_keys(object_node: tree_sitter::Node) -> bool {
    let mut cursor = object_node.walk();
    let found = object_node.named_children(&mut cursor).any(|child| {
        child.kind() == "spread_element"
            || (child.kind() == "pair"
                && child
                    .child_by_field_name("key")
                    .is_some_and(|key| key.kind() == "computed_property_name"))
    });
    found
}

/// Whether the object literal has a property named `name`, as `name: …`,
/// `"name": …` or the shorthand `name`.
fn ts_object_has_property(source: &str, object_node: tree_sitter::Node, name: &str) -> bool {
    let mut cursor = object_node.walk();
    for child in object_node.named_children(&mut cursor) {
        let key = match child.kind() {
            "pair" => child.child_by_field_name("key"),
            "shorthand_property_identifier" => Some(child),
            _ => None,
        };
        if let Some(key) = key {
            let text = &source[key.start_byte()..key.end_byte()];
            if unquote(text).unwrap_or(text) == name {
                return true;
            }
        }
    }
    false
}

/// The lines a rewrite adds: the proxy URL (unless the object already has
/// it), and the header that authenticates to it. The provider key stays in
/// the SDK's own option (or its environment default), which the proxy
/// forwards to the provider.
fn write_proxy_props(
    out: &mut String,
    with_base_url: bool,
    info: &ProviderInfo,
    proxy_url: &str,
    api_key_env_var: &str,
) {
    if with_base_url {
        let _ = writeln!(out, "  {}: \"{proxy_url}\",", info.ts_base_url_param);
    }
    let _ = writeln!(
        out,
        "  {}: {{ \"X-API-Key\": process.env.{api_key_env_var} }}",
        info.ts_headers_param
    );
}

fn transform_ts_object(
    source: &str,
    object_node: tree_sitter::Node,
    with_base_url: bool,
    info: &ProviderInfo,
    proxy_url: &str,
    api_key_env_var: &str,
) -> String {
    let object_text = &source[object_node.start_byte()..object_node.end_byte()];
    // Strip exactly ONE outer `{` / `}`: the delimiters of this `object`
    // node. `trim_end_matches('}')` stripped *every* trailing brace, so a
    // nested object literal like `{apiKey:k, defaults:{timeout:1}}` lost its
    // inner closing brace and became invalid.
    let inner = object_text
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .unwrap_or(object_text);

    // End of the last real property (comments excluded): the injected comma
    // must go right after it. Appending the comma to the raw text swallowed
    // it into any trailing line comment (`apiKey: k // note` became
    // `apiKey: k // note,`) and produced a syntax error.
    let last_prop_end = last_non_comment_child_end(object_node);

    let mut new_object = String::from("{\n");

    match last_prop_end {
        Some(end) if object_text.starts_with('{') => {
            let split_at = end - object_node.start_byte() - 1;
            let (props_part, tail) = inner.split_at(split_at);

            let mut tail = tail.trim_start();
            if let Some(rest) = tail.strip_prefix(',') {
                tail = rest.trim_start();
            }
            let tail = tail.trim_end();

            new_object.push_str("  ");
            new_object.push_str(props_part.trim());
            new_object.push(',');
            if !tail.is_empty() {
                new_object.push_str("  ");
                new_object.push_str(tail);
            }
            new_object.push('\n');
            write_proxy_props(
                &mut new_object,
                with_base_url,
                info,
                proxy_url,
                api_key_env_var,
            );
        },
        _ => {
            // No properties. Keep any comment-only content after the
            // injected properties.
            write_proxy_props(&mut new_object, true, info, proxy_url, api_key_env_var);
            let comments = inner.trim();
            if !comments.is_empty() {
                let _ = writeln!(new_object, "  {comments}");
            }
        },
    }

    new_object.push('}');
    new_object
}

/// The Anthropic rewrite, the TypeScript side of `python::anthropic_args`:
/// `apiKey` comes out and its value becomes the `Authorization: Bearer`
/// header beside the proxy's `X-API-Key`, and the base URL drops the `/v1`
/// the SDK appends itself. Returns the replacement for the options object, or
/// for the whole argument list when it was empty.
fn anthropic_options<'tree>(
    source: &str,
    args_node: tree_sitter::Node<'tree>,
    proxy_url: &str,
    api_key_env_var: &str,
) -> (AnthropicRewrite, tree_sitter::Node<'tree>) {
    let text = |node: tree_sitter::Node| &source[node.start_byte()..node.end_byte()];
    let mut cursor = args_node.walk();
    let object = args_node
        .children(&mut cursor)
        .find(|child| child.kind() == "object");

    let Some(object) = object else {
        // A non-object argument means the options come from elsewhere.
        if last_non_comment_child_end(args_node).is_some() {
            return (AnthropicRewrite::Manual, args_node);
        }
        let comments: Vec<&str> = {
            let mut c = args_node.walk();
            args_node.named_children(&mut c).map(&text).collect()
        };
        let body = anthropic_object(&[], &comments, None, proxy_url, api_key_env_var);
        return (AnthropicRewrite::Replace(format!("({body})")), args_node);
    };

    if ts_object_has_dynamic_keys(object) {
        return (AnthropicRewrite::Manual, object);
    }

    let mut kept = Vec::new();
    let mut comments = Vec::new();
    let mut api_key = None;
    let mut base_url = None;
    let mut has_headers = false;
    let mut cursor = object.walk();
    for child in object.named_children(&mut cursor) {
        let (name, value) = match child.kind() {
            "comment" => {
                comments.push(text(child));
                continue;
            },
            "pair" => match (
                child.child_by_field_name("key"),
                child.child_by_field_name("value"),
            ) {
                (Some(key), Some(value)) => (unquote(text(key)).unwrap_or(text(key)), text(value)),
                _ => return (AnthropicRewrite::Manual, object),
            },
            "shorthand_property_identifier" => (text(child), text(child)),
            _ => {
                kept.push(text(child));
                continue;
            },
        };
        match name {
            "baseURL" => base_url = Some(value),
            "apiKey" => api_key = Some(value),
            "defaultHeaders" => has_headers = true,
            // Another credential the rewrite would have to override.
            "authToken" => return (AnthropicRewrite::Manual, object),
            _ => kept.push(text(child)),
        }
    }

    if let Some(decided) = anthropic_decision(base_url, has_headers, proxy_url) {
        return (decided, object);
    }
    let body = anthropic_object(&kept, &comments, api_key, proxy_url, api_key_env_var);
    (AnthropicRewrite::Replace(body), object)
}

/// The rebuilt Anthropic options object. `api_key` is the expression the
/// call passed as `apiKey`; one naming the proxy key's variable is an
/// earlier rewrite's, and the Anthropic key is read from its own variable.
fn anthropic_object(
    kept: &[&str],
    comments: &[&str],
    api_key: Option<&str>,
    proxy_url: &str,
    api_key_env_var: &str,
) -> String {
    let key = match api_key {
        // `??` cannot sit beside an unparenthesized `||` or `&&`.
        Some(expr) if !expr_names_env_var(expr, api_key_env_var) => {
            if expr
                .chars()
                .all(|c| c.is_alphanumeric() || matches!(c, '_' | '$' | '.'))
            {
                expr.to_string()
            } else {
                format!("({expr})")
            }
        },
        _ => "process.env.ANTHROPIC_API_KEY".to_string(),
    };
    let mut out = String::from("{\n");
    for prop in kept {
        let _ = writeln!(out, "  {prop},");
    }
    for comment in comments {
        let _ = writeln!(out, "  {comment}");
    }
    let _ = writeln!(out, "  baseURL: \"{}\",", anthropic_base_url(proxy_url));
    out.push_str("  defaultHeaders: {\n");
    let _ = writeln!(out, "    \"X-API-Key\": process.env.{api_key_env_var},");
    let _ = writeln!(out, "    Authorization: `Bearer ${{{key} ?? \"\"}}`");
    out.push_str("  }\n}");
    out
}

/// Build a replacement for an EMPTY argument list, `new OpenAI()`, by
/// synthesizing an options object carrying the proxy URL and header,
/// mirroring the Python transformer's empty-args behavior. The SDK keeps
/// reading the provider key from its own environment variable.
fn synthesize_ts_options(
    source: &str,
    args_node: tree_sitter::Node,
    info: &ProviderInfo,
    proxy_url: &str,
    api_key_env_var: &str,
) -> String {
    let args_text = &source[args_node.start_byte()..args_node.end_byte()];
    let inner = args_text
        .strip_prefix('(')
        .and_then(|s| s.strip_suffix(')'))
        .unwrap_or(args_text);

    let mut new_args = String::from("({\n");
    write_proxy_props(&mut new_args, true, info, proxy_url, api_key_env_var);
    // Keep any comment-only content from the original argument list.
    let comments = inner.trim();
    if !comments.is_empty() {
        let _ = writeln!(new_args, "  {comments}");
    }
    new_args.push_str("})");
    new_args
}

/// Byte offset just past the last named child of `node` that is not a
/// comment, or `None` when there is no such child.
fn last_non_comment_child_end(node: tree_sitter::Node) -> Option<usize> {
    let mut cursor = node.walk();
    let mut last_end = None;
    for child in node.named_children(&mut cursor) {
        if child.kind() != "comment" {
            last_end = Some(child.end_byte());
        }
    }
    last_end
}

impl Transformer for TypeScriptTransformer {
    fn transform_file(
        &self,
        file_path: &Path,
        provider: Provider,
        proxy_url: &str,
        api_key_env_var: &str,
        dry_run: bool,
    ) -> crate::error::Result<TransformResult> {
        // .tsx/.jsx need the TSX grammar: JSX syntax does not parse under
        // the plain TypeScript grammar (and .ts must not use TSX, where
        // generics are ambiguous with JSX).
        let grammar = match file_path.extension().and_then(|e| e.to_str()) {
            Some("tsx" | "jsx") => Grammar::Tsx,
            _ => Grammar::TypeScript,
        };

        // Counted from inside the Fn closure, so interior mutability.
        let manual_skips = std::cell::Cell::new(0usize);

        let mut result = transform_file_generic(
            file_path,
            grammar,
            provider,
            |source, args_node| {
                // No registry metadata, or a detect-only provider (Bedrock,
                // Gemini: empty parameter names; interpolating them produced
                // `{ : ... }`, a syntax error): leave the call untouched.
                if provider == Provider::Anthropic {
                    let (rewrite, node) =
                        anthropic_options(source, args_node, proxy_url, api_key_env_var);
                    return match rewrite {
                        AnthropicRewrite::Unchanged => None,
                        AnthropicRewrite::Manual => {
                            manual_skips.set(manual_skips.get() + 1);
                            None
                        },
                        AnthropicRewrite::Replace(new) => {
                            Some((node.start_byte(), node.end_byte(), new))
                        },
                    };
                }
                let info = ProviderInfo::get(provider)?;
                if info.ts_base_url_param.is_empty() {
                    return None;
                }

                let mut cursor = args_node.walk();
                let object = args_node
                    .children(&mut cursor)
                    .find(|child| child.kind() == "object");

                if let Some(object) = object {
                    let with_base_url = !ts_has_base_url(source, object, provider);
                    let manual = ts_needs_manual_routing(source, Some(object), info);
                    if !with_base_url {
                        // Already routed. A call an earlier version rewrote
                        // has the proxy URL but no header and gets 401: add
                        // the header. Any other base URL is the developer's.
                        let text = &source[object.start_byte()..object.end_byte()];
                        if manual || !text.contains(&format!("\"{proxy_url}\"")) {
                            return None;
                        }
                    }
                    if manual {
                        manual_skips.set(manual_skips.get() + 1);
                        return None;
                    }
                    let new_obj = transform_ts_object(
                        source,
                        object,
                        with_base_url,
                        info,
                        proxy_url,
                        api_key_env_var,
                    );
                    return Some((object.start_byte(), object.end_byte(), new_obj));
                }

                // A non-object argument (identifier, spread, call, …) means
                // the options come from elsewhere: the call needs manual
                // routing, which is reported instead of silently claiming
                // "no changes needed".
                if last_non_comment_child_end(args_node).is_some()
                    || ts_needs_manual_routing(source, None, info)
                {
                    manual_skips.set(manual_skips.get() + 1);
                    return None;
                }
                // Empty argument list (`new OpenAI()`): synthesize options.
                let new_args =
                    synthesize_ts_options(source, args_node, info, proxy_url, api_key_env_var);
                Some((args_node.start_byte(), args_node.end_byte(), new_args))
            },
            |s| s,
            dry_run,
        )?;
        result.needs_manual_routing = manual_skips.get();
        Ok(result)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;
    use tree_sitter::Parser;

    /// Parse `source` as TypeScript and assert zero ERROR nodes.
    fn assert_reparses_clean(source: &str) {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .expect("set typescript language");
        let tree = parser.parse(source, None).expect("parse");
        assert!(
            !tree.root_node().has_error(),
            "transformed TypeScript has tree-sitter ERROR node(s):\n{source}"
        );
    }

    fn transform_ts(input: &str) -> String {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("client.ts");
        fs::write(&path, input).unwrap();
        TypeScriptTransformer::new()
            .transform_file(
                &path,
                Provider::OpenAI,
                "https://api.promptguard.co/api/v1",
                "PROMPTGUARD_API_KEY",
                false,
            )
            .unwrap();
        fs::read_to_string(&path).unwrap()
    }

    /// Regression: `trim_end_matches('}')` stripped the nested object's
    /// closing brace too, producing an unbalanced/invalid object literal.
    #[test]
    fn nested_object_literal_keeps_balanced_braces() {
        let input = "import OpenAI from \"openai\";\nconst client = new OpenAI({apiKey: k, fetchOptions: {timeout: 1}});\n";
        let out = transform_ts(input);
        assert!(
            out.contains("fetchOptions: {timeout: 1}"),
            "nested object must survive:\n{out}"
        );
        assert!(out.contains("baseURL: \"https://api.promptguard.co/api/v1\""));
        assert_reparses_clean(&out);
    }

    #[test]
    fn empty_options_object_reparses_clean() {
        let input = "import OpenAI from \"openai\";\nconst client = new OpenAI({});\n";
        let out = transform_ts(input);
        assert!(out.contains("baseURL:"));
        assert_reparses_clean(&out);
    }

    /// Regression: appending the comma to the raw object text swallowed it
    /// into a trailing line comment (`apiKey: k // note,`) → syntax error.
    #[test]
    fn trailing_line_comment_keeps_comma_out_of_comment() {
        let input = "import OpenAI from \"openai\";\nconst client = new OpenAI({\n  apiKey: k // from env\n});\n";
        let out = transform_ts(input);
        assert!(out.contains("baseURL: \"https://api.promptguard.co/api/v1\""));
        assert!(
            out.contains("apiKey: k,"),
            "comma must land after the property, not inside the comment:\n{out}"
        );
        assert!(out.contains("// from env"), "comment kept:\n{out}");
        assert_reparses_clean(&out);
    }

    /// Trailing comma plus trailing comment must not produce a double comma.
    #[test]
    fn trailing_comma_and_comment_reparses_clean() {
        let input = "import OpenAI from \"openai\";\nconst client = new OpenAI({\n  apiKey: k, // note\n});\n";
        let out = transform_ts(input);
        assert!(!out.contains(",,"), "no double comma:\n{out}");
        assert!(out.contains("// note"));
        assert_reparses_clean(&out);
    }

    /// Bedrock has empty parameter names in the registry (detect-only).
    /// Interpolating them produced `{ : ..., : "..." }`: a syntax error,
    /// so the transformer must leave `BedrockRuntimeClient` untouched.
    #[test]
    fn bedrock_runtime_client_is_left_untouched() {
        let input = "import { BedrockRuntimeClient } from \"@aws-sdk/client-bedrock-runtime\";\nconst client = new BedrockRuntimeClient({ region: \"us-east-1\" });\n";

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("bedrock.ts");
        fs::write(&path, input).unwrap();
        let result = TypeScriptTransformer::new()
            .transform_file(
                &path,
                Provider::Bedrock,
                "https://api.promptguard.co/api/v1",
                "PROMPTGUARD_API_KEY",
                false,
            )
            .unwrap();

        assert!(!result.modified, "bedrock must be detect-only");
        let out = fs::read_to_string(&path).unwrap();
        assert_eq!(out, input, "BedrockRuntimeClient must be untouched");
    }

    /// Regression: `new OpenAI()` with NO options object was detected but
    /// silently reported "(no changes needed)", the call never routed
    /// through the proxy. An options object must be synthesized, mirroring
    /// the Python empty-args behavior. #60 has the header half of it.
    #[test]
    fn no_arguments_synthesizes_options_object() {
        let input = "import OpenAI from \"openai\";\nconst client = new OpenAI();\n";
        let out = transform_ts(input);
        assert!(
            out.contains("\"X-API-Key\": process.env.PROMPTGUARD_API_KEY"),
            "proxy auth header must be injected:\n{out}"
        );
        assert!(
            out.contains("baseURL: \"https://api.promptguard.co/api/v1\""),
            "proxy URL must be injected:\n{out}"
        );
        assert_reparses_clean(&out);
    }

    /// Comment-only argument lists must keep the comment and stay valid.
    #[test]
    fn comment_only_arguments_synthesize_and_keep_comment() {
        let input =
            "import OpenAI from \"openai\";\nconst client = new OpenAI(/* configured later */);\n";
        let out = transform_ts(input);
        assert!(out.contains("baseURL:"));
        assert!(
            out.contains("/* configured later */"),
            "comment kept:\n{out}"
        );
        assert_reparses_clean(&out);
    }

    /// A non-object argument (identifier, call, spread, …) means the options
    /// come from elsewhere, the call must be left untouched.
    #[test]
    fn identifier_argument_is_left_untouched() {
        let input = "import OpenAI from \"openai\";\nconst client = new OpenAI(config);\n";
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("client.ts");
        fs::write(&path, input).unwrap();
        let result = TypeScriptTransformer::new()
            .transform_file(
                &path,
                Provider::OpenAI,
                "https://api.promptguard.co/api/v1",
                "PROMPTGUARD_API_KEY",
                false,
            )
            .unwrap();
        assert!(!result.modified, "identifier args must not be rewritten");
        assert_eq!(
            result.needs_manual_routing, 1,
            "the skip must be reported as needing manual routing"
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), input);
    }

    /// Bedrock is detect-only: an empty argument list must NOT get a
    /// synthesized options object either.
    #[test]
    fn bedrock_empty_arguments_left_untouched() {
        let input = "import { BedrockRuntimeClient } from \"@aws-sdk/client-bedrock-runtime\";\nconst client = new BedrockRuntimeClient();\n";
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("bedrock.ts");
        fs::write(&path, input).unwrap();
        let result = TypeScriptTransformer::new()
            .transform_file(
                &path,
                Provider::Bedrock,
                "https://api.promptguard.co/api/v1",
                "PROMPTGUARD_API_KEY",
                false,
            )
            .unwrap();
        assert!(!result.modified, "bedrock must stay detect-only");
        assert_eq!(fs::read_to_string(&path).unwrap(), input);
    }

    /// Gemini is detect-only in TS: `@google/genai` reads its base URL from
    /// `httpOptions.baseUrl`, NOT a top-level `baseURL` (verified against the
    /// package's `GoogleGenAIOptions` type, which has no top-level base-URL
    /// field, only `httpOptions` carries `baseUrl`).
    /// A `baseURL:` injection would be silently ignored (false coverage), so
    /// the transformer must leave `new GoogleGenAI({...})` untouched.
    #[test]
    fn gemini_googlegenai_is_left_untouched() {
        let input = "import { GoogleGenAI } from \"@google/genai\";\nconst client = new GoogleGenAI({ apiKey: k });\n";

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("gem.ts");
        fs::write(&path, input).unwrap();
        let result = TypeScriptTransformer::new()
            .transform_file(
                &path,
                Provider::Gemini,
                "https://api.promptguard.co/api/v1",
                "PROMPTGUARD_API_KEY",
                false,
            )
            .unwrap();

        assert!(!result.modified, "gemini must be detect-only");
        let out = fs::read_to_string(&path).unwrap();
        assert_eq!(out, input, "GoogleGenAI must be untouched");
    }

    /// Gemini detect-only also covers the empty-argument-list case: no options
    /// object must be synthesized (that would inject an ignored `baseURL`).
    #[test]
    fn gemini_empty_arguments_left_untouched() {
        let input =
            "import { GoogleGenAI } from \"@google/genai\";\nconst client = new GoogleGenAI();\n";
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("gem.ts");
        fs::write(&path, input).unwrap();
        let result = TypeScriptTransformer::new()
            .transform_file(
                &path,
                Provider::Gemini,
                "https://api.promptguard.co/api/v1",
                "PROMPTGUARD_API_KEY",
                false,
            )
            .unwrap();
        assert!(!result.modified, "gemini must stay detect-only");
        assert_eq!(fs::read_to_string(&path).unwrap(), input);
    }

    #[test]
    fn simple_options_object_reparses_clean() {
        let input =
            "import OpenAI from \"openai\";\nconst client = new OpenAI({apiKey: process.env.KEY});\n";
        let out = transform_ts(input);
        assert!(out.contains("apiKey: process.env.KEY"));
        assert!(out.contains("baseURL:"));
        assert_reparses_clean(&out);
    }
}
