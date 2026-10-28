# AGENTS.md

Rust CLI for PromptGuard, published as a single binary: AST-based (Tree-sitter)
scanning for unprotected LLM calls, auto-fix code transforms, MCP server and
`mcp-proxy` modes, red team testing, and policy management.

## Where things live

- `src/main.rs` is the Clap entry point; each subcommand is a file in
  `src/commands/`.
- `src/local_rules/` is the rule pack behind `scan --offline`. It is
  **generated**: change it through `scripts/local-rules/regenerate.sh`, whose
  header says how.
- `src/commands/mcp_proxy/` wraps a stdio MCP server: it checks each
  `tools/call`, redacts each tool result (`redact.rs`) and scans and pins each
  tool list (`manifest.rs`, `pins.rs`). `destructive.rs` is a **safety
  boundary** (the platform's ADR-0034); treat a change to it as a security
  change. Its tests run against `tests/support/fake_mcp_server.py`.
- `tests/fixtures/` holds real project directories the scanner runs on;
  `tests/support/` holds test helpers that are not scanner fixtures.

## Setup: enable the tracked git hooks

Once per clone, because git never turns on a repo's own hooks for you:

```bash
git config core.hooksPath .githooks
git config promptguard.pushGate true    # optional: also run `make ci` on push
```

`.githooks/pre-push` scans the commits you are pushing for secrets. It is
scoped to that range on purpose: this repo is public, so a credential on `main`
is world-readable at once, while scanning the whole tree or the history fails on
its first run and teaches everyone `--no-verify`. Fixtures that are meant to
look like credentials (the env-var redaction tests) are exempted by path in
`.gitleaks.toml`, where the exemption is reviewable. The `make ci` push gate is
opt-in because fmt-check + clippy + test + build takes minutes on this workspace.

## Checks

The `Makefile` is the source of truth for commands (`make help`). After editing
Rust, run `make format` and `make lint`, and leave clippy at zero warnings
(`make lint` treats them as errors across all targets). Run `make ci` before
pushing; it is what CI runs.

## Coding standards

- CLI arguments use `clap` derive macros.
- Application errors return `anyhow::Result`; library code uses custom error
  types (`thiserror`). The `[lints]` table in `Cargo.toml` denies `unwrap`,
  `expect`, `panic!`, `exit` and `todo!`.
- Tests go in `tests/` as integration tests. The one case for an inline
  `#[cfg(test)]` module is testing a private function.

## API types are hand-written, deliberately

The API response structs in `src/commands/*.rs` are hand-written, and so are
copies of backend value lists such as `VALID_PII_MODES`. Keep them that way:
the published OpenAPI spec carries no enums worth generating and omits part of
the CLI's surface. The structs derive `Deserialize` without
`deny_unknown_fields`, so a removed or renamed field fails loudly in the
integration tests. **Before adding or changing an API type, or proposing to
generate them**, read `docs/adr/0003-hand-written-api-types.md` for the full
reasoning and the conditions that would reopen it.

## Commit messages

Imperative mood after the conventional type prefix `git log` shows
(`fix: Add X`, not `Added X`), describing what changed from the user's
perspective.

## Boundaries

### Ask first
- Adding new Cargo dependencies
- Changing the CLI interface (subcommands, flags, output format)
- Modifying Tree-sitter grammar usage

### Hard rules
- Keep API keys, tokens and credentials out of commits; the pre-push hook
  backs this up but only if it is enabled.
- A breaking change to the CLI interface ships only with a major version bump.

## Agent skills

### Issue tracker

Issues live in this repo's GitHub Issues, worked via the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

The five canonical triage roles, each label string equal to its name. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: `CONTEXT.md` plus `docs/adr/` at the repo root, both created lazily. See `docs/agents/domain.md`.
