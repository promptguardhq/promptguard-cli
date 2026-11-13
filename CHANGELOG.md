# Changelog

Product updates for every PromptGuard product, written for customers, are at [docs.promptguard.co/changelog](https://docs.promptguard.co/changelog); how long each version is supported is at [Versioning & support](https://docs.promptguard.co/versioning-and-support).

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

`Unreleased` holds work that is merged but not yet published. Move entries into
a dated version section when a release goes out, an `Unreleased` block that
survives three releases is a changelog nobody is maintaining.

## [Unreleased]

## [2.5.0] - 2026-11-13

### Added

- **The local MCP server's `promptguard_redact` takes `pii_types`, as the
  hosted tool does.** Name the PII types to redact in the REST API's
  vocabulary (detector names such as `email` or `phone_us`, the aliases
  `phone`, `ip_address` and `passport`, and `api_key`); omit it and the
  Project's policy decides, as before. An unknown name is a tool error whose
  structured content is `{"kind": "error", "error": ..., "code":
  "unknown_pii_type"}`, the hosted server's shape, and nothing is redacted or
  counted. The tool's description and parameters are the hosted tool's again.

- **`promptguard_redact` results carry `skipped`.** It lists the matches the
  API deliberately left in the text, such as an email at a domain reserved
  for documentation and testing (`example.com`, `.test`), with the reason
  `reserved_domain`. It is `[]` when nothing was skipped. An API from before
  the field sends none, and the tool then answers `[]` too, although that API
  may still have left a reserved-domain email in the text.

### Security

- **The lockfile moves `quinn-udp` to 0.5.16 (RUSTSEC-2026-0538) and `rustix`
  to 1.1.6 (RUSTSEC-2026-0486).** Neither was in the shipped binary:
  `quinn-udp` belongs to the HTTP client's HTTP/3 support, which the CLI does
  not enable, and `rustix` only to the test suite. The update keeps
  `cargo audit` clean.

## [2.4.1] - 2026-11-10

### Changed

- **Messages use plain punctuation.** Warnings, hints and generated shim
  comments that used an em or en dash now use a comma or colon instead. The
  wording is otherwise unchanged.

- **The MCP tool manifest copy is refreshed, and held to the platform's.**
  `tests/mcp-tool-definitions.json` now lists the hosted server's Read-stage
  tools and `promptguard_propose_suppression`. `scripts/check_mcp_tool_manifest.py`
  fails `make ci` and the pre-push hook when the copy is not byte-identical to
  the platform's `origin/main`, so it can no longer fall behind silently.

## [2.4.0] - 2026-11-05

### Added

- **`promptguard mcp install` adds PromptGuard's MCP server to every AI client
  on the machine.** It finds Claude Code, Codex, Cursor, VS Code, Windsurf and
  Claude Desktop and adds the hosted server, `https://api.promptguard.co/mcp`,
  to each: through `claude mcp add` and `codex mcp add` for the first two, by
  merging one `promptguard` entry into the JSON config of the others, and, for
  Claude Desktop, which takes remote servers only as connectors, by printing
  the step to add one. `--clients` limits it to named clients, `--dry-run`
  shows what would change, `--local` installs the local stdio server instead
  and `--url` points at another server. It never replaces a config file: other
  entries, key order and indentation are kept, the write is atomic, the
  original is kept as `<file>.bak`, an entry pointing elsewhere is left alone
  without `--force`, and a file that is not valid JSON is reported and not
  touched. No API key is written; each client signs in to PromptGuard itself.

## [2.3.1] - 2026-11-05

### Fixed

- **Links to the dashboard's API keys page work again.** `promptguard key`,
  `init`, `login`, `test`, the MCP server's `promptguard_auth` and
  `install.sh` sent you to `https://app.promptguard.co/settings/api-keys`,
  which does not exist, so the step that tells you where to get a key ended on
  a 404. They now link `https://app.promptguard.co/dashboard/api-keys`, and
  `init`'s sign-up link goes to `/register` instead of the missing `/signup`.
  A test now fails on any dashboard link the dashboard does not serve.

## [2.3.0] - 2026-11-05

### Added

- **`promptguard mcp` speaks MCP 2026-07-28 and 2025-11-25.** A 2026-07-28
  client needs no `initialize`: each request names its revision in `_meta`,
  `server/discover` answers with every revision the server speaks (2026-07-28,
  2025-11-25, 2025-06-18, 2025-03-26, 2024-11-05), its capabilities and its
  identity, and a revision it does not speak gets `-32022`
  (`UnsupportedProtocolVersionError`) with that list. Those results carry
  `resultType`, the server's identity in `_meta`, and, for `tools/list` and
  `server/discover`, `ttlMs` and `cacheScope`; `ping` and `logging/setLevel`,
  which 2026-07-28 removed, are unknown methods there. Older clients still
  open with `initialize`, which now also agrees on 2025-11-25.
- **`promptguard_scan_text` takes `content_type`** (`prompt`, the default, or
  `response`), so an agent can scan a model's output as well as a prompt. It is
  sent to the API as the scan `type`; any other value is a tool error the model
  can correct.

### Security

- **`promptguard mcp` no longer takes an API key through the chat.**
  `promptguard_auth` used to accept the key as a tool argument, which put it in
  the model's context, the client's transcript and any log of tool calls. The
  tool now only checks authentication and, when there is none, opens the
  dashboard and tells the user to save the key with `promptguard login` or
  `PROMPTGUARD_API_KEY`. A client still sending `api_key` is refused, and
  nothing is saved.
- **`promptguard_redact` no longer returns the un-redacted text.** It passed the
  API's response through whole, including the `original` field, so the PII it
  removed came straight back into the conversation. It now returns `redacted`
  and `piiFound` only, as the hosted server does.

### Changed

- **The MCP server follows the current spec.** `initialize` negotiates the
  protocol version (2025-06-18, 2025-03-26 or 2024-11-05) instead of always
  answering 2025-03-26. It no longer advertises a `logging` capability it never
  implemented. Every tool has a `title` and behaviour annotations, and the scan,
  redact, scan-project and status tools declare an `outputSchema` and return
  `structuredContent`. Calling a tool that does not exist is now a JSON-RPC
  `-32602` error rather than a tool result.
- **The shared MCP tools match the hosted server's exactly.** `scan_text`,
  `redact` and `status` now carry the hosted server's title, description,
  parameters and annotations: `scan_text` and `redact` are read-only (each
  call is still one metered Request, which their descriptions now say), and
  `tests/mcp-tool-definitions.json`, a copy of the platform's published tool
  manifest, fails a test on any drift. Every tool's `inputSchema` sets
  `additionalProperties: false`, and an undeclared argument is now a tool error
  naming it instead of being ignored.

## [2.2.4] - 2026-11-03

### Added

- **Every release is announced in Slack `#releases`.** The release workflow's
  new `announce` job posts the version and its GitHub Release once the
  release job has published it, through `scripts/post-release.sh`, a copy of
  the platform repo's script. It reads the `SLACK_RELEASES_WEBHOOK_URL`
  secret, and an unset secret or a Slack failure is a warning, never a failed
  release. The GitHub Release body was already this file's section.

### Changed

- The crate's author contact is now `support@promptguard.co`. `hello@promptguard.co`
  never existed, so mail to the address shown on crates.io bounced.
- The crate's `repository` and the README's install commands point at
  `github.com/promptguardhq/promptguard-cli`, where the repository now lives.
- Dependencies: `serde_json` 1.0.154, `icu_normalizer` 2.4.0, `open` 5.4.5 and
  `aws-lc-rs` 1.19.0 (#61).

### Fixed

- **`init` and `test` no longer tell you to run `promptguard logs`**, a command
  that does not exist. They now suggest `promptguard verify`, and a test fails
  if any message in the source names a subcommand the CLI does not have (#59).

### Security

- **tokio 1.51.6** (RUSTSEC-2026-0386): 1.51.1's safe `AsyncFd` constructors
  let safe code violate I/O safety. The CLI never constructs an `AsyncFd`;
  the lockfile bump clears the advisory (#58).

## [2.2.3] - 2026-10-23

### Security

- **`rustls-webpki` 0.103.16 and `webpki-root-certs` 1.0.11**, so certificate
  verification no longer accepts distrusted intermediates (RUSTSEC-2026-0382)
  and the bundled roots no longer trust the distrusted emSign intermediates
  (RUSTSEC-2026-0383).

## [2.2.2] - 2026-10-18

### Security

- **Replaced the deprecated `serde_yaml` with `serde-saphyr`**, a YAML library
  in safe Rust, for `policy apply`, `policy diff` and `policy export`.
  `serde_yaml` pulled in `unsafe-libyaml`, which is unmaintained
  (RUSTSEC-2024-0449). Existing policy files read exactly as before (YAML 1.2:
  `yes`/`on` stay strings, `<<` is an ordinary key). The differences:
  `policy export` now quotes strings with double quotes rather than single,
  and quotes `yes`; a value of `.inf`, `.nan` or with an unknown `!tag`, which
  used to reach the API silently as `null` or a one-key object, is now a
  `YAML parse error`; and a number with a redundant leading zero (`017`)
  reads as 17 where it used to be the string `"017"`.

## [2.2.1] - 2026-10-18

### Security

- **Updated `rustls` to 0.23.46 and `quinn-proto` to 0.11.19**, which fix
  RUSTSEC-2026-0338 to 0342 (quinn-proto) and RUSTSEC-2026-0346 to 0349
  (rustls). 2.2.0 shipped with the affected versions; upgrade to 2.2.1.

## [2.2.0] - 2026-10-18

### Added

- **`promptguard scan --offline` scans `--text` or `--file` content with no API
  key and no network**, for CI jobs that have neither. It matches a regex rule
  pack compiled into the binary (147 rules: prompt injection, jailbreak
  phrasings, provider credentials) and says on every run, `--json` included,
  that it is a local subset and not the full detection the PromptGuard API
  runs: no ML classifiers and no project policy. Matches are scored with the
  upstream rule set's own thresholds, so ordinary system prompts pass: only a
  block finding fails the scan, warnings and masked credentials are reported.
  `--untrusted` adds the indirect-injection rules for tool output and retrieved
  documents. Exit codes match the API scan's (0 clean, 2 a blocking finding, 1
  an error, including a file over 10 MiB). The pack is generated by
  `scripts/local-rules/regenerate.sh` and pinned by `tests/local_rules_tests.rs`
  (acebot712/promptguard#971). Its patterns and parity corpus were ported by
  the copyright holder from their own earlier private rule set and are
  licensed under this repository's Apache-2.0 licence; the pack's
  `provenance` block records the source files' hashes and what was left out.


- **`promptguard mcp-proxy` redacts tool results and scans and pins tool
  lists** (acebot712/promptguard#954).
  - The text of every `tools/call` result (text blocks, embedded resources'
    text, a resource link's name, title and description, string values of
    `structuredContent`, and a JSON-RPC error's message and data) goes through
    `POST /guard` as output, and what the project's guardrails mask is masked
    before the agent sees it; the envelope and every other block are left as
    they were. A blocked result is replaced by a `-32600` error in every mode.
    One the API cannot redact (an outage, the plan limit, too large, not done
    within 20 seconds) is relayed and logged as unredacted under `mixed` and
    `open`, and withheld under `closed`. A result needing more than 16 guard
    requests has its first 16 sent, so a block in them still applies.
    `resources/read`, `prompts/get` and the server's log notifications pass
    through unredacted.
  - Every `tools/list` result goes through `POST /mcp/manifest-scan` with the
    pin stored for the server, and each finding is logged. A paginated list is
    collected whole first (the proxy fetches the later pages) and relayed in
    one page. A tool with a `high` finding (a poisoned description,
    shadowing) is removed from the list in every mode, and a call to it is
    refused. So is any tool the scan cannot take: one that breaks the shape
    rules, one too large to scan alone, one refused with a 413/422, one the
    scan does not reach; a list over the endpoint's limits is split into
    several scans. A rug-pull (`E301`) names the server and the tools that
    changed; under `closed` the changed and added tools are withheld, under
    `mixed` and `open` the list is relayed, and it is reported on every run
    until accepted. A list the API cannot scan is refused under `closed` and
    relayed, logged as unchecked, otherwise.
  - **`--repin`** accepts a server's current tool list: on the first complete
    scan of the run it replaces that server's pin, and only that server's, and
    says so on stderr.
  - Pins are kept in `~/.promptguard/mcp-pins.json` (owner-only, written
    atomically under a lock), keyed by a SHA-256 of the server's command line
    and working directory. Each entry keeps a label (the program and, for a
    package runner, the package, without flag values or URL credentials) and
    no other argument. A missing file is created; a corrupt one is moved aside
    as `mcp-pins.json.corrupt-<timestamp>`, resetting every pin; one from a
    newer version is left untouched and the server runs unpinned.
  - A server message over 4 MiB is now dropped in every mode, and the request
    it answered gets a `-32600` error. At most 64 results and lists are
    inspected at once; past that the proxy stops reading the server rather
    than drop anything.
- **`promptguard mcp-proxy -- <server command>`** wraps a stdio MCP server and
  checks every tool call before the server sees it: first a local
  destructive-action check on the arguments (a pattern ported from our own
  earlier private rule set, which we extended to catch `rm -r -f`, `rm --recursive --force` in any order,
  `rm -rfv`, `find -delete`, `find -exec rm`, `DROP SCHEMA`, `TRUNCATE`,
  `DELETE FROM` with no `WHERE`, `dd`/`shred`/`wipefs` on a disk, a recursive
  `chmod`/`chown` of `/`, the fork bomb, `curl | sudo bash`, `base64 -d | sh`,
  `sh -c "$(curl ...)"`, a download piped into `python`/`perl`/`ruby`/`node`,
  `DROP INDEX`, `ALTER TABLE ... DROP`, `rm --rec --forc`,
  `Remove-Item -Recurse -Force`, `del /s`, `rmdir /s`, `git clean -f`,
  `git reset --hard` and a forced `git push`, after NFKC normalisation and with zero-width characters
  removed), then the API's
  `POST /agent/validate-tool`. A refused call is answered with JSON-RPC
  `-32600` and never reaches the server.
  - `--fail-mode open|closed|mixed` (default `mixed`) decides what happens when
    the API cannot be reached (no answer, a timeout or a 5xx; a 429 plan limit
    too, logged as such): `mixed` refuses calls the local check matches and
    relays the rest, logged to stderr as unchecked. A rejected key, another
    4xx or a malformed answer refuses the call in every mode, and a key the API
    rejects at startup stops the proxy before it starts the server.
  - Agent messages reach the server as the proxy parsed them, never as the
    agent's bytes; an agent line that is not JSON, or holds a bare carriage
    return, is dropped. A server that parses differently cannot see a tool
    call the proxy did not check.
  - Server output and stderr pass through untouched. Messages are bounded at
    4 MiB; at most 1024 requests may be pending, and a request reusing a
    pending id (`1` and `1.0` are one id) is refused, as are a tool call
    without an id and a batch holding anything but JSON-RPC objects.
  - The wrapped server does not inherit `PROMPTGUARD_API_KEY`, and logs name
    the server's program, never its arguments (acebot712/promptguard#943).

### Changed

- `SECURITY.md` links to the published disclosure policy
  (https://promptguard.co/security#reporting-a-vulnerability) instead of
  keeping its own copy of the response times.

### Fixed

- **The README lists only install methods that work.** The Homebrew tap it
  advertised was never published and will not be, so that line is gone. `cargo
  install promptguard` failed because the crate is not on crates.io; the Cargo
  method now builds the release tag from this repository (`cargo install
  --locked --git https://github.com/acebot712/promptguard-cli --tag cli-v2.1.2`).
  Linux ARM64 was listed as a supported platform but no release builds it, and
  Windows x86_64, which every release does build, was missing; the README now
  names each published binary. `promptguard update` and `install.sh` stopped
  suggesting Homebrew and the crates.io crate too, and `update` on Windows now
  points at the release binary instead of piping `install.sh` into `sh`. A new test,
  `tests/install_methods_tests.rs`, checks the README and `install.sh` against
  the release workflow's build matrix and fails when they disagree
  (acebot712/promptguard#962).


- **`promptguard scan --text` no longer reports a flagged result as clean.**
  When a detector's warn threshold flags content (promptguard#970), the API
  answers `allow` with `flagged: true`; the CLI printed "No security threats
  detected." It now prints `⚠️ FLAGGED` and says the content was allowed but
  flagged for review. The exit code is unchanged (clean), since nothing was
  blocked. `--json` passes the new `flagged` and `threshold` fields through.

## [2.1.2] - 2026-10-10

**No change to the CLI's own code.** No source file changed since 2.1.1; this
release rebuilds the binaries against newer patch versions of four direct
dependencies, so the published binaries match what `main` has been building
and testing.

### Changed

- **clap 4.6.6 → 4.6.7, reqwest 0.13.4 → 0.13.5, thiserror 2.0.20 → 2.0.21 and
  open 5.4.2 → 5.4.4** (#45). Patch releases of the argument parser, the HTTP
  client, the error-derive macro and the browser launcher. reqwest 0.13.5 moves
  to base64 0.23.1, so the lockfile carries that alongside 0.22.1. None of the
  four is a security fix: no advisory applied to the versions 2.1.1 shipped.
- The `dtolnay/rust-toolchain` action that installs Rust in CI and in the
  release build is pinned to a newer commit (#44). It still installs `stable`.

## [2.1.1] - 2026-09-18

### Security

- **rustls 0.23.45, for RUSTSEC-2026-0285.** The TLS stack every HTTP call in
  this CLI goes through. Published so the released binaries carry the patched
  version rather than only the source tree.

## [2.1.0] - 2026-09-06

### Added

- **`policy apply` accepts `tokenize` as a `pii_detection.mode`.** It validated
  the field against a hand-written list of `redact`/`mask`/`block` and rejected
  `tokenize`, telling you a value the API accepts is invalid. Tokenize is the
  reversible mode, the proxy tokenises on the way out and restores on the way
  back, streaming included, so the one PII mode whose effect can be undone was
  the one unreachable from policy-as-code.

  The platform had this same bug: `tokenize` was implemented end to end and then
  omitted from the write schema, which made a finished feature unreachable for
  every customer. This list is a third copy of that vocabulary and stays
  hand-maintained, so it now records where the source of truth is and that a new
  mode has to be added here too.

## [2.0.0] - 2026-08-26

What each removal means for your code, and what to use instead: [Upgrade to SDK and CLI 2.0](https://docs.promptguard.co/releases/sdk-v2-upgrade).

### Fixed

- **`redteam` was unreachable for every customer.** Its subcommands targeted
  `/internal/redteam`, the platform-admin plane, which rejects an API key
  outright, so the command could not have worked for anyone using the CLI as
  documented. It now targets the customer-facing `/api/v1/security-testing`.

### Removed

- **BREAKING: `logs` and `events` are gone.** Both called endpoints the API
  does not serve, so they only ever failed. Scripts invoking `promptguard logs`
  or `promptguard events` will now exit with an unrecognised-subcommand error
  rather than a request failure. There is no replacement command; security
  events are available in the dashboard.
- **BREAKING: `redteam --autonomous` and the intelligence-stats output are
  gone**, for the same reason: the endpoints behind them do not exist.

## [1.7.2] - 2026-08-19

### Security

- **h2 bumped to 0.4.17** for RUSTSEC-2026-0258. Versions below 0.4.16 accept
  and queue empty HTTP/2 DATA frames without limit, unbounded memory if
  streams are not drained, or a panic when the length overflows. It reaches the
  CLI transitively through `reqwest` -> `hyper`, so it sits under every API call
  the CLI makes. DoS only; no data exposure, no API change.

  Caught by this repo's nightly `cargo-deny` run, not by Dependabot, which
  reported no open alerts on this repository while the advisory was live.

