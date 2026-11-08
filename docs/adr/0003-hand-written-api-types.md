# API response types are hand-written, not generated from the OpenAPI spec

`promptguard-python` and `promptguard-node` generate their API types from the
published OpenAPI spec, on a weekly `sync-from-api.yml` that opens a PR when the
spec moves. **This repo does not, and that is a decision, not an oversight.**
Recorded 2026-08-11 after checking the spec rather than guessing.

The response structs live in `src/commands/*.rs` (`SecurityScanResponse`,
`RedactResponse`, `GuardrailsResponse`, `LogsResponse`, `RedTeamTestResult`,
and `mcp-proxy`'s `ToolValidation`, `GuardAnswer` and `ManifestScan`) and
stay hand-written, because generating them would cost machinery and return
nothing:

- **The spec does not carry the information worth generating.** The one field
  where a generated type would help is `threatType`, and in
  `openapi-developer.json` it is `{"anyOf": [{"type": "string"}, {"type":
  "null"}]}`: no enum. The real values live in the backend's `ThreatType`
  StrEnum and never reach the published spec. A generator would emit
  `Option<String>`, which is what `SecurityScanResponse` already declares by
  hand. Same for `decision` and `reason`: bare strings.
- **Part of the surface is not in the published spec at all.** `promptguard
  redteam` calls `/internal/redteam/*`, which is internal-domain and appears
  only in the full `openapi.json`: a spec that is `.mintignore`d and not served
  publicly. `/health` is in neither spec. A sync would cover some endpoints and
  silently skip others, which is worse than covering none: it reads as complete.
- **The surface is small and slow.** Seven endpoints, and the structs pin the
  serde renames (`threatType`, `eventId`, `processingTimeMs`, `piiFound`) that
  the wire format actually uses. Those renames are the part that breaks, and a
  generator would reproduce them from the same spec that already agrees.

## Consequences

**What protects this repo instead:** the structs are `#[derive(Deserialize)]`
without `deny_unknown_fields`, so an added field is ignored and a *removed* or
renamed one fails at parse time in the integration tests, loudly, at the call
site, in the repo that owns the code.

Value vocabularies the backend owns (such as `VALID_PII_MODES` in
`src/commands/policy.rs`) are hand-maintained copies for the same reason, so a
value added on the backend has to be added here too.

**Revisit this if** the developer spec starts publishing real enums for
`threatType`/`decision`, or the CLI's endpoint count grows past a handful of
hand-maintainable structs. At that point copy the SDKs' `sync-from-api.yml`
wholesale; do not invent a second mechanism.
