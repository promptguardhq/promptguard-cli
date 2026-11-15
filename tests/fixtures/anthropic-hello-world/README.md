# Anthropic/Claude Hello World Test Fixture

This fixture provides simple Anthropic Claude examples for testing the PromptGuard CLI.

## Files

- `hello.ts` - TypeScript Anthropic example
- `hello.js` - JavaScript Anthropic example
- `hello.py` - Python Anthropic example
- `.env` - Test environment variables
- `package.json` - Node.js dependencies
- `requirements.txt` - Python dependencies

## Usage with PromptGuard CLI

### Test Scanning

```bash
cd tests/fixtures/anthropic-hello-world
promptguard scan
```

Expected output: Should detect Anthropic SDK usage in all 3 files

### Test Initialization

```bash
promptguard init --api-key pg_live_xxx --dry-run
```

Expected behavior: Should show transformations for TypeScript, JavaScript, and Python files

### Test Apply (with git)

```bash
git init && git add . && git commit -m "Before PromptGuard"
promptguard init --api-key pg_live_xxx
```

Expected behavior: Should transform all Anthropic constructor calls to use PromptGuard proxy

### Test Revert (with git)

```bash
git diff                 # Review changes
git checkout -- .        # Revert code changes
promptguard revert -y    # Clean up config
```

Expected behavior: Should restore original files via git

## Expected Detections

The CLI should detect:

- **TypeScript (hello.ts)**: 1 Anthropic instance
- **JavaScript (hello.js)**: 1 Anthropic instance
- **Python (hello.py)**: 1 Anthropic instance
- **Total**: 3 instances across 3 files

## Expected Transformations

None, for now: `init` and `apply` leave these clients untouched and list them for manual
routing. The Anthropic SDK sends its own key in `X-Api-Key`, the header the proxy reads the
PromptGuard key from, and appends `/v1` to the base URL itself, so the generic rewrite cannot
work. Tracked in promptguardhq/promptguard-cli#66; the shape to set up by hand is on
docs.promptguard.co under Integrations, Anthropic.

## Model Used

This fixture uses Claude 3.5 Sonnet (`claude-3-5-sonnet-20241022`), the latest production model as of October 2024.
