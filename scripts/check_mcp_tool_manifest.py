#!/usr/bin/env python3
"""Fail when tests/mcp-tool-definitions.json is not a byte copy of the platform's.

`tests/mcp-tool-definitions.json` is a copy of the platform monorepo's
`mcp-server/tool-definitions.json`, which the platform generates from its
hosted MCP server. `tests/mcp_tool_manifest_tests.rs` holds the CLI's tools to
its `shared_tools` and `cli_only_tools`, and the platform's own check compares
those two sections. Nothing compared the rest, so the copy fell behind on the
hosted-only tools for weeks (promptguardhq/promptguard#1124).

This compares the whole file with the platform checkout's `origin/main`, read
with `git show` rather than from its working tree, because other sessions move
the sibling's branch mid-change. It runs where both repos are on disk: the
pre-push hook and `make ci`. CI cannot run it: the platform repo is private
and this public repo's CI holds no credential for it, by design. Without a
sibling checkout it says it could not compare and exits 0.

To refresh the copy:

    git -C ../promptguard show origin/main:mcp-server/tool-definitions.json \\
        > tests/mcp-tool-definitions.json

    python3 scripts/check_mcp_tool_manifest.py --check
    PROMPTGUARD_PLATFORM_REPO=/path/to/promptguard python3 scripts/check_mcp_tool_manifest.py
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COPY = ROOT / "tests" / "mcp-tool-definitions.json"
CANONICAL = "mcp-server/tool-definitions.json"
# Beside the main checkout, and beside a worktree under promptguard-cli-worktrees/.
SIBLING_CANDIDATES = ("../promptguard", "../../promptguard")


def find_platform_repo() -> Path | None:
    named = os.environ.get("PROMPTGUARD_PLATFORM_REPO")
    candidates = [Path(named)] if named else [ROOT / c for c in SIBLING_CANDIDATES]
    for candidate in candidates:
        if (candidate / "mcp-server").is_dir():
            return candidate.resolve()
    if named:
        raise SystemExit(f"PROMPTGUARD_PLATFORM_REPO={named} has no mcp-server/ directory")
    return None


def canonical(repo: Path) -> bytes | None:
    """The platform's manifest on its origin/main, or None when it is not there."""
    # Without the caller's GIT_* variables: a git hook exports GIT_DIR, and
    # `git -C` honours it over the directory.
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    shown = subprocess.run(
        ["git", "-C", str(repo), "show", f"origin/main:{CANONICAL}"],
        capture_output=True,
        check=False,
        env=env,
    )
    return shown.stdout if shown.returncode == 0 else None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="exit 1 on drift (the default)")
    parser.parse_args(argv)

    repo = find_platform_repo()
    if repo is None:
        print("mcp tool manifest: no promptguard checkout beside this repo; not compared")
        return 0
    theirs = canonical(repo)
    if theirs is None:
        print(f"mcp tool manifest: {repo} origin/main has no {CANONICAL}; not compared")
        return 0
    if COPY.read_bytes() != theirs:
        print(
            f"{COPY.relative_to(ROOT)} is not a copy of {repo} origin/main:{CANONICAL}.\n"
            "Copy it across:\n"
            f"  git -C {repo} show origin/main:{CANONICAL} > {COPY.relative_to(ROOT)}",
            file=sys.stderr,
        )
        return 1
    print(f"mcp tool manifest: matches {repo} origin/main")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
