"""Capture claude-code-security-review output across the 20-case corpus.

Runs each corpus case's files through the local `claude` CLI using the ccsr audit
prompt, parses the JSON findings, and writes a per-case capture:
    {"CASE-ID": {"findings": [{"file","category"}, ...]}, ...}

This is a one-time, credentialed capture; the resulting JSON is replayed offline by
`umbra-eval corpus --claude-capture <file>`. Not part of the test suite (needs the
CLI + network). Run:  python -m umbra_eval.detection.capture_claude out.json
"""
# ruff: noqa: E501  (this module embeds a verbatim audit prompt; long lines are intentional)
from __future__ import annotations

import json
import re
import subprocess
import sys

from .corpus import ALL_CASES

_PROMPT = """You are a senior security engineer performing a focused security review of the file(s) below. \
Find HIGH-CONFIDENCE, exploitable security vulnerabilities only. Minimise false positives: do NOT flag \
safe code (parameterised queries, escaped output, arg-list subprocess, secure randomness, placeholder values). \
Do NOT report open redirects, DoS, or rate limiting.

Output STRICT JSON only, no prose:
{"findings":[{"file":"<path>","category":"<sql_injection|command_injection|insecure_deserialization|xss|path_traversal|hardcoded_secret|weak_crypto|code_injection|debug_enabled|insecure_randomness|tls_disabled>","severity":"HIGH"}]}
If there are no vulnerabilities, output {"findings":[]}.

FILES:
"""


def _run_claude(prompt: str, model: str = "sonnet", timeout: int = 180) -> str:
    proc = subprocess.run(
        ["claude", "-p", "--model", model],
        input=prompt, capture_output=True, text=True, timeout=timeout, check=False,
    )
    return proc.stdout


def _parse(raw: str) -> list[dict]:
    m = re.search(r"\{.*\}", raw, re.S)
    if not m:
        return []
    try:
        return json.loads(m.group(0)).get("findings", [])
    except json.JSONDecodeError:
        return []


def capture(out_path: str, model: str = "sonnet") -> None:
    result: dict[str, dict] = {}
    for case in ALL_CASES:
        blob = _PROMPT
        for rel, content in case.files.items():
            blob += f"\n=== {rel} ===\n{content}\n"
        raw = _run_claude(blob, model=model)
        findings = _parse(raw)
        result[case.id] = {"findings": findings}
        print(f"{case.id:40} -> {len(findings)} finding(s)", file=sys.stderr)
    with open(out_path, "w") as fh:
        json.dump(result, fh, indent=2)
    print(f"wrote capture: {out_path}", file=sys.stderr)


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "claude_corpus_capture.json"
    model = sys.argv[2] if len(sys.argv) > 2 else "sonnet"
    capture(out, model)
