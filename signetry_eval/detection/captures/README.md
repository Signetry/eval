# Competitor captures

These JSON files are **real captured outputs** of competitor scanners run against
the 20-case public corpus (`signetry_eval/detection/corpus/`). They are replayed
offline by `signetry-eval corpus --claude-capture <file>` so the head-to-head is
reproducible in CI without credentials.

Provenance (how each was produced):

- `claude-opus-4-8.json` — `claude-code-security-review`-style audit prompt run per
  case through the Claude Code CLI on model `claude-opus-4-8` (Opus 4.8).
- `claude-sonnet.json` — same prompt on model `sonnet`.

Regenerate with (requires the `claude` CLI + credentials):

    python -m signetry_eval.detection.capture_claude out.json claude-opus-4-8

Capture shape (per case id):

    { "PUB-01-sqli-python": { "findings": [ {"file": "app.py", "category": "sql_injection"} ] }, ... }

`@openai/codex-security` has no committed capture: at capture time the available
ChatGPT account was over its usage limit, so it is honestly reported as *not run*
rather than fabricated. Add `codex-security.json` here (same shape) once a run is
available and pass `--codex-capture`.
