"""Scanner adapters for the head-to-head detection benchmark.

- **Signetry** runs the real ``signetry_core`` detection engine (offline, deterministic).
- **Competitor adapters** replay a PRE-CAPTURED findings JSON (so a paid, credentialed
  run can be recorded once and re-scored offline in CI) — or, when no capture is
  provided, report ``ran=False`` so the tool is shown as *not run* rather than faked.

This mirrors signetry-eval's honesty rule: a tool that did not run is never presented
as if it produced results.
"""
from __future__ import annotations

import json
from pathlib import Path

from .benchmark import DetectedFinding, ScannerResult, normalise_category


def signetry_adapter(use_semgrep: bool = False):
    """Adapter running the real signetry-core layered engine over the fixture."""

    def _run(root: Path) -> ScannerResult:
        from signetry_core import scan_repository

        report = scan_repository(root, use_semgrep=use_semgrep)
        findings = [
            DetectedFinding(file=f.file, category=normalise_category(f.category))
            for f in report.findings
        ]
        layers = ", ".join(report.layers)
        return ScannerResult(name="signetry-core", ran=True, findings=findings,
                             note=f"layers: {layers}")

    return _run


def _findings_from_generic_json(data: dict) -> list[DetectedFinding]:
    """Parse the common {"findings": [{"file","category"|"check_id", ...}]} shape used
    by both claude-code-security-review and codex-security JSON output."""
    out: list[DetectedFinding] = []
    items = data.get("findings") or data.get("results") or []
    for it in items:
        if not isinstance(it, dict):
            continue
        file = it.get("file") or it.get("path") or (it.get("location", {}) or {}).get("file", "")
        cat = (it.get("category") or it.get("check_id") or it.get("rule_id")
               or it.get("type") or "")
        if file:
            out.append(DetectedFinding(file=str(file), category=normalise_category(str(cat))))
    return out


def captured_json_adapter(name: str, capture_path: str | Path | None):
    """Adapter that replays a competitor's captured findings JSON.

    ``capture_path`` points to a JSON file previously produced by running the
    competitor tool against the fixture. If it is None or missing, the adapter
    reports the tool as *not run* (never fabricates findings)."""

    def _run(_root: Path) -> ScannerResult:
        if not capture_path:
            return ScannerResult(name=name, ran=False,
                                 note="no captured output provided (requires credentials to run live)")
        p = Path(capture_path)
        if not p.exists():
            return ScannerResult(name=name, ran=False, note=f"capture not found: {p}")
        try:
            data = json.loads(p.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            return ScannerResult(name=name, ran=False, note=f"capture unreadable: {exc}")
        return ScannerResult(name=name, ran=True,
                             findings=_findings_from_generic_json(data),
                             note=f"replayed from {p.name}")

    return _run
