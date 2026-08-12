"""Adapters for the 20-case corpus benchmark.

- ``signetry_corpus_adapter`` runs the real signetry-core engine per case.
- ``captured_corpus_adapter`` replays a competitor's captured findings, keyed by
  case id, from a single JSON capture file of the shape:
      {"CASE-ID": {"findings": [{"file": ..., "category": ...}, ...]}, ...}
  A case absent from the capture yields no findings for that case (recorded as a
  miss, never fabricated). If the whole capture is missing, the scanner is
  reported as not-run by the caller.
"""
from __future__ import annotations

import json
from pathlib import Path

from .benchmark import DetectedFinding, ScannerResult, normalise_category
from .corpus import Case
from .corpus_benchmark import CorpusAdapter


def signetry_corpus_adapter(use_semgrep: bool = False) -> CorpusAdapter:
    def _run(case: Case, root: Path) -> ScannerResult:
        from signetry_core import scan_repository

        report = scan_repository(root, use_semgrep=use_semgrep)
        findings = [
            DetectedFinding(file=f.file, category=normalise_category(f.category))
            for f in report.findings
        ]
        return ScannerResult(name="signetry-core", ran=True, findings=findings)

    return _run


def load_capture(capture_path: str | Path) -> dict:
    """Load a per-case competitor capture; returns {} if missing/unreadable."""
    p = Path(capture_path)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def captured_corpus_adapter(capture: dict) -> CorpusAdapter:
    def _run(case: Case, _root: Path) -> ScannerResult:
        entry = capture.get(case.id) or {}
        items = entry.get("findings", []) if isinstance(entry, dict) else []
        findings = [
            DetectedFinding(
                file=str(it.get("file", "")),
                category=normalise_category(str(it.get("category", ""))),
            )
            for it in items if isinstance(it, dict) and it.get("file")
        ]
        return ScannerResult(name="captured", ran=True, findings=findings)

    return _run
