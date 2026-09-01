"""Adapters for the 20-case corpus benchmark.

- ``signetry_corpus_adapter`` runs the real signetry-core engine per case.
- ``captured_corpus_adapter`` replays a competitor's captured findings, keyed by
  case id, from a single JSON capture file of the shape:
      {"CASE-ID": {"findings": [{"file": ..., "category": ...}, ...]}, ...}
  A case **absent** from the capture returns ``ran=False`` for that case, and the
  scorer drops it from that scanner's denominator. It is not a miss: the scanner
  was never given the case. Captures are taken at a point in time and the corpus
  grows, so charging a scanner for cases added after its capture would report a
  red on evidence that does not exist — the same rule that shows an entirely
  unrun scanner as ``not run`` rather than zero, applied per case.
  An entry that IS present but lists no findings is a genuine miss.
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
        if case.id not in capture:
            # Not covered by this capture. ran=False tells the scorer to exclude the
            # case rather than charge the scanner with missing it.
            return ScannerResult(name="captured", ran=False,
                                 note=f"{case.id} is not in this capture")
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
