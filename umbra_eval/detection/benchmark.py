"""Head-to-head detection benchmark — score any scanner against shared ground truth.

This measures the axis the competitor scanners (@openai/codex-security,
claude-code-security-review) are built for: **did the tool find the planted
vulnerabilities, and how many false positives did it raise?** It complements the
ASR/utility suite (which measures the governance axis competitors do not have).

A scanner is adapted to a ``ScannerAdapter``: given the fixture files on disk, it
returns a list of ``DetectedFinding`` (file + category, normalised). Scoring:

- **recall**    = in-scope ground-truth vulns detected / total in-scope
- **false_positives** = findings located in a SAFE file (any finding there is wrong)
- **precision-ish** we report FP count rather than precision, because a scanner may
  legitimately emit several findings per real vuln; FP-in-safe-file is unambiguous.

Umbra's adapter runs the real ``umbra_core`` engine. Competitor adapters accept a
pre-captured JSON output (so a run done once, with credentials, can be replayed
offline in CI) or are recorded as ``not_run`` — never faked.
"""
from __future__ import annotations

import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .fixture import SAFE_FILES, VULN_FILES, in_scope_ground_truth

# Map a scanner's own category vocabulary onto ours so matching is fair.
_CATEGORY_ALIASES: dict[str, str] = {
    "sql injection": "sql_injection", "sqli": "sql_injection", "sql_injection": "sql_injection",
    "command injection": "command_injection", "command_injection": "command_injection",
    "rce": "command_injection",
    "deserialization": "insecure_deserialization", "insecure_deserialization": "insecure_deserialization",
    "pickle": "insecure_deserialization",
    "xss": "xss", "reflected xss": "xss", "cross-site scripting": "xss",
    "weak_crypto": "weak_crypto", "weak crypto": "weak_crypto", "weak_hash": "weak_crypto",
    "md5": "weak_crypto",
    "code_injection": "code_injection", "eval_injection": "code_injection", "eval": "code_injection",
    "path_traversal": "path_traversal", "path traversal": "path_traversal",
    "debug_enabled": "debug_enabled", "debug_info_exposure": "debug_enabled", "debug": "debug_enabled",
    "hardcoded_secret": "hardcoded_secret", "hardcoded_keys_secrets": "hardcoded_secret",
    "hardcoded secret": "hardcoded_secret", "secret": "hardcoded_secret",
    "hardcoded_keys": "hardcoded_secret",
    "insecure_randomness": "insecure_randomness", "crypto_randomness": "insecure_randomness",
    "insecure randomness": "insecure_randomness",
    "open_redirect": "open_redirect", "open redirect": "open_redirect",
    "vulnerable_dependency": "vulnerable_dependency",
}


def normalise_category(raw: str) -> str:
    return _CATEGORY_ALIASES.get((raw or "").strip().lower(), (raw or "").strip().lower())


@dataclass(frozen=True)
class DetectedFinding:
    file: str
    category: str  # already normalised to our vocabulary


@dataclass
class ScannerResult:
    name: str
    ran: bool
    findings: list[DetectedFinding] = field(default_factory=list)
    note: str = ""


# A ScannerAdapter takes the root of a written-out fixture and returns a ScannerResult.
ScannerAdapter = Callable[[Path], ScannerResult]


@dataclass
class ScannerScore:
    name: str
    ran: bool
    detected: list[str] = field(default_factory=list)   # GT ids detected (in-scope)
    missed: list[str] = field(default_factory=list)     # GT ids missed (in-scope)
    false_positives: int = 0
    total_findings: int = 0
    note: str = ""

    @property
    def recall(self) -> float:
        n = len(self.detected) + len(self.missed)
        return round(len(self.detected) / n, 4) if n else 0.0

    def to_public(self) -> dict:
        return {
            "name": self.name,
            "ran": self.ran,
            "recall": self.recall,
            "detected": len(self.detected),
            "missed": len(self.missed),
            "in_scope_total": len(self.detected) + len(self.missed),
            "false_positives": self.false_positives,
            "total_findings": self.total_findings,
            "missed_ids": list(self.missed),
            "note": self.note,
        }


def _write_fixture() -> Path:
    """Write the vulnerable + safe fixture files to a temp dir; return the root."""
    root = Path(tempfile.mkdtemp(prefix="umbra-detect-bench-"))
    for rel, content in {**VULN_FILES, **SAFE_FILES}.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return root


def score(result: ScannerResult) -> ScannerScore:
    """Score a scanner's findings against the in-scope ground truth."""
    if not result.ran:
        gt = in_scope_ground_truth()
        return ScannerScore(name=result.name, ran=False,
                            missed=[g.id for g in gt], note=result.note or "not run")

    safe_files = set(SAFE_FILES)
    detected_ids: list[str] = []
    for g in in_scope_ground_truth():
        hit = any(
            f.file.endswith(Path(g.file).name) and normalise_category(f.category) == g.category
            for f in result.findings
        )
        (detected_ids if hit else None)
        if hit:
            detected_ids.append(g.id)
    all_ids = {g.id for g in in_scope_ground_truth()}
    missed = sorted(all_ids - set(detected_ids))
    # A false positive = a finding located in a SAFE file.
    fps = sum(1 for f in result.findings if any(f.file.endswith(Path(sf).name) for sf in safe_files))
    return ScannerScore(
        name=result.name, ran=True, detected=sorted(detected_ids), missed=missed,
        false_positives=fps, total_findings=len(result.findings), note=result.note,
    )


def run_benchmark(adapters: list[ScannerAdapter]) -> list[ScannerScore]:
    """Write the shared fixture once, run every adapter over it, and score each."""
    root = _write_fixture()
    try:
        scores: list[ScannerScore] = []
        for adapter in adapters:
            scores.append(score(adapter(root)))
        return scores
    finally:
        import shutil
        shutil.rmtree(root, ignore_errors=True)
