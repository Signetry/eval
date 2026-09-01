"""Corpus benchmark harness — score any scanner across the 20-case public corpus.

Per-case scoring against ground truth:
- A **vulnerable** case contributes each ``ExpectedFinding`` to the recall
  denominator; a scanner is credited when it reports the same (file, category).
- A **safe** case contributes to the false-positive count: any finding a scanner
  reports on a safe case is a false positive.

Aggregate metrics: recall (detected / expected), false-positive count, per-family
breakdown, and a per-language breakdown so breadth is visible. Competitor scanners
are scored from captured JSON (replayed offline) or reported ``not_run`` — never
faked, matching signetry-eval's honesty rule.

A case the scanner was never run on (absent from its capture) is marked
``covered=False`` and excluded from every aggregate. Captures are point-in-time and
this corpus grows, so counting a later-added case as a miss would publish a red on
evidence that does not exist — and it would do so against a named competitor. Every
rate is therefore reported over the cases that scanner actually saw, with the
coverage printed beside it.
"""
from __future__ import annotations

import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .benchmark import ScannerResult, normalise_category
from .corpus import ALL_CASES, Case

# A CorpusAdapter scans ONE case's files (written to a temp dir) and returns the
# scanner's findings for that case.
CorpusAdapter = Callable[[Case, Path], ScannerResult]


@dataclass
class CaseScore:
    case_id: str
    family: str
    language: str
    is_safe: bool
    expected: int
    detected: int
    false_positives: int
    detected_categories: list[str] = field(default_factory=list)
    missed_categories: list[str] = field(default_factory=list)
    # False when this scanner was never run on the case (not in its capture). Such a
    # case is excluded from every aggregate below rather than counted as a miss.
    covered: bool = True

    def to_public(self) -> dict:
        return {
            "case_id": self.case_id, "family": self.family, "language": self.language,
            "is_safe": self.is_safe, "covered": self.covered,
            "expected": self.expected, "detected": self.detected,
            "false_positives": self.false_positives,
            "missed": list(self.missed_categories),
        }


@dataclass
class CorpusScore:
    name: str
    ran: bool
    cases: list[CaseScore] = field(default_factory=list)
    note: str = ""

    @property
    def covered_cases(self) -> list[CaseScore]:
        """Only the cases this scanner was actually run on. Every rate uses these."""
        return [c for c in self.cases if c.covered]

    @property
    def uncovered_cases(self) -> list[CaseScore]:
        return [c for c in self.cases if not c.covered]

    @property
    def expected_total(self) -> int:
        return sum(c.expected for c in self.covered_cases)

    @property
    def detected_total(self) -> int:
        return sum(c.detected for c in self.covered_cases)

    @property
    def false_positive_total(self) -> int:
        return sum(c.false_positives for c in self.covered_cases)

    @property
    def recall(self) -> float | None:
        """Recall over the covered cases, or None when nothing was measured.

        None, not 0.0: a scanner with no covered cases has no recall, and rendering
        that as 0% would score an absent measurement as a total failure.
        """
        if not self.expected_total:
            return None
        return round(self.detected_total / self.expected_total, 4)

    def by_family(self) -> dict[str, dict]:
        out: dict[str, dict] = {}
        for c in self.covered_cases:
            b = out.setdefault(c.family, {"expected": 0, "detected": 0, "fp": 0})
            b["expected"] += c.expected
            b["detected"] += c.detected
            b["fp"] += c.false_positives
        return out

    def by_language(self) -> dict[str, dict]:
        out: dict[str, dict] = {}
        for c in self.covered_cases:
            b = out.setdefault(c.language, {"expected": 0, "detected": 0, "fp": 0})
            b["expected"] += c.expected
            b["detected"] += c.detected
            b["fp"] += c.false_positives
        return out

    def to_public(self) -> dict:
        return {
            "name": self.name, "ran": self.ran, "recall": self.recall,
            "detected": self.detected_total, "expected": self.expected_total,
            "false_positives": self.false_positive_total,
            "cases": len(self.covered_cases),
            "cases_in_corpus": len(self.cases),
            "cases_not_covered": [c.case_id for c in self.uncovered_cases],
            "by_family": self.by_family(),
            "by_language": self.by_language(),
            "note": self.note,
            "per_case": [c.to_public() for c in self.cases],
        }


def _score_case(case: Case, result: ScannerResult) -> CaseScore:
    if not result.ran:
        # The scanner was never run on this case. Record it, exclude it, do not score it.
        return CaseScore(case.id, case.family.value, case.language, case.is_safe,
                         expected=0, detected=0, false_positives=0, covered=False)
    found = {(f.file.split("/")[-1], normalise_category(f.category)) for f in result.findings}
    if case.is_safe:
        # every finding on a safe case is a false positive
        return CaseScore(case.id, case.family.value, case.language, True,
                         expected=0, detected=0, false_positives=len(result.findings))
    detected_cats: list[str] = []
    missed_cats: list[str] = []
    for e in case.expected:
        if (Path(e.file).name, e.category) in found:
            detected_cats.append(e.category)
        else:
            missed_cats.append(e.category)
    return CaseScore(
        case.id, case.family.value, case.language, False,
        expected=len(case.expected), detected=len(detected_cats), false_positives=0,
        detected_categories=detected_cats, missed_categories=missed_cats,
    )


def run_corpus_benchmark(name: str, adapter: CorpusAdapter, *, note: str = "") -> CorpusScore:
    """Run ``adapter`` over every case in the corpus and aggregate the score."""
    scores: list[CaseScore] = []
    for case in ALL_CASES:
        root = Path(tempfile.mkdtemp(prefix="signetry-corpus-"))
        try:
            for rel, content in case.files.items():
                p = root / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(content)
            result = adapter(case, root)
        finally:
            import shutil
            shutil.rmtree(root, ignore_errors=True)
        scores.append(_score_case(case, result))
    return CorpusScore(name=name, ran=True, cases=scores, note=note)


def not_run(name: str, note: str) -> CorpusScore:
    return CorpusScore(name=name, ran=False, cases=[], note=note)
