"""The 20-case public detection corpus — schema + case definitions.

Purpose: a credible, independently-traceable benchmark so Signetry's detection can be
scored head-to-head against LLM scanners (claude-code-security-review /
@openai/codex-security) on cases a skeptic can verify. Every case records:

- ``provenance``: where the pattern comes from (OWASP, a public CVE, an academic
  dataset family like NIST SARD/Juliet, or a crafted edge case) with a citation
  string. Nothing here is scraped verbatim from a copyrighted corpus — cases are
  minimal reimplementations of *publicly documented* vulnerability patterns, each
  labelled with the canonical CWE, so the ground truth is auditable.
- ``expected``: the ground-truth findings (CWE class + which file). A SAFE case has
  an empty ``expected`` list — any finding on it is a false positive.
- ``language``: so language breadth is measured, not just Python.

Case families:
- PUBLIC   (1-7):  OWASP / real-CVE-shaped patterns.
- ACADEMIC (8-14): NIST SARD / Juliet / CWE-catalogue-shaped labelled snippets.
- CRAFTED  (15-20): obfuscation, taint-through-helper, and SAFE decoys that probe
                    false-positive robustness (the axis LLM filters trade against).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Family(str, Enum):
    PUBLIC = "public"
    ACADEMIC = "academic"
    CRAFTED = "crafted"
    HARD = "hard"
    MULTILANG = "multilang"


@dataclass(frozen=True)
class ExpectedFinding:
    """One ground-truth vulnerability expected in a case file."""

    cwe: str
    category: str  # signetry-normalised category (see benchmark._CATEGORY_ALIASES)
    file: str


@dataclass(frozen=True)
class Case:
    id: str
    family: Family
    language: str
    title: str
    provenance: str  # citation / source description — auditable
    files: dict[str, str]  # rel path -> source
    expected: list[ExpectedFinding] = field(default_factory=list)  # empty == SAFE case

    @property
    def is_safe(self) -> bool:
        return not self.expected
