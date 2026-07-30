"""The 20-case public detection corpus.

Aggregates the three families (PUBLIC / ACADEMIC / CRAFTED) into one ordered list
and exposes helpers. The corpus is the scoring key for the head-to-head benchmark:
each vulnerable case lists its expected CWE findings; each SAFE case expects none.
"""
from __future__ import annotations

from . import academic, crafted, hard, multilang, public, xfile_lang
from .schema import Case, ExpectedFinding, Family

ALL_CASES: list[Case] = [
    *public.CASES, *academic.CASES, *crafted.CASES, *hard.CASES, *multilang.CASES,
    *xfile_lang.CASES,
]


def vulnerable_cases() -> list[Case]:
    return [c for c in ALL_CASES if not c.is_safe]


def safe_cases() -> list[Case]:
    return [c for c in ALL_CASES if c.is_safe]


def cases_for_family(family: str) -> list[Case]:
    return [c for c in ALL_CASES if c.family.value == family]


def total_expected_findings() -> int:
    return sum(len(c.expected) for c in ALL_CASES)


# Sanity: the corpus must have unique ids across all families.
assert len({c.id for c in ALL_CASES}) == len(ALL_CASES), "case ids must be unique"

__all__ = [
    "ALL_CASES",
    "Case",
    "ExpectedFinding",
    "Family",
    "cases_for_family",
    "safe_cases",
    "total_expected_findings",
    "vulnerable_cases",
]
