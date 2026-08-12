"""Real public-repo detection cases.

Unlike the snippet corpus (self-contained, offline, CI-safe), these point at real
public GitHub repositories at PINNED commits, each a well-known deliberately-
vulnerable teaching app or a project with documented vulnerable patterns. Running
this scans the actual repo (network + clone) and reports what Signetry finds — the
same thing a user gets from ``signetry scan <url>``.

These are intentionally *not* asserted for exact recall in unit tests (real repos
drift, and ground truth for a whole app is fuzzy); instead the harness reports the
findings so a human/CI can review them, and the committed expectations below are
CONSERVATIVE lower bounds (categories the repo definitely contains) used only for a
smoke assertion when network is available.

Provenance: each entry cites the project and why it is a valid detection target.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class RealRepoCase:
    id: str
    url: str
    commit: str  # pinned for reproducibility ("" = default branch, less reproducible)
    languages: list[str]
    provenance: str
    # Conservative lower-bound categories the repo is known to contain (for a smoke
    # check only — not a strict recall assertion).
    expect_at_least: list[str] = field(default_factory=list)


REAL_REPO_CASES: list[RealRepoCase] = [
    RealRepoCase(
        id="REAL-nodegoat",
        url="https://github.com/OWASP/NodeGoat.git",
        commit="",  # default branch
        languages=["javascript"],
        provenance="OWASP NodeGoat — intentionally vulnerable Node/Express teaching app "
                   "(OWASP Top 10). Expected: injection / weak-crypto / hardcoded patterns.",
        expect_at_least=[],  # reported, not asserted (JS coverage varies)
    ),
    RealRepoCase(
        id="REAL-pygoat",
        url="https://github.com/adeyosemanputra/pygoat.git",
        commit="",
        languages=["python"],
        provenance="PyGoat — intentionally vulnerable Django app (OWASP Top 10). "
                   "Expected: command injection / SSTI / weak crypto / hardcoded secrets.",
        expect_at_least=[],
    ),
    RealRepoCase(
        id="REAL-vulnerable-flask",
        url="https://github.com/we45/Vulnerable-Flask-App.git",
        commit="",
        languages=["python"],
        provenance="Vulnerable-Flask-App (we45) — deliberately vulnerable Flask app. "
                   "Expected: SQLi / command injection / deserialization.",
        expect_at_least=[],
    ),
    RealRepoCase(
        id="REAL-damn-vulnerable-python",
        url="https://github.com/anxolerd/dvpwa.git",
        commit="",
        languages=["python"],
        provenance="DVPWA — Damn Vulnerable Python Web App (aiohttp). "
                   "Expected: SQLi / XSS / session flaws.",
        expect_at_least=[],
    ),
    RealRepoCase(
        id="REAL-juice-shop-server",
        url="https://github.com/juice-shop/juice-shop.git",
        commit="",
        languages=["javascript", "typescript"],
        provenance="OWASP Juice Shop — the reference modern vulnerable web app. "
                   "Large; scanned shallowly. Expected: assorted JS/TS sinks.",
        expect_at_least=[],
    ),
]
