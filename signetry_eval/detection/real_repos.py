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
    # The cases above pin no commit, so they drift with their default branch. The two
    # below are pinned, and are the first JVM/Ruby targets here — every case above is
    # Python or JavaScript, which under-exercises the multi-language tier.
    RealRepoCase(
        id="REAL-webgoat",
        url="https://github.com/WebGoat/WebGoat.git",
        commit="7517acca95d9851da706452454c223dd13545ef4",
        languages=["java"],
        provenance="OWASP WebGoat — the reference deliberately-insecure Java teaching "
                   "app, maintained by OWASP. Pinned for reproducibility. Exercises the "
                   "Java tier (JDBC concatenation, XXE, native deserialization, path "
                   "traversal) that no other real-repo case here reaches.",
        expect_at_least=[],  # reported, not asserted (see the module docstring)
    ),
    RealRepoCase(
        id="REAL-railsgoat",
        url="https://github.com/OWASP/railsgoat.git",
        commit="0222f7da3406ba3ab637bc6d24ae9366b5f0a680",
        languages=["ruby"],
        provenance="OWASP RailsGoat — deliberately vulnerable Rails app covering the "
                   "OWASP Top 10. Pinned for reproducibility. First Ruby target here, so "
                   "it exercises the Ruby rules (interpolated SQL/command, YAML/Marshal "
                   "load) against real application code rather than snippets.",
        expect_at_least=[],
    ),
]
