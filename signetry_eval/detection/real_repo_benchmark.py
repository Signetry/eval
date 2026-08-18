"""Harness to scan the real public-repo detection cases with Signetry.

Network + git required (opt-in). For each pinned repo: shallow-clone, run the
Signetry engine, and report finding counts by category. This is exactly the
``signetry scan <url>`` path, aggregated for the benchmark, so it demonstrates the
live entry point on real code rather than snippets.
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .real_repos import REAL_REPO_CASES, RealRepoCase


@dataclass
class RealRepoResult:
    id: str
    url: str
    ran: bool
    files_scanned: int = 0
    total_findings: int = 0
    by_category: dict[str, int] = field(default_factory=dict)
    note: str = ""

    def to_public(self) -> dict:
        return {
            "id": self.id, "url": self.url, "ran": self.ran,
            "files_scanned": self.files_scanned, "total_findings": self.total_findings,
            "by_category": self.by_category, "note": self.note,
        }


def _git_available() -> bool:
    try:
        subprocess.run(["git", "--version"], capture_output=True, check=False)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def _checkout_pinned(root: Path, commit: str) -> str:
    """Check out a pinned commit in a (possibly shallow) clone.

    ``resolve_scan_target`` clones with ``--depth 1``, so the pinned object is not
    present and a plain ``git checkout <sha>`` fails. Previously that failure was
    swallowed (``check=False``) and the scan silently ran against the default-branch
    tip — so a "pinned for reproducibility" case was not actually pinned.

    Fetch the specific object first (GitHub permits fetching an arbitrary SHA), and
    if pinning genuinely cannot be honoured, say so in the note rather than
    reporting an unpinned scan as pinned.
    """
    fetched = subprocess.run(
        ["git", "fetch", "--quiet", "--depth", "1", "origin", commit],
        cwd=root, capture_output=True, check=False,
    )
    ref = "FETCH_HEAD" if fetched.returncode == 0 else commit
    checked = subprocess.run(
        ["git", "checkout", "-q", ref], cwd=root, capture_output=True, check=False,
    )
    if checked.returncode != 0:
        return f"NOT pinned (commit {commit[:12]} unreachable; scanned default branch)"
    return f"pinned @ {commit[:12]}"


def scan_real_repo(case: RealRepoCase, *, use_semgrep: bool = False, depth: int = 1) -> RealRepoResult:
    """Clone + scan one real repo. Returns a result; never raises (records notes)."""
    from signetry_core import scan_repository
    from signetry_core.pipeline.findings.fetch import resolve_scan_target

    if not _git_available():
        return RealRepoResult(case.id, case.url, ran=False, note="git unavailable")
    pin_note = ""
    try:
        with resolve_scan_target(case.url, depth=depth) as root:
            root = Path(root)
            if case.commit:
                pin_note = _checkout_pinned(root, case.commit)
            report = scan_repository(root, use_semgrep=use_semgrep)
    except RuntimeError as exc:
        return RealRepoResult(case.id, case.url, ran=False, note=f"clone/scan failed: {exc}")
    by_cat: dict[str, int] = {}
    for f in report.findings:
        by_cat[f.category] = by_cat.get(f.category, 0) + 1
    note = f"layers: {', '.join(report.layers)}"
    if pin_note:
        note = f"{pin_note} · {note}"
    return RealRepoResult(
        case.id, case.url, ran=True, files_scanned=report.files_scanned,
        total_findings=len(report.findings), by_category=by_cat,
        note=note,
    )


def scan_all_real_repos(*, use_semgrep: bool = False, depth: int = 1) -> list[RealRepoResult]:
    return [scan_real_repo(c, use_semgrep=use_semgrep, depth=depth) for c in REAL_REPO_CASES]


def render_text(results: list[RealRepoResult]) -> str:
    out = ["Signetry real public-repo detection", "=" * 44]
    for r in results:
        if not r.ran:
            out.append(f"  {r.id:28} NOT RUN ({r.note})")
        else:
            cats = ", ".join(f"{k}={v}" for k, v in sorted(r.by_category.items())) or "none"
            out.append(f"  {r.id:28} {r.total_findings:3d} findings / {r.files_scanned:4d} files  [{cats}]")
    return "\n".join(out)
