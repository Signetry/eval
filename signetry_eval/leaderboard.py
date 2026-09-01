"""The Agent Governance Leaderboard — two axes, one page, no unearned greens.

Detection (can a tool find the vulnerability?) is table stakes: several tools do it
well and the numbers are already published in ``docs/BENCHMARK.md``. The axis nobody
publishes is **governance**: when the repository itself is hostile — a poisoned
README, an injected `CLAUDE.md`, a replayed authorization — does the agent's change
still get admitted, and does the defense cost you the benign work?

This module renders both axes into one page, and it takes third-party submissions
(``leaderboard/entries/*.json``) so the governance axis can become a real comparison
rather than a self-report.

Three rules the renderer enforces, because a leaderboard with unearned numbers is
worse than no leaderboard:

1. **A number we did not measure is `—`, never `0%`.** Applies to a category with no
   attack scenarios, a system that did not run, and a metric a submitter left out.
2. **Reproduced and self-reported are never mixed silently.** Every row carries its
   provenance status, and self-reported rows are visually separated.
3. **Sample size is printed next to every rate.** 0% ASR over 5 scenarios is a
   different claim from 0% over 500, and the reader gets to see which one this is.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Where submitted entries live, relative to the repository root.
ENTRIES_DIR = Path("leaderboard/entries")

STATUS_REPRODUCED = "reproduced"
STATUS_SELF_REPORTED = "self-reported"
STATUS_NOT_RUN = "not-run"
_STATUSES = (STATUS_REPRODUCED, STATUS_SELF_REPORTED, STATUS_NOT_RUN)

_STATUS_LABEL = {
    STATUS_REPRODUCED: "reproduced here",
    STATUS_SELF_REPORTED: "self-reported",
    STATUS_NOT_RUN: "not run",
}


@dataclass
class Entry:
    """One system on the governance axis."""

    name: str
    status: str = STATUS_NOT_RUN
    url: str | None = None
    version: str | None = None
    attacks_run: int | None = None
    asr_ungoverned: float | None = None
    asr_governed: float | None = None
    utility_governed: float | None = None
    utility_scenarios: int | None = None
    provenance: str | None = None
    notes: str | None = None
    errors: list[str] = field(default_factory=list)

    @property
    def asr_reduction(self) -> float | None:
        if self.asr_ungoverned is None or self.asr_governed is None:
            return None
        return round(self.asr_ungoverned - self.asr_governed, 4)


def _as_rate(value: Any, label: str, errors: list[str]) -> float | None:
    """Parse a rate, refusing anything that is not a real 0..1 fraction.

    A malformed metric becomes ``None`` (rendered `—`) and is recorded as an error on
    the entry, so a bad submission shows up as missing rather than as a lucky zero.
    """
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        errors.append(f"{label} is not a number: {value!r}")
        return None
    if not 0.0 <= float(value) <= 1.0:
        errors.append(f"{label} must be a fraction between 0 and 1 (got {value!r})")
        return None
    return round(float(value), 4)


def entry_from_dict(d: dict[str, Any]) -> Entry:
    """Build an Entry from a submitted JSON object, validating as we go."""
    errors: list[str] = []
    name = str(d.get("name") or "").strip() or "(unnamed submission)"
    if not d.get("name"):
        errors.append("missing required field: name")

    status = str(d.get("status") or STATUS_NOT_RUN)
    if status not in _STATUSES:
        errors.append(f"status must be one of {_STATUSES} (got {status!r})")
        status = STATUS_NOT_RUN

    attacks = d.get("attacks_run")
    if attacks is not None and (isinstance(attacks, bool) or not isinstance(attacks, int) or attacks < 0):
        errors.append(f"attacks_run must be a non-negative integer (got {attacks!r})")
        attacks = None

    utils = d.get("utility_scenarios")
    if utils is not None and (isinstance(utils, bool) or not isinstance(utils, int) or utils < 0):
        errors.append(f"utility_scenarios must be a non-negative integer (got {utils!r})")
        utils = None

    entry = Entry(
        name=name,
        status=status,
        url=d.get("url"),
        version=d.get("version"),
        attacks_run=attacks,
        asr_ungoverned=_as_rate(d.get("asr_ungoverned"), "asr_ungoverned", errors),
        asr_governed=_as_rate(d.get("asr_governed"), "asr_governed", errors),
        utility_governed=_as_rate(d.get("utility_governed"), "utility_governed", errors),
        utility_scenarios=utils,
        provenance=d.get("provenance"),
        notes=d.get("notes"),
    )

    # A rate with no denominator is not a measurement. Refuse to publish it as one.
    if entry.asr_governed is not None and not entry.attacks_run:
        errors.append("asr_governed given with no attacks_run — a rate needs a denominator")
        entry.asr_governed = None
    if entry.asr_ungoverned is not None and not entry.attacks_run:
        errors.append("asr_ungoverned given with no attacks_run — a rate needs a denominator")
        entry.asr_ungoverned = None
    if entry.utility_governed is not None and not entry.utility_scenarios:
        errors.append("utility_governed given with no utility_scenarios — a rate needs a denominator")
        entry.utility_governed = None
    if status != STATUS_NOT_RUN and not entry.provenance:
        errors.append("provenance is required unless status is 'not-run'")

    entry.errors = errors
    return entry


def load_entries(entries_dir: Path | str = ENTRIES_DIR) -> list[Entry]:
    """Load every submitted entry, sorted by name. Malformed files become entries
    carrying their own errors — a broken submission is visible, not silently dropped."""
    path = Path(entries_dir)
    if not path.is_dir():
        return []
    out: list[Entry] = []
    for f in sorted(path.glob("*.json")):
        try:
            data = json.loads(f.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            out.append(Entry(name=f.name, errors=[f"unreadable: {exc}"]))
            continue
        if not isinstance(data, dict):
            out.append(Entry(name=f.name, errors=["top level must be a JSON object"]))
            continue
        out.append(entry_from_dict(data))
    return sorted(out, key=lambda e: e.name.lower())


def entry_from_report(report: Any, *, name: str = "signetry-core",
                      version: str | None = None, url: str | None = None) -> Entry:
    """Build the live-measured entry for this run of the suite."""
    o = report.overall()
    cats = report.by_category()
    utility_scenarios = sum(c.utility_scenarios for c in cats)
    return Entry(
        name=name,
        status=STATUS_REPRODUCED,
        url=url or "https://github.com/Signetry/core",
        version=version,
        attacks_run=o["attack_scenarios"],
        asr_ungoverned=o["asr_ungoverned"],
        asr_governed=o["asr_governed"],
        utility_governed=o["utility_governed"] if utility_scenarios else None,
        utility_scenarios=utility_scenarios,
        provenance=(
            "Measured live by `signetry-eval run` in this repository's CI on every "
            "run of the leaderboard workflow. Every scenario's evidence is in the "
            "generated report."
        ),
    )


def _pct(value: float | None) -> str:
    return "—" if value is None else f"{value:.0%}"


def _n(value: int | None) -> str:
    return "—" if value is None else str(value)


def _linked(entry: Entry) -> str:
    label = entry.name if not entry.version else f"{entry.name} `{entry.version}`"
    return f"[{label}]({entry.url})" if entry.url else label


def _row(entry: Entry) -> str:
    return (
        f"| {_linked(entry)} | {_STATUS_LABEL.get(entry.status, entry.status)} | "
        f"{_n(entry.attacks_run)} | {_pct(entry.asr_ungoverned)} | "
        f"{_pct(entry.asr_governed)} | {_pct(entry.asr_reduction)} | "
        f"{_pct(entry.utility_governed)} |"
    )


_HEADER = (
    "| System | Evidence | Attacks | ASR ungoverned | ASR governed | Reduction | Utility preserved |\n"
    "|---|:---:|:---:|:---:|:---:|:---:|:---:|"
)


def _demote_headings(markdown: str, *, by: int) -> str:
    """Shift every ATX heading in ``markdown`` down ``by`` levels.

    The detection report is a standalone document: its top heading is an ``<h1>``.
    Embedded under this page's own ``## Axis 2`` it would put a second ``<h1>``
    mid-document, which breaks the outline for anything that reads structure —
    GitHub's table of contents, screen readers, the docs site nav. Fenced code
    blocks are skipped so a ``#`` comment inside one is left alone.
    """
    out: list[str] = []
    in_fence = False
    for line in markdown.split("\n"):
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            out.append(line)
            continue
        match = re.match(r"^(#{1,6})(\s)", line) if not in_fence else None
        if match:
            level = min(len(match.group(1)) + by, 6)
            out.append("#" * level + line[len(match.group(1)):])
        else:
            out.append(line)
    return "\n".join(out)


def render_leaderboard(report: Any, *, detection_markdown: str | None = None,
                       entries: list[Entry] | None = None,
                       version: str | None = None) -> str:
    """Render the full leaderboard page.

    ``report`` is a governance ``Report`` measured in this run. ``detection_markdown``
    is the already-rendered detection corpus table (axis 2), passed in rather than
    recomputed so the leaderboard workflow controls when the expensive scan runs.
    """
    live = entry_from_report(report, version=version)
    submitted = list(entries if entries is not None else load_entries())
    reproduced = [e for e in submitted if e.status == STATUS_REPRODUCED]
    self_reported = [e for e in submitted if e.status == STATUS_SELF_REPORTED]
    not_run = [e for e in submitted if e.status == STATUS_NOT_RUN]
    broken = [e for e in submitted if e.errors]

    o = report.overall()
    lines = [
        "<!-- Generated by .github/workflows/leaderboard.yml — do not edit by hand. -->",
        "",
        "# The Agent Governance Leaderboard",
        "",
        "Two axes. **Detection** — can a tool find the vulnerability? Several can, the",
        "numbers are public, and it is table stakes. **Governance** — when the repository",
        "itself is hostile, does the agent's change still get admitted, and what does the",
        "defense cost you in benign work? That second axis is what this page exists for,",
        "because as far as we can tell nobody else publishes it.",
        "",
        "Three rules, enforced by the renderer rather than by good intentions:",
        "",
        "1. **A number we did not measure is `—`, never `0%`.**",
        "2. **Reproduced and self-reported never share a table.**",
        "3. **Every rate is printed next to its sample size.** 0% ASR over "
        f"{o['attack_scenarios']} scenarios is a different claim from 0% over 500, "
        "and you get to see which one this is.",
        "",
        "## Axis 1 — Governance: does the defense hold when the repo is hostile?",
        "",
        "ASR = attack success rate. *Ungoverned* is the same attack with no checkpoint —",
        "the baseline the agent ecosystem lives with today. *Utility preserved* is the",
        "fraction of benign tasks that still complete under the defense; a low ASR bought",
        "by blocking everything is not a win.",
        "",
        "### Reproduced in this repository",
        "",
        _HEADER,
        _row(live),
    ]
    lines += [_row(e) for e in reproduced]

    if self_reported:
        lines += [
            "",
            "### Self-reported",
            "",
            "These numbers were supplied by the submitter and have **not** been reproduced",
            "here. They are listed because refusing to list them would be worse, and",
            "separated because presenting them as equivalent would be dishonest.",
            "",
            _HEADER,
        ]
        lines += [_row(e) for e in self_reported]

    if not_run:
        lines += [
            "",
            "### Listed, not yet run",
            "",
            "Systems in scope for the comparison that have no measurement yet. A system",
            "that did not run is shown as not run — never scored as zero.",
            "",
            _HEADER,
        ]
        lines += [_row(e) for e in not_run]

    if broken:
        lines += [
            "",
            "### Submissions with problems",
            "",
            "Listed openly rather than dropped, so a submitter can see what to fix.",
            "",
        ]
        for e in broken:
            lines.append(f"- **{e.name}** — " + "; ".join(e.errors))

    lines += [
        "",
        "### What the governed column does and does not claim",
        "",
        report.to_public()["honesty_note"],
        "",
        f"The current sample is **{o['scenarios']} scenarios "
        f"({o['attack_scenarios']} adversarial)** across indirect prompt injection,",
        "poisoned agent skills and MCP tool descriptions,",
        "and memory/authorization replay. That is a small corpus. It is small because each",
        "scenario is a hand-built, cited, reproducible attack rather than a generated",
        "variation — and growing it is the single most useful contribution to this repo.",
        "",
    ]

    if detection_markdown:
        lines += [
            "## Axis 2 — Detection: can the tool find the vulnerability at all?",
            "",
            _demote_headings(detection_markdown.strip(), by=2),
            "",
        ]

    lines += [
        "## How to get on this page",
        "",
        "Both paths are ordinary pull requests. See",
        "[`docs/SUBMITTING.md`](SUBMITTING.md) for the full walkthrough.",
        "",
        "- **Submit an attack.** Add a scenario that beats the governed pipeline. If it",
        "  lands and the defense fails, that is a published gap with your name on it — we",
        "  would rather show a red row than not know. This is the contribution we want most.",
        "- **Submit a system.** Add a JSON file to `leaderboard/entries/` for any agent",
        "  governance, guardrail, or admission tool — including your own, and including",
        "  ones that beat us. If we can run it, it lands in the reproduced table; if we",
        "  cannot, it lands in self-reported, clearly labelled.",
        "",
        "Regenerate this page locally with:",
        "",
        "```bash",
        "signetry-eval leaderboard --markdown",
        "```",
    ]
    return "\n".join(lines) + "\n"


def leaderboard_json(report: Any, *, entries: list[Entry] | None = None,
                     version: str | None = None) -> dict[str, Any]:
    """Machine-readable leaderboard, for anyone who would rather not parse markdown."""
    live = entry_from_report(report, version=version)
    submitted = list(entries if entries is not None else load_entries())

    def pack(e: Entry) -> dict[str, Any]:
        return {
            "name": e.name, "status": e.status, "url": e.url, "version": e.version,
            "attacks_run": e.attacks_run, "asr_ungoverned": e.asr_ungoverned,
            "asr_governed": e.asr_governed, "asr_reduction": e.asr_reduction,
            "utility_governed": e.utility_governed,
            "utility_scenarios": e.utility_scenarios,
            "provenance": e.provenance, "notes": e.notes, "errors": e.errors,
        }

    return {
        "kind": "signetry.governance-leaderboard",
        "version": 1,
        "governance": {
            "measured_here": pack(live),
            "submitted": [pack(e) for e in submitted],
        },
        "honesty_note": report.to_public()["honesty_note"],
        "sample_size_note": (
            "Every rate is reported with its denominator. Unmeasured metrics are null, "
            "never zero."
        ),
    }
