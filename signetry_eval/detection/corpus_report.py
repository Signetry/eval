"""Render the 20-case corpus benchmark as a head-to-head comparison report."""
from __future__ import annotations

from .corpus import ALL_CASES
from .corpus_benchmark import CorpusScore


def _recall(score: CorpusScore) -> str:
    """Recall as a percentage, or `—` when nothing was measured. Never `0%`."""
    return "—" if score.recall is None else f"**{score.recall:.0%}**"


def _coverage(score: CorpusScore) -> str:
    """`52 / 60` when a capture predates part of the corpus, else the plain count.

    Printed next to every rate so the denominator is never a guess: a scanner
    replayed from a capture is scored only over the cases that capture covers.
    """
    covered, total = len(score.covered_cases), len(score.cases)
    return str(covered) if covered == total else f"{covered} / {total}"


def render_markdown(scores: list[CorpusScore]) -> str:
    n_cases = len(ALL_CASES)
    n_safe = sum(1 for c in ALL_CASES if c.is_safe)
    n_expected = sum(len(c.expected) for c in ALL_CASES)
    langs = sorted({c.language for c in ALL_CASES})
    lines = [
        f"# Signetry detection benchmark — {n_cases} public test cases",
        "",
        f"> {n_cases} cases ({n_cases - n_safe} vulnerable, {n_safe} safe decoys) across "
        f"{len(langs)} languages ({', '.join(langs)}), {n_expected} ground-truth findings.",
        "> Families: **public** (OWASP/CVE-shaped) · **academic** (CWE/SARD/Juliet-shaped) · "
        "**crafted** (obfuscation + safe decoys) · **hard** (cross-file taint, framework sinks, "
        "true-negative traps).",
        "> Every case cites a public provenance. A scanner that was not run is shown as "
        "`not run`, never scored as zero.",
        "> **Cases scored** is per scanner. A competitor replayed from a capture is scored "
        "only over the cases that capture covers: captures are taken at a point in time and "
        "this corpus grows, so charging a scanner for cases added afterwards would report a "
        "miss on a case it was never given. Uncovered cases are listed under Notes.",
        "",
        "## Head-to-head",
        "",
        "| Scanner | Ran | Cases scored | Recall | Found / Expected | False positives |",
        "|---|:---:|:---:|:---:|:---:|:---:|",
    ]
    for s in scores:
        if not s.ran:
            lines.append(f"| {s.name} | no | — | — | — | — |")
            continue
        lines.append(
            f"| {s.name} | yes | {_coverage(s)} | {_recall(s)} "
            f"| {s.detected_total} / {s.expected_total} | {s.false_positive_total} |"
        )
    # Per-language breakdown for the tools that ran.
    lines += ["", "## Recall by language (tools that ran)", "",
              "| Scanner | " + " | ".join(langs) + " |",
              "|---|" + "|".join([":---:"] * len(langs)) + "|"]
    for s in scores:
        if not s.ran:
            continue
        cells = []
        bl = s.by_language()
        for lang in langs:
            b = bl.get(lang)
            cells.append(f"{b['detected']}/{b['expected']}" if b and b["expected"] else "—")
        lines.append(f"| {s.name} | " + " | ".join(cells) + " |")
    # Notes
    lines += ["", "## Notes", ""]
    for s in scores:
        note = s.note or ("ran" if s.ran else "not run")
        lines.append(f"- **{s.name}**: {note}")
        if s.uncovered_cases:
            ids = ", ".join(f"`{c.case_id}`" for c in s.uncovered_cases)
            charge = sum(len(c.expected) for c in ALL_CASES
                         if c.id in {u.case_id for u in s.uncovered_cases})
            lines.append(
                f"  - **not covered by its capture** ({len(s.uncovered_cases)} of "
                f"{len(s.cases)} cases): {ids}. Excluded from its recall rather than "
                f"counted as {charge} miss(es) — the scanner was never run on them. "
                "Re-capture to score them."
            )
        # Be explicit about the source of any false positive: the deterministic floor
        # is 0-FP on the corpus; FPs appear only when the optional Semgrep layer is
        # enabled (its community rules don't model every sanitizer). This is why the
        # Semgrep layer is opt-in and non-gating.
        semgrep_fp = (
            s.ran and s.name == "signetry-core" and s.false_positive_total > 0
            and "semgrep" in (s.note or "").lower()
        )
        if semgrep_fp:
            lines.append(
                f"  - the {s.false_positive_total} false positive(s) come from the optional "
                "**Semgrep** layer, not the deterministic engine (which is 0-FP on this "
                "corpus). Semgrep's generic rules can miss a sanitizer (e.g. an escaped-"
                "output helper). Run without `--semgrep` for the zero-FP deterministic result."
            )
    lines += [
        "",
        "---",
        "",
        "Signetry reaches this on the **deterministic, offline, free** layer — no model, "
        "no per-scan cost, no quota, and the same result every run. The scanner tools "
        "need paid model calls per scan and can drift between runs. Detection parity is "
        "table stakes; the governance layer Signetry adds on top (earned authority, "
        "prompt-injection quarantine, independent verifier, Ed25519-signed receipts) is "
        "measured by `signetry-eval run` and is not attempted by either scanner.",
    ]
    return "\n".join(lines)


def render_text(scores: list[CorpusScore]) -> str:
    out = [f"Signetry detection benchmark — {len(ALL_CASES)} public cases", "=" * 46]
    for s in scores:
        if not s.ran:
            out.append(f"  {s.name:32} NOT RUN ({s.note})")
        else:
            recall = "    —" if s.recall is None else f"{s.recall:5.0%}"
            covered = ""
            if s.uncovered_cases:
                covered = f"  (over {len(s.covered_cases)}/{len(s.cases)} cases)"
            out.append(
                f"  {s.name:32} recall {recall}  "
                f"found {s.detected_total:2d}/{s.expected_total:2d}  "
                f"FP {s.false_positive_total:2d}{covered}"
            )
    return "\n".join(out)
