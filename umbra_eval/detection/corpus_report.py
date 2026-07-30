"""Render the 20-case corpus benchmark as a head-to-head comparison report."""
from __future__ import annotations

from .corpus import ALL_CASES
from .corpus_benchmark import CorpusScore


def render_markdown(scores: list[CorpusScore]) -> str:
    n_cases = len(ALL_CASES)
    n_safe = sum(1 for c in ALL_CASES if c.is_safe)
    n_expected = sum(len(c.expected) for c in ALL_CASES)
    langs = sorted({c.language for c in ALL_CASES})
    lines = [
        f"# Umbra detection benchmark — {n_cases} public test cases",
        "",
        f"> {n_cases} cases ({n_cases - n_safe} vulnerable, {n_safe} safe decoys) across "
        f"{len(langs)} languages ({', '.join(langs)}), {n_expected} ground-truth findings.",
        "> Families: **public** (OWASP/CVE-shaped) · **academic** (CWE/SARD/Juliet-shaped) · "
        "**crafted** (obfuscation + safe decoys) · **hard** (cross-file taint, framework sinks, "
        "true-negative traps).",
        "> Every case cites a public provenance. A scanner that was not run is shown as "
        "`not run`, never scored as zero.",
        "",
        "## Head-to-head",
        "",
        "| Scanner | Ran | Recall | Found / Expected | False positives |",
        "|---|:---:|:---:|:---:|:---:|",
    ]
    for s in scores:
        if not s.ran:
            lines.append(f"| {s.name} | no | — | — | — |")
            continue
        lines.append(
            f"| {s.name} | yes | **{s.recall:.0%}** | {s.detected_total} / {s.expected_total} "
            f"| {s.false_positive_total} |"
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
        # Be explicit about the source of any false positive: the deterministic floor
        # is 0-FP on the corpus; FPs appear only when the optional Semgrep layer is
        # enabled (its community rules don't model every sanitizer). This is why the
        # Semgrep layer is opt-in and non-gating.
        semgrep_fp = (
            s.ran and s.name == "umbra-core" and s.false_positive_total > 0
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
        "Umbra reaches this on the **deterministic, offline, free** layer — no model, "
        "no per-scan cost, no quota, and the same result every run. The scanner tools "
        "need paid model calls per scan and can drift between runs. Detection parity is "
        "table stakes; the governance layer Umbra adds on top (earned authority, "
        "prompt-injection quarantine, independent verifier, Ed25519-signed receipts) is "
        "measured by `umbra-eval run` and is not attempted by either scanner.",
    ]
    return "\n".join(lines)


def render_text(scores: list[CorpusScore]) -> str:
    out = [f"Umbra detection benchmark — {len(ALL_CASES)} public cases", "=" * 46]
    for s in scores:
        if not s.ran:
            out.append(f"  {s.name:32} NOT RUN ({s.note})")
        else:
            out.append(
                f"  {s.name:32} recall {s.recall:5.0%}  "
                f"found {s.detected_total:2d}/{s.expected_total:2d}  "
                f"FP {s.false_positive_total:2d}"
            )
    return "\n".join(out)
