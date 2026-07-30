"""Render the head-to-head detection benchmark as a comparison table."""
from __future__ import annotations

from .benchmark import ScannerScore


def render_markdown(scores: list[ScannerScore]) -> str:
    lines = [
        "# Umbra detection benchmark — head to head",
        "",
        "> Recall and false positives on a shared ground-truth fixture (13 in-scope",
        "> planted vulnerabilities across Python + JavaScript). Open-redirect is",
        "> excluded from the in-scope set because the LLM competitors deliberately",
        "> filter that class out. A tool that was not run (missing credentials/capture)",
        "> is shown as `not run`, never scored as zero-by-omission.",
        "",
        "| Scanner | Ran | Recall | Detected | Missed | False positives | Total findings |",
        "|---|:---:|:---:|:---:|:---:|:---:|:---:|",
    ]
    for s in scores:
        if not s.ran:
            lines.append(f"| {s.name} | no | — | — | — | — | — |")
            continue
        lines.append(
            f"| {s.name} | yes | **{s.recall:.0%}** | {len(s.detected)} | "
            f"{len(s.missed)} | {s.false_positives} | {s.total_findings} |"
        )
    lines += ["", "## Notes", ""]
    for s in scores:
        note = s.note or ""
        if s.ran and s.missed:
            note += f" · missed: {', '.join(s.missed)}"
        lines.append(f"- **{s.name}**: {note or ('ran' if s.ran else 'not run')}")
    lines += [
        "",
        "---",
        "",
        "Detection parity is the table-stakes axis. The differentiator Umbra adds on "
        "top — earned/revocable authority, on-disk prompt-injection quarantine, an "
        "independent verifier the writer cannot bypass, and an Ed25519-signed receipt — "
        "is measured by the ASR / utility suite (`umbra-eval run`), which the scanner "
        "tools do not attempt.",
    ]
    return "\n".join(lines)


def render_text(scores: list[ScannerScore]) -> str:
    out = ["Umbra detection benchmark (head to head)", "=" * 44]
    for s in scores:
        if not s.ran:
            out.append(f"  {s.name:32} NOT RUN  ({s.note})")
        else:
            out.append(
                f"  {s.name:32} recall {s.recall:5.0%}  "
                f"detected {len(s.detected):2d}  missed {len(s.missed):2d}  "
                f"FP {s.false_positives:2d}  findings {s.total_findings:2d}"
            )
    return "\n".join(out)
