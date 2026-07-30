"""Head-to-head detection benchmark: score Umbra and competitor scanners against a
shared ground-truth fixture (recall + false positives). Complements the ASR/utility
suite by measuring the vuln-detection axis the scanner tools are built for."""
from __future__ import annotations

from .adapters import captured_json_adapter, umbra_adapter
from .benchmark import ScannerScore, run_benchmark, score
from .corpus import ALL_CASES, safe_cases, total_expected_findings, vulnerable_cases
from .corpus_adapters import (
    captured_corpus_adapter,
    load_capture,
    umbra_corpus_adapter,
)
from .corpus_benchmark import CorpusScore, not_run, run_corpus_benchmark
from .corpus_report import render_markdown as render_corpus_markdown
from .corpus_report import render_text as render_corpus_text
from .fixture import GROUND_TRUTH, in_scope_ground_truth
from .report import render_markdown, render_text


def _default_claude_capture() -> str | None:
    """The committed Opus 4.8 capture, if present — used as the default competitor
    baseline so `umbra-eval corpus` shows the head-to-head with no arguments."""
    from pathlib import Path

    p = Path(__file__).parent / "captures" / "claude-opus-4-8.json"
    return str(p) if p.exists() else None


def run_corpus_head_to_head(
    *,
    use_semgrep: bool = False,
    claude_capture: str | None = None,
    codex_capture: str | None = None,
) -> list[CorpusScore]:
    """Run the 20-case corpus for Umbra + (optionally captured) competitor outputs."""
    if claude_capture is None:
        claude_capture = _default_claude_capture()
    umbra_note = "deterministic + semgrep layer" if use_semgrep else "deterministic, offline"
    scores: list[CorpusScore] = [
        run_corpus_benchmark("umbra-core", umbra_corpus_adapter(use_semgrep=use_semgrep),
                             note=umbra_note),
    ]
    for name, cap in (("claude-code-security-review", claude_capture),
                      ("openai-codex-security", codex_capture)):
        if cap:
            data = load_capture(cap)
            if data:
                s = run_corpus_benchmark(name, captured_corpus_adapter(data),
                                         note=f"replayed from capture ({len(data)} cases)")
                s.name = name
                scores.append(s)
                continue
        scores.append(not_run(name, "no captured output (requires credentials to run live)"))
    return scores


def run_detection_benchmark(
    *,
    use_semgrep: bool = False,
    claude_capture: str | None = None,
    codex_capture: str | None = None,
) -> list[ScannerScore]:
    """Run the benchmark across Umbra + (optionally captured) competitor outputs."""
    adapters = [
        umbra_adapter(use_semgrep=use_semgrep),
        captured_json_adapter("claude-code-security-review", claude_capture),
        captured_json_adapter("openai-codex-security", codex_capture),
    ]
    return run_benchmark(adapters)


__all__ = [
    # 20-case public corpus
    "ALL_CASES",
    "GROUND_TRUTH",
    "CorpusScore",
    "ScannerScore",
    "captured_corpus_adapter",
    "captured_json_adapter",
    "in_scope_ground_truth",
    "load_capture",
    "not_run",
    "render_corpus_markdown",
    "render_corpus_text",
    "render_markdown",
    "render_text",
    "run_benchmark",
    "run_corpus_benchmark",
    "run_corpus_head_to_head",
    "run_detection_benchmark",
    "safe_cases",
    "score",
    "total_expected_findings",
    "umbra_adapter",
    "umbra_corpus_adapter",
    "vulnerable_cases",
]
