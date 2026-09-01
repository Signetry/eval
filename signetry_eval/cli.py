"""``signetry-eval`` CLI — run the adversarial suite and print ASR / utility.

    signetry-eval run                 # run all scenarios, human summary
    signetry-eval run --json          # machine-readable report
    signetry-eval run --markdown      # publishable markdown report
    signetry-eval run --category ipi  # filter by threat category
    signetry-eval list                # list scenarios

Exit code is non-zero if the defense did not hold on every adversarial scenario
(so it can gate CI as a regression guard).
"""
# ruff: noqa: E501  (argparse help strings read better on one line)
from __future__ import annotations

import argparse
import json
import sys

from . import run_all
from .report import render_markdown
from .scenarios import scenarios_for

_CATEGORIES = ("ipi", "skill_poison", "minja", "utility", "contract")


def cmd_run(args: argparse.Namespace) -> int:
    report = run_all(args.category)
    if args.json:
        print(json.dumps(report.to_public(), indent=2, default=str))
    elif args.markdown:
        print(render_markdown(report))
    else:
        o = report.overall()
        print("Signetry adversarial evaluation")
        print("=" * 40)
        print(f"scenarios            : {o['scenarios']} ({o['attack_scenarios']} adversarial)")
        print(f"ASR ungoverned       : {o['asr_ungoverned']:.0%}")
        print(f"ASR governed         : {o['asr_governed']:.0%}")
        print(f"ASR reduction        : {o['asr_reduction']:.0%}")
        print(f"utility (governed)   : {o['utility_governed']:.0%}")
        print(f"defense held on all  : {o['defense_held_all']}")
        print("-" * 40)
        for r in report.results:
            u = "HIT " if r.ungoverned.attack_succeeded else "safe"
            g = "HIT " if r.governed.attack_succeeded else "bnd "
            print(f"  [{u}->{g}] {r.id}")
    # Non-zero if any adversarial scenario's defense failed.
    return 0 if report.overall()["defense_held_all"] else 1


def cmd_benchmark(args: argparse.Namespace) -> int:
    """Head-to-head detection benchmark: recall + false positives vs competitor
    scanners on a shared ground-truth fixture. Exits non-zero if Signetry's recall
    falls below ``--min-recall`` (default 1.0 = must find every in-scope vuln)."""
    from .detection import render_markdown, render_text, run_detection_benchmark

    scores = run_detection_benchmark(
        use_semgrep=args.semgrep,
        claude_capture=args.claude_capture,
        codex_capture=args.codex_capture,
    )
    if args.json:
        print(json.dumps([s.to_public() for s in scores], indent=2, default=str))
    elif args.markdown:
        print(render_markdown(scores))
    else:
        print(render_text(scores))

    signetry = next((s for s in scores if s.name == "signetry-core"), None)
    if signetry is not None and signetry.recall < args.min_recall:
        print(f"FAIL: Signetry recall {signetry.recall:.0%} < required {args.min_recall:.0%}",
              file=sys.stderr)
        return 1
    return 0


def cmd_corpus(args: argparse.Namespace) -> int:
    """20-case public detection corpus, head-to-head vs competitor scanners.

    Signetry runs live (deterministic, offline); competitor scores come from a
    captured per-case JSON (replayed) or are shown as not-run. Exits non-zero if
    Signetry recall falls below ``--min-recall`` or it raises any false positive."""
    from .detection import (
        render_corpus_markdown,
        render_corpus_text,
        run_corpus_head_to_head,
    )

    scores = run_corpus_head_to_head(
        use_semgrep=args.semgrep,
        claude_capture=args.claude_capture,
        codex_capture=args.codex_capture,
    )
    if args.json:
        print(json.dumps([s.to_public() for s in scores], indent=2, default=str))
    elif args.markdown:
        print(render_corpus_markdown(scores))
    else:
        print(render_corpus_text(scores))

    signetry = next((s for s in scores if s.name == "signetry-core"), None)
    if signetry is not None:
        if signetry.recall is None:
            # Nothing measured is a failure of the gate, not a pass by default.
            print("FAIL: Signetry recall was not measured (no covered cases)", file=sys.stderr)
            return 1
        if signetry.recall < args.min_recall:
            print(f"FAIL: Signetry recall {signetry.recall:.0%} < required {args.min_recall:.0%}",
                  file=sys.stderr)
            return 1
        if signetry.false_positive_total > args.max_fp:
            print(f"FAIL: Signetry false positives {signetry.false_positive_total} > allowed {args.max_fp}",
                  file=sys.stderr)
            return 1
    return 0


def cmd_realrepo(args: argparse.Namespace) -> int:
    """Scan the real public-repo detection cases with Signetry (network + git).

    Demonstrates the live `signetry scan <url>` entry point on real vulnerable apps,
    aggregated. Report-only; exits 0 unless a clone/scan hard-fails everywhere."""
    from .detection.real_repo_benchmark import render_text, scan_all_real_repos

    results = scan_all_real_repos(use_semgrep=args.semgrep, depth=args.depth)
    if args.json:
        print(json.dumps([r.to_public() for r in results], indent=2, default=str))
    else:
        print(render_text(results))
    return 0 if any(r.ran for r in results) else 2


def cmd_list(args: argparse.Namespace) -> int:
    for s in scenarios_for(args.category):
        print(f"{s.category:14} {s.id:44} {s.title}")
    print(f"\n{len(scenarios_for(args.category))} scenario(s).")
    return 0


def cmd_leaderboard(args: argparse.Namespace) -> int:
    """Render the two-axis governance leaderboard.

    Axis 1 (governance) is always measured live — it is cheap and offline. Axis 2
    (detection) needs the SAST engine and the competitor captures, so it is included
    only when asked for, and its absence is stated on the page rather than faked.
    """
    from .leaderboard import leaderboard_json, load_entries, render_leaderboard

    report = run_all(None)
    entries = load_entries(args.entries) if args.entries else load_entries()

    detection_md = None
    if args.with_detection:
        from .detection import render_corpus_markdown, run_corpus_head_to_head

        try:
            scores = run_corpus_head_to_head(
                use_semgrep=args.semgrep,
                claude_capture=args.claude_capture,
                codex_capture=args.codex_capture,
            )
            detection_md = render_corpus_markdown(scores)
        # Deliberately broad: any failure to run the detection axis must omit it with a
        # warning. Emitting an empty or partial table would publish a zero for a
        # scanner that never ran, which is the one thing this page must not do.
        except Exception as exc:
            print(f"warning: detection axis unavailable, omitting it: {exc}", file=sys.stderr)

    if args.json:
        print(json.dumps(leaderboard_json(report, entries=entries, version=args.version),
                         indent=2, default=str))
    else:
        print(render_leaderboard(report, detection_markdown=detection_md,
                                 entries=entries, version=args.version))

    # Same gate as `run`: a leaderboard that renders while the defense is failing is
    # a report, not a pass.
    return 0 if report.overall()["defense_held_all"] else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="signetry-eval", description="Signetry adversarial evaluation suite.")
    sub = p.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run", help="Run scenarios and report ASR / utility.")
    p_run.add_argument("--category", choices=_CATEGORIES, help="Only run one threat category.")
    p_run.add_argument("--json", action="store_true", help="Emit the full report as JSON.")
    p_run.add_argument("--markdown", action="store_true", help="Emit a publishable markdown report.")
    p_run.set_defaults(func=cmd_run)

    p_bench = sub.add_parser("benchmark", help="Head-to-head detection benchmark: recall + false positives vs competitor scanners on a shared fixture.")
    p_bench.add_argument("--semgrep", action="store_true", help="Enable Signetry's Semgrep layer if installed.")
    p_bench.add_argument("--claude-capture", help="Path to a captured claude-code-security-review findings JSON to replay.")
    p_bench.add_argument("--codex-capture", help="Path to a captured @openai/codex-security findings JSON to replay.")
    p_bench.add_argument("--min-recall", type=float, default=1.0, help="Exit non-zero if Signetry recall is below this (default 1.0).")
    p_bench.add_argument("--json", action="store_true", help="Emit the scores as JSON.")
    p_bench.add_argument("--markdown", action="store_true", help="Emit a publishable markdown comparison table.")
    p_bench.set_defaults(func=cmd_benchmark)

    p_corpus = sub.add_parser("corpus", help="20-case public detection corpus, head-to-head vs competitor scanners (recall, false positives, by-language).")
    p_corpus.add_argument("--semgrep", action="store_true", help="Enable Signetry's Semgrep layer if installed.")
    p_corpus.add_argument("--claude-capture", help="Per-case JSON capture of claude-code-security-review output to replay.")
    p_corpus.add_argument("--codex-capture", help="Per-case JSON capture of @openai/codex-security output to replay.")
    p_corpus.add_argument("--min-recall", type=float, default=1.0, help="Exit non-zero if Signetry recall is below this (default 1.0; the deterministic engine now covers cross-file taint and 7 languages).")
    p_corpus.add_argument("--max-fp", type=int, default=0, help="Exit non-zero if Signetry raises more than this many false positives (default 0).")
    p_corpus.add_argument("--json", action="store_true", help="Emit the full scores as JSON.")
    p_corpus.add_argument("--markdown", action="store_true", help="Emit a publishable markdown comparison table.")
    p_corpus.set_defaults(func=cmd_corpus)

    p_real = sub.add_parser("realrepo", help="Scan real public vulnerable repos with Signetry (network + git): live entry-point demo on real code.")
    p_real.add_argument("--semgrep", action="store_true", help="Enable Signetry's Semgrep layer if installed.")
    p_real.add_argument("--depth", type=int, default=1, help="Clone depth (default 1).")
    p_real.add_argument("--json", action="store_true", help="Emit results as JSON.")
    p_real.set_defaults(func=cmd_realrepo)

    p_lb = sub.add_parser("leaderboard", help="Render the two-axis governance leaderboard (governance + optional detection).")
    p_lb.add_argument("--with-detection", action="store_true", help="Also run the detection corpus and include axis 2 (needs the signetry-core SAST engine).")
    p_lb.add_argument("--semgrep", action="store_true", help="Enable Signetry's Semgrep layer if installed (detection axis only).")
    p_lb.add_argument("--claude-capture", help="Per-case JSON capture of claude-code-security-review output to replay.")
    p_lb.add_argument("--codex-capture", help="Per-case JSON capture of @openai/codex-security output to replay.")
    p_lb.add_argument("--entries", help="Directory of submitted leaderboard entries (default: leaderboard/entries).")
    p_lb.add_argument("--version", help="Version label for the live signetry-core row.")
    p_lb.add_argument("--markdown", action="store_true", help="Emit markdown (the default; accepted for symmetry with the other subcommands).")
    p_lb.add_argument("--json", action="store_true", help="Emit the leaderboard as JSON instead of markdown.")
    p_lb.set_defaults(func=cmd_leaderboard)

    p_list = sub.add_parser("list", help="List available scenarios.")
    p_list.add_argument("--category", choices=_CATEGORIES, help="Filter by threat category.")
    p_list.set_defaults(func=cmd_list)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
