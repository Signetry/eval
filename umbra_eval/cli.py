"""``umbra-eval`` CLI — run the adversarial suite and print ASR / utility.

    umbra-eval run                 # run all scenarios, human summary
    umbra-eval run --json          # machine-readable report
    umbra-eval run --markdown      # publishable markdown report
    umbra-eval run --category ipi  # filter by threat category
    umbra-eval list                # list scenarios

Exit code is non-zero if the defense did not hold on every adversarial scenario
(so it can gate CI as a regression guard).
"""
from __future__ import annotations

import argparse
import json
import sys

from .report import render_markdown
from .scenarios import scenarios_for
from . import run_all

_CATEGORIES = ("ipi", "skill_poison", "minja", "utility", "contract")


def cmd_run(args: argparse.Namespace) -> int:
    report = run_all(args.category)
    if args.json:
        print(json.dumps(report.to_public(), indent=2, default=str))
    elif args.markdown:
        print(render_markdown(report))
    else:
        o = report.overall()
        print("Umbra adversarial evaluation")
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


def cmd_list(args: argparse.Namespace) -> int:
    for s in scenarios_for(args.category):
        print(f"{s.category:14} {s.id:44} {s.title}")
    print(f"\n{len(scenarios_for(args.category))} scenario(s).")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="umbra-eval", description="Umbra adversarial evaluation suite.")
    sub = p.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run", help="Run scenarios and report ASR / utility.")
    p_run.add_argument("--category", choices=_CATEGORIES, help="Only run one threat category.")
    p_run.add_argument("--json", action="store_true", help="Emit the full report as JSON.")
    p_run.add_argument("--markdown", action="store_true", help="Emit a publishable markdown report.")
    p_run.set_defaults(func=cmd_run)

    p_list = sub.add_parser("list", help="List available scenarios.")
    p_list.add_argument("--category", choices=_CATEGORIES, help="Filter by threat category.")
    p_list.set_defaults(func=cmd_list)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
