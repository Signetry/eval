"""Aggregate scenario results into honest metrics + curves.

The headline numbers Umbra publishes:

- **ASR (ungoverned)** — attack success rate with no checkpoint (the baseline the
  agent ecosystem lives with today).
- **ASR (governed)** — attack success rate through umbra-core. The claim is a
  *large reduction*, never zero: novel phrasings can evade a pattern detector, so
  the honest framing is **bounded + quarantined + dual-verified + receipted**.
- **Utility (governed)** — fraction of benign tasks that still complete under
  defense. A low ASR is only meaningful if utility stays high.

No result is rounded up; every scenario's evidence is retained so a skeptic can
audit each number.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .scenario import CATEGORY_UTILITY, ScenarioResult


def _rate(n: int, d: int) -> float:
    return round(n / d, 4) if d else 0.0


@dataclass
class CategoryMetrics:
    category: str
    total: int = 0
    attack_scenarios: int = 0
    asr_ungoverned: float = 0.0
    asr_governed: float = 0.0
    utility_governed: float = 0.0
    demonstrated_gaps: int = 0

    def to_public(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "total": self.total,
            "attack_scenarios": self.attack_scenarios,
            "asr_ungoverned": self.asr_ungoverned,
            "asr_governed": self.asr_governed,
            "utility_governed": self.utility_governed,
            "demonstrated_gaps": self.demonstrated_gaps,
        }


@dataclass
class Report:
    results: list[ScenarioResult] = field(default_factory=list)

    def _attack_results(self) -> list[ScenarioResult]:
        return [r for r in self.results if r.category != CATEGORY_UTILITY]

    def _utility_results(self) -> list[ScenarioResult]:
        # Utility = every scenario that carries a benign task (all of them do here,
        # but the dedicated utility category is the primary signal).
        return [r for r in self.results if r.category == CATEGORY_UTILITY]

    def overall(self) -> dict[str, Any]:
        attacks = self._attack_results()
        util = self._utility_results() or self.results
        asr_u = _rate(sum(1 for r in attacks if r.ungoverned.attack_succeeded), len(attacks))
        asr_g = _rate(sum(1 for r in attacks if r.governed.attack_succeeded), len(attacks))
        utility = _rate(sum(1 for r in util if r.utility_preserved), len(util))
        return {
            "scenarios": len(self.results),
            "attack_scenarios": len(attacks),
            "asr_ungoverned": asr_u,
            "asr_governed": asr_g,
            "asr_reduction": round(asr_u - asr_g, 4),
            "utility_governed": utility,
            "demonstrated_gaps": sum(1 for r in attacks if r.demonstrates_gap),
            "defense_held_all": all(r.defense_held for r in attacks),
        }

    def by_category(self) -> list[CategoryMetrics]:
        cats: dict[str, list[ScenarioResult]] = {}
        for r in self.results:
            cats.setdefault(r.category, []).append(r)
        out: list[CategoryMetrics] = []
        for cat, rs in sorted(cats.items()):
            attacks = [r for r in rs if r.category != CATEGORY_UTILITY]
            m = CategoryMetrics(category=cat, total=len(rs), attack_scenarios=len(attacks))
            if attacks:
                m.asr_ungoverned = _rate(sum(1 for r in attacks if r.ungoverned.attack_succeeded), len(attacks))
                m.asr_governed = _rate(sum(1 for r in attacks if r.governed.attack_succeeded), len(attacks))
                m.demonstrated_gaps = sum(1 for r in attacks if r.demonstrates_gap)
            m.utility_governed = _rate(sum(1 for r in rs if r.utility_preserved), len(rs))
            out.append(m)
        return out

    def to_public(self) -> dict[str, Any]:
        return {
            "overall": self.overall(),
            "by_category": [c.to_public() for c in self.by_category()],
            "scenarios": [r.to_public() for r in self.results],
            "honesty_note": (
                "ASR (governed) is not a claim that injection is solved. Novel phrasings can "
                "evade a fixed pattern detector; these are tested patterns. The guarantee is "
                "bounded + quarantined + dual-verified + receipted: the governed run keeps the "
                "attacker objective out of the admitted change and caps authority on evidence."
            ),
        }


def render_markdown(report: Report) -> str:
    o = report.overall()
    lines = [
        "# Umbra adversarial evaluation",
        "",
        "> ASR = attack success rate. The governed column is Umbra's admission pipeline "
        "(umbra-core). This is **not** a claim that injection is solved — it is "
        "*bounded + quarantined + dual-verified + receipted*.",
        "",
        "## Headline",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Scenarios | {o['scenarios']} ({o['attack_scenarios']} adversarial) |",
        f"| ASR ungoverned | **{o['asr_ungoverned']:.0%}** |",
        f"| ASR governed | **{o['asr_governed']:.0%}** |",
        f"| ASR reduction | **{o['asr_reduction']:.0%}** |",
        f"| Utility preserved (governed) | **{o['utility_governed']:.0%}** |",
        f"| Defense held on all attacks | {o['defense_held_all']} |",
        "",
        "## By category",
        "",
        "| Category | Scenarios | ASR ungoverned | ASR governed | Utility |",
        "|---|---|---|---|---|",
    ]
    for c in report.by_category():
        lines.append(
            f"| {c.category} | {c.total} | {c.asr_ungoverned:.0%} | {c.asr_governed:.0%} | {c.utility_governed:.0%} |"
        )
    lines += ["", "## Scenarios", ""]
    for r in report.results:
        u = "hit" if r.ungoverned.attack_succeeded else "safe"
        g = "hit" if r.governed.attack_succeeded else "bounded"
        lines.append(f"- **{r.id}** ({r.category}) — ungoverned: {u} · governed: {g}")
        lines.append(f"  - {r.title} — _{r.threat}_")
        lines.append(f"  - governed: {r.governed.detail}")
    lines += ["", "---", "", report.to_public()["honesty_note"]]
    return "\n".join(lines)
