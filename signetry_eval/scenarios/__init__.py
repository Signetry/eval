"""All adversarial scenarios, grouped by threat category."""
from __future__ import annotations

from ..scenario import Scenario
from . import ipi, minja, skill_poison, utility

ALL_SCENARIOS: list[Scenario] = [
    *ipi.SCENARIOS,
    *skill_poison.SCENARIOS,
    *minja.SCENARIOS,
    *utility.SCENARIOS,
]


def scenarios_for(category: str | None) -> list[Scenario]:
    if not category:
        return list(ALL_SCENARIOS)
    return [s for s in ALL_SCENARIOS if s.category == category]
