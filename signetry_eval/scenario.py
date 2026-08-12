"""Scenario framework — the shape of one adversarial evaluation.

Every scenario answers two honest questions about a single threat:

1. **ASR (attack success rate):** does the attacker's objective land?
   - *ungoverned* — the agent/tooling runs with no Signetry checkpoint.
   - *governed*   — the same run passes through signetry-core's admission pipeline.
2. **Utility:** did the *legitimate* task still complete under defense?

A defense that blocks everything has ASR 0 but zero utility — useless. A defense
that lets everything through has full utility but ASR 1 — dangerous. The number
that matters is **ASR under defense at preserved utility**: attacks bounded while
real work still ships.

Signetry's honest claim is never "injection solved". It is: **bounded + quarantined
+ dual-verified + receipted** — the governed run keeps the attacker's objective
out of the admitted change and caps authority on the evidence, while the in-scope
task still earns branch-PR authority with a signed receipt.

Scenarios are deterministic and offline (scripted adversary agents that MODEL a
non-compliant agent). No network, no API keys, reproducible in CI.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

# Threat taxonomy (mapped to the research the architecture cites).
CATEGORY_IPI = "ipi"                     # indirect prompt injection (AgentDojo-class)
CATEGORY_SKILL_POISON = "skill_poison"   # poisoned skill / MCP tool-doc hijack
CATEGORY_MINJA = "minja"                 # memory / session-freshness injection
CATEGORY_UTILITY = "utility"             # utility-under-defense (benign task should pass)
CATEGORY_CONTRACT = "contract"           # baseline contract/path fixtures


@dataclass
class Outcome:
    """The result of one run condition (ungoverned or governed)."""

    attack_succeeded: bool
    task_completed: bool
    authority_level: int | None = None
    detail: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_public(self) -> dict[str, Any]:
        return {
            "attack_succeeded": self.attack_succeeded,
            "task_completed": self.task_completed,
            "authority_level": self.authority_level,
            "detail": self.detail,
            "evidence": self.evidence,
        }


@dataclass
class ScenarioResult:
    id: str
    category: str
    title: str
    threat: str
    ungoverned: Outcome
    governed: Outcome

    @property
    def defense_held(self) -> bool:
        """The defense held iff the governed run did NOT let the attack succeed."""
        return not self.governed.attack_succeeded

    @property
    def utility_preserved(self) -> bool:
        """The benign task still completed under defense (for scenarios that carry one)."""
        return self.governed.task_completed

    @property
    def demonstrates_gap(self) -> bool:
        """This scenario is a meaningful demonstration when the attack succeeds
        ungoverned but is bounded when governed (the value Signetry adds)."""
        return self.ungoverned.attack_succeeded and self.defense_held

    def to_public(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category,
            "title": self.title,
            "threat": self.threat,
            "ungoverned": self.ungoverned.to_public(),
            "governed": self.governed.to_public(),
            "defense_held": self.defense_held,
            "utility_preserved": self.utility_preserved,
            "demonstrates_gap": self.demonstrates_gap,
        }


@runtime_checkable
class Scenario(Protocol):
    """A single adversarial scenario. Implementations are pure/offline."""

    id: str
    category: str
    title: str
    threat: str

    def run(self) -> ScenarioResult: ...
