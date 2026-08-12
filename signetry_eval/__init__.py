"""signetry-eval — the public adversarial evaluation suite for Signetry.

Measures attack success rate (ASR) and utility-under-defense for coding-agent
threats — indirect prompt injection, skill/MCP poisoning, and memory injection —
running the same governance production uses (signetry-core). Deterministic, offline,
reproducible in CI.
"""
from __future__ import annotations

from .report import Report, render_markdown
from .scenario import Outcome, Scenario, ScenarioResult
from .scenarios import ALL_SCENARIOS, scenarios_for


def run_all(category: str | None = None) -> Report:
    """Run every scenario (optionally filtered by category) and return a Report."""
    return Report(results=[s.run() for s in scenarios_for(category)])


__all__ = [
    "ALL_SCENARIOS",
    "Outcome",
    "Report",
    "Scenario",
    "ScenarioResult",
    "render_markdown",
    "run_all",
    "scenarios_for",
]
