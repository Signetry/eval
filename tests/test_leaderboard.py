"""Tests for the public leaderboard renderer.

The leaderboard's whole claim is that it will not print a number nobody measured. That
claim lives in validation code, so it is only true for as long as these tests pass —
every assertion here corresponds to one of the three rules in
``signetry_eval/leaderboard.py``'s docstring.
"""
from __future__ import annotations

import json

import pytest

from signetry_eval import run_all
from signetry_eval.leaderboard import (
    STATUS_NOT_RUN,
    STATUS_REPRODUCED,
    STATUS_SELF_REPORTED,
    Entry,
    entry_from_dict,
    entry_from_report,
    leaderboard_json,
    load_entries,
    render_leaderboard,
)

VALID = {
    "name": "some-guardrail",
    "status": STATUS_SELF_REPORTED,
    "attacks_run": 12,
    "asr_ungoverned": 1.0,
    "asr_governed": 0.25,
    "utility_governed": 0.9,
    "utility_scenarios": 10,
    "provenance": "Run by the maintainers on 2026-08-01, logs linked in the PR.",
}


def _entry(**overrides):
    return entry_from_dict({**VALID, **overrides})


# --- Rule 1: a number nobody measured is None, never 0 ------------------------------


def test_a_valid_entry_has_no_errors():
    e = _entry()
    assert e.errors == []
    assert e.asr_governed == 0.25
    assert e.asr_reduction == 0.75


def test_absent_metrics_stay_absent():
    e = entry_from_dict({"name": "x", "status": STATUS_NOT_RUN})
    assert e.asr_governed is None
    assert e.asr_ungoverned is None
    assert e.utility_governed is None
    assert e.asr_reduction is None


@pytest.mark.parametrize("bad", ["0.5", True, [], {}, 1.5, -0.1, float("nan")])
def test_a_rate_that_is_not_a_fraction_is_refused(bad):
    # True is in this list deliberately: bool is a subclass of int, so a naive numeric
    # check accepts it and publishes an ASR of 100%.
    e = _entry(asr_governed=bad)
    assert e.asr_governed is None, f"{bad!r} was accepted as a rate"
    assert any("asr_governed" in err for err in e.errors)


def test_nan_is_not_a_rate():
    # float('nan') passes isinstance checks and every comparison against it is False,
    # so a naive 0 <= x <= 1 guard lets it through and renders as "nan%".
    e = _entry(asr_governed=float("nan"))
    assert e.asr_governed is None
    assert any("asr_governed" in err for err in e.errors)


def test_a_rate_with_no_denominator_is_not_a_measurement():
    e = _entry(attacks_run=None)
    assert e.asr_governed is None
    assert e.asr_ungoverned is None
    assert any("denominator" in err for err in e.errors)


def test_utility_with_no_denominator_is_refused_independently():
    e = _entry(utility_scenarios=0)
    assert e.utility_governed is None
    assert e.asr_governed == 0.25, "the ASR denominator is intact; only utility lost its own"


@pytest.mark.parametrize("bad", ["five", -1, 2.5, True])
def test_attacks_run_must_be_a_non_negative_integer(bad):
    e = _entry(attacks_run=bad)
    assert e.attacks_run is None
    assert any("attacks_run" in err for err in e.errors)


# --- Rule 2: provenance is mandatory, and reproduced/self-reported never mix ---------


def test_provenance_is_required_unless_the_system_did_not_run():
    missing = _entry(provenance=None)
    assert any("provenance" in err for err in missing.errors)

    not_run = entry_from_dict({"name": "x", "status": STATUS_NOT_RUN})
    assert not any("provenance" in err for err in not_run.errors)


def test_an_unknown_status_falls_back_to_not_run():
    e = _entry(status="verified-by-vibes")
    assert e.status == STATUS_NOT_RUN
    assert any("status" in err for err in e.errors)


def test_reproduced_and_self_reported_render_in_separate_tables():
    report = run_all(None)
    page = render_leaderboard(
        report,
        entries=[*load_entries(), _entry(name="claims-a-lot", status=STATUS_SELF_REPORTED)],
    )
    assert "### Reproduced in this repository" in page
    assert "### Self-reported" in page
    reproduced_at = page.index("### Reproduced in this repository")
    self_reported_at = page.index("### Self-reported")
    signetry_at = page.index("signetry-core")
    claims_at = page.index("claims-a-lot")
    assert reproduced_at < signetry_at < self_reported_at < claims_at


def test_a_broken_submission_is_shown_not_dropped():
    report = run_all(None)
    page = render_leaderboard(report, entries=[_entry(asr_governed="lots")])
    assert "some-guardrail" in page, "the entry vanished instead of being flagged"
    assert "asr_governed" in page, "the validation error was not surfaced on the page"


# --- Rule 3: rendering ---------------------------------------------------------------


def test_an_unmeasured_metric_renders_as_an_em_dash_not_a_zero():
    report = run_all(None)
    page = render_leaderboard(
        report,
        entries=[_entry(name="no-utility-figure", utility_governed=None,
                        utility_scenarios=None)],
    )
    row = next(line for line in page.split("\n") if "no-utility-figure" in line)
    cells = [c.strip() for c in row.strip("|").split("|")]
    assert cells[-1] == "—", f"utility rendered as {cells[-1]!r} instead of not-measured"
    assert "0%" not in cells, "an unmeasured metric was rendered as 0%"


def test_every_rate_is_printed_with_its_sample_size():
    report = run_all(None)
    page = render_leaderboard(report)
    live = entry_from_report(report)
    row = next(line for line in page.split("\n") if "signetry-core" in line and "|" in line)
    cells = [c.strip() for c in row.strip("|").split("|")]
    assert str(live.attacks_run) in cells, \
        "the row shows rates without the scenario count they were computed over"


def test_the_page_states_its_own_sample_size_in_prose():
    page = render_leaderboard(run_all(None))
    assert "scenarios" in page
    assert "small corpus" in page, "the page must admit the corpus is small"


def test_the_generated_header_names_the_workflow_that_writes_it():
    page = render_leaderboard(run_all(None))
    first = page.strip().split("\n")[0]
    assert ".github/workflows/leaderboard.yml" in first
    assert "do not edit by hand" in first


def test_embedded_detection_report_does_not_introduce_a_second_h1():
    detection = "# Detection report\n\n## Head-to-head\n\n```\n# not a heading\n```\n"
    page = render_leaderboard(run_all(None), detection_markdown=detection)
    h1s, in_fence = [], False
    for ln in page.split("\n"):
        if ln.lstrip().startswith("```"):
            in_fence = not in_fence
        elif not in_fence and ln.startswith("# "):
            h1s.append(ln)
    assert len(h1s) == 1, f"expected exactly one h1, got {h1s}"
    assert "### Detection report" in page
    assert "#### Head-to-head" in page
    assert "# not a heading" in page, "a comment inside a fenced block was rewritten"


def test_the_live_row_is_built_from_the_report_not_hand_written():
    report = run_all(None)
    e = entry_from_report(report)
    assert e.status == STATUS_REPRODUCED
    assert e.errors == []
    assert e.provenance, "the live row must carry provenance like any other"
    assert e.attacks_run and e.attacks_run > 0


# --- The committed entries and the JSON envelope -------------------------------------


def test_the_committed_entries_all_validate():
    entries = load_entries()
    assert entries, "leaderboard/entries/ should contain at least the control condition"
    for e in entries:
        assert e.errors == [], f"committed entry {e.name!r} is invalid: {e.errors}"


def test_the_control_condition_is_a_visible_row():
    baseline = next(e for e in load_entries() if "ungoverned" in e.name)
    assert baseline.asr_ungoverned == 1.0
    assert baseline.asr_governed == 1.0, "the control has nothing governing it, by construction"
    assert baseline.utility_governed is None, "utility is not measured for the control"


def test_unreadable_entry_files_become_visible_errors(tmp_path):
    (tmp_path / "broken.json").write_text("{not json")
    (tmp_path / "list.json").write_text("[]")
    entries = load_entries(tmp_path)
    assert len(entries) == 2
    assert all(e.errors for e in entries)


def test_a_missing_entries_directory_is_not_an_error(tmp_path):
    assert load_entries(tmp_path / "nope") == []


def test_json_envelope_is_serializable_and_versioned():
    payload = leaderboard_json(run_all(None))
    round_tripped = json.loads(json.dumps(payload))
    assert round_tripped["kind"] == "signetry.governance-leaderboard"
    assert round_tripped["version"] == 1
    # None must survive as null, not become 0.
    baseline = next(r for r in round_tripped["governance"]["submitted"]
                    if "ungoverned" in r["name"])
    assert baseline["utility_governed"] is None
    assert baseline["asr_ungoverned"] == 1.0, "null is for unmeasured, not for a real 1.0"
    assert round_tripped["governance"]["measured_here"]["status"] == STATUS_REPRODUCED


def test_entry_defaults_are_all_unmeasured():
    # A bare Entry() is what a not-run system looks like. None of its metrics may
    # default to a number.
    e = Entry(name="nothing known")
    assert (e.asr_ungoverned, e.asr_governed, e.utility_governed) == (None, None, None)
    assert e.status == STATUS_NOT_RUN
