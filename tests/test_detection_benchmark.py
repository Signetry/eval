"""Tests for the head-to-head detection benchmark."""
from __future__ import annotations

import json

import pytest

from signetry_eval.detection import (
    in_scope_ground_truth,
    render_markdown,
    run_detection_benchmark,
)
from signetry_eval.detection.adapters import captured_json_adapter
from signetry_eval.detection.benchmark import run_benchmark

# Engine-dependent tests skip when the installed signetry-core lacks scan_repository
# (e.g. CI installing an older signetry-core from PyPI before the engine is released).
try:
    from signetry_core import scan_repository as _scan_repository  # noqa: F401
    _HAS_ENGINE = True
except Exception:
    _HAS_ENGINE = False

requires_engine = pytest.mark.skipif(
    not _HAS_ENGINE, reason="signetry-core detection engine not available",
)


@requires_engine
def test_signetry_achieves_full_recall_zero_fp():
    scores = run_detection_benchmark()
    signetry = next(s for s in scores if s.name == "signetry-core")
    assert signetry.ran is True
    assert signetry.recall == 1.0, f"expected full recall, got {signetry.recall} (missed {signetry.missed})"
    assert signetry.false_positives == 0


@requires_engine
def test_competitors_not_run_without_capture():
    scores = run_detection_benchmark()
    claude = next(s for s in scores if s.name == "claude-code-security-review")
    assert claude.ran is False  # honestly reported, never faked
    # A not-run tool credits no detections and is not scored as zero-recall silently.
    assert claude.recall == 0.0


def test_captured_competitor_is_scored(tmp_path):
    # A capture that finds SQLi + command injection in app.py.
    capture = tmp_path / "cap.json"
    capture.write_text(json.dumps({"findings": [
        {"file": "src/app.py", "category": "sql_injection"},
        {"file": "src/app.py", "category": "command_injection"},
    ]}))
    scores = run_benchmark([captured_json_adapter("claude", str(capture))])
    s = scores[0]
    assert s.ran is True
    assert "GT-2" in s.detected  # SQLi
    assert "GT-3" in s.detected  # command injection ping
    assert s.recall > 0


def test_false_positive_counted_when_finding_in_safe_file(tmp_path):
    capture = tmp_path / "cap.json"
    capture.write_text(json.dumps({"findings": [
        {"file": "safe/util.py", "category": "sql_injection"},  # safe file → FP
    ]}))
    scores = run_benchmark([captured_json_adapter("x", str(capture))])
    assert scores[0].false_positives == 1


@requires_engine
def test_markdown_renders_table():
    scores = run_detection_benchmark()
    md = render_markdown(scores)
    assert "Recall" in md and "signetry-core" in md
    assert "100%" in md  # signetry full recall


def test_ground_truth_excludes_open_redirect_from_in_scope():
    ids = {g.id for g in in_scope_ground_truth()}
    assert "GT-11" not in ids  # open redirect excluded (competitors filter it)
    assert len(ids) == 13


@requires_engine
def test_semgrep_layer_optional_does_not_break(tmp_path):
    # use_semgrep=True must not error even if semgrep is absent.
    scores = run_detection_benchmark(use_semgrep=True)
    signetry = next(s for s in scores if s.name == "signetry-core")
    assert signetry.ran is True
    assert signetry.recall == 1.0
