"""Tests for the 20-case public detection corpus + head-to-head benchmark."""
from __future__ import annotations

from pathlib import Path

from umbra_eval.detection import (
    ALL_CASES,
    run_corpus_benchmark,
    run_corpus_head_to_head,
    safe_cases,
    umbra_corpus_adapter,
)
from umbra_eval.detection.corpus_report import render_markdown

# --- corpus integrity -------------------------------------------------------


def test_corpus_has_at_least_45_unique_cases():
    assert len(ALL_CASES) >= 45
    assert len({c.id for c in ALL_CASES}) == len(ALL_CASES)


def test_corpus_includes_crossfile_lang_cases():
    ids = {c.id for c in ALL_CASES}
    assert {"XLANG-46-go-crossfile-sqli", "XLANG-47-java-crossfile-sqli",
            "XLANG-48-php-crossfile-sqli", "XLANG-50-ruby-crossfile-sqli",
            "XLANG-51-csharp-crossfile-sqli"} <= ids


def test_corpus_has_safe_decoys_and_seven_languages():
    assert len(safe_cases()) >= 8, "need safe decoys to measure false positives"
    langs = {c.language for c in ALL_CASES}
    assert {"python", "javascript", "go", "java", "ruby", "php", "csharp"} <= langs


def test_every_case_has_provenance():
    for c in ALL_CASES:
        assert c.provenance and len(c.provenance) > 10, f"{c.id} missing provenance"


def test_families_all_present():
    fams = {c.family.value for c in ALL_CASES}
    assert fams == {"public", "academic", "crafted", "hard", "multilang"}


# --- umbra detection on the corpus ------------------------------------------


def test_umbra_full_recall_zero_fp_on_corpus():
    """With cross-file taint + multi-language rules, the deterministic engine now
    reaches full recall on the corpus at ZERO false positives."""
    score = run_corpus_benchmark("umbra-core", umbra_corpus_adapter())
    assert score.recall == 1.0, (
        f"recall {score.recall}; missed "
        + str([c.case_id for c in score.cases if c.missed_categories])
    )
    assert score.false_positive_total == 0, (
        "false positives on: "
        + str([c.case_id for c in score.cases if c.false_positives])
    )


def test_umbra_detects_cross_file_taint():
    score = run_corpus_benchmark("umbra-core", umbra_corpus_adapter())
    xfile = next(c for c in score.cases if c.case_id == "HARD-21-crossfile-taint-python")
    assert xfile.detected == xfile.expected == 1


def test_umbra_covers_all_seven_languages():
    score = run_corpus_benchmark("umbra-core", umbra_corpus_adapter())
    by_lang = score.by_language()
    for lang in ("go", "java", "ruby", "php", "csharp"):
        assert by_lang.get(lang, {}).get("expected", 0) >= 1
        assert by_lang[lang]["detected"] == by_lang[lang]["expected"], f"missed a {lang} case"


def test_umbra_detects_multivariable_lang_taint():
    """The multi-variable (source->local->sink) cases across Go/Java/PHP/C# must be
    detected — the gap the pure per-line regex tier had."""
    score = run_corpus_benchmark("umbra-core", umbra_corpus_adapter())
    for cid in ("LANG-41-go-multivar-sqli", "LANG-42-java-multivar-sqli",
                "LANG-43-php-multivar-cmdi", "LANG-44-csharp-multivar-sqli"):
        c = next(x for x in score.cases if x.case_id == cid)
        assert c.detected == c.expected >= 1, f"{cid} multi-variable taint not detected"


def test_umbra_no_fp_on_parameterized_safe_decoys():
    """Parameterised / prepared-statement SAFE decoys across languages must not
    trip (the false-positive axis LLMs trade recall to control)."""
    score = run_corpus_benchmark("umbra-core", umbra_corpus_adapter())
    for cid in ("LANG-39-SAFE-go-parameterized", "LANG-40-SAFE-php-prepared",
                "LANG-45-SAFE-java-parameterized", "XLANG-49-SAFE-go-crossfile-constant"):
        c = next(x for x in score.cases if x.case_id == cid)
        assert c.false_positives == 0, f"false positive on {cid}"


def test_umbra_detects_crossfile_taint_in_non_python_langs():
    score = run_corpus_benchmark("umbra-core", umbra_corpus_adapter())
    for cid in ("XLANG-46-go-crossfile-sqli", "XLANG-47-java-crossfile-sqli",
                "XLANG-48-php-crossfile-sqli", "XLANG-50-ruby-crossfile-sqli",
                "XLANG-51-csharp-crossfile-sqli"):
        c = next(x for x in score.cases if x.case_id == cid)
        assert c.detected == c.expected >= 1, f"{cid} cross-file taint not detected"


def test_umbra_detects_taint_through_helper():
    score = run_corpus_benchmark("umbra-core", umbra_corpus_adapter())
    craft = next(c for c in score.cases if c.case_id == "CRAFT-15-taint-through-helper-python")
    assert craft.detected == craft.expected == 1


def test_umbra_no_fp_on_safe_decoys():
    score = run_corpus_benchmark("umbra-core", umbra_corpus_adapter())
    for c in score.cases:
        if c.is_safe:
            assert c.false_positives == 0, f"false positive on safe case {c.case_id}"


def test_by_language_breakdown_present():
    score = run_corpus_benchmark("umbra-core", umbra_corpus_adapter())
    by_lang = score.by_language()
    assert "python" in by_lang and "javascript" in by_lang
    assert by_lang["javascript"]["expected"] >= 3


# --- head-to-head -----------------------------------------------------------


def test_head_to_head_includes_committed_claude_capture():
    scores = run_corpus_head_to_head()
    names = {s.name for s in scores}
    assert "umbra-core" in names
    claude = next(s for s in scores if s.name == "claude-code-security-review")
    # The committed Opus 4.8 capture should be present and replayed.
    assert claude.ran is True
    assert claude.recall > 0.5  # a real capture with meaningful recall


def test_umbra_beats_or_matches_claude_on_corpus():
    """The headline claim: on the harder corpus, the deterministic engine's recall
    is at least as high as the captured Opus 4.8 baseline, at zero false positives."""
    scores = run_corpus_head_to_head()
    umbra = next(s for s in scores if s.name == "umbra-core")
    claude = next(s for s in scores if s.name == "claude-code-security-review")
    assert umbra.recall >= claude.recall
    assert umbra.false_positive_total == 0


def test_committed_capture_file_exists():
    p = Path(__file__).parent.parent / "umbra_eval" / "detection" / "captures" / "claude-opus-4-8.json"
    assert p.exists(), "committed Opus 4.8 capture is missing"


def test_codex_reported_not_run_without_capture():
    scores = run_corpus_head_to_head()
    codex = next(s for s in scores if s.name == "openai-codex-security")
    assert codex.ran is False  # honestly reported, never faked


def test_corpus_markdown_renders():
    scores = run_corpus_head_to_head()
    md = render_markdown(scores)
    assert "public test cases" in md
    assert "Recall by language" in md
    assert "umbra-core" in md
