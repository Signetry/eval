"""The published pages are verified, never pushed — enforced here, not by memory.

`docs/LEADERBOARD.{md,json}` and `docs/BENCHMARK.{md,json}` are generated files that live
in the repository. Two workflows used to regenerate them and push the result straight to
`main`; `main` requires a pull request, so every run that actually had something to publish
was rejected by branch protection, and because the push came *before* each workflow's gate,
a broken defense would have surfaced as a git error instead of a failed gate.

The fix has three parts, and each is easy to undo by accident, so each is asserted:

1. Neither workflow can write to the repository — the pages arrive by pull request.
2. Both use the `Makefile` recipe rather than their own inlined copy of the commands, so
   the page a contributor regenerates is byte-for-byte the page CI checks against.
3. Both gates carry `if: !cancelled() && ...`, so an earlier failure cannot mask them.

These are text assertions on purpose: PyYAML is not a dependency of this suite, and adding
one to check four lines of workflow would cost more than it buys.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"

# (workflow, make target, the page it owns)
OWNERSHIP = [
    ("leaderboard.yml", "leaderboard", "LEADERBOARD"),
    ("benchmark.yml", "benchmark", "BENCHMARK"),
]

pytestmark = pytest.mark.skipif(
    not WORKFLOWS.is_dir(),
    reason="not running from a checkout (the workflows are not installed with the package)",
)


def _code_lines(text: str) -> list[str]:
    """Every line that is not a YAML comment.

    The workflows explain their own history in comments — including what they used to do —
    so a check for `git push` has to look at what runs, not at what is described.
    """
    return [ln for ln in text.split("\n") if not ln.strip().startswith("#")]


@pytest.mark.parametrize("workflow,target,page", OWNERSHIP)
def test_the_workflow_cannot_write_to_the_repository(workflow: str, target: str, page: str):
    text = (WORKFLOWS / workflow).read_text()
    block = re.search(r"^permissions:\n(?:[ \t]+\S.*\n)+", text, re.M)
    assert block, f"{workflow} must declare permissions explicitly"
    assert "contents: read" in block.group(0), f"{workflow} must take a read-only token"
    assert "write" not in block.group(0), (
        f"{workflow} requests write access. It publishes nothing: the pages reach `main` "
        "through a pull request, which is what branch protection requires and what this "
        "repository argues for."
    )


@pytest.mark.parametrize("workflow,target,page", OWNERSHIP)
def test_the_workflow_does_not_push(workflow: str, target: str, page: str):
    code = "\n".join(_code_lines((WORKFLOWS / workflow).read_text()))
    for forbidden in ("git push", "git commit", "git config user"):
        assert forbidden not in code, (
            f"{workflow} runs `{forbidden}`. Pushing to a protected branch is the bug this "
            "design removed — regenerate, diff, and fail if the committed page is stale."
        )


@pytest.mark.parametrize("workflow,target,page", OWNERSHIP)
def test_the_workflow_uses_the_shared_recipe(workflow: str, target: str, page: str):
    code = "\n".join(_code_lines((WORKFLOWS / workflow).read_text()))
    assert f"make {target}" in code, (
        f"{workflow} must regenerate with `make {target}`, not its own copy of the "
        "commands: a regenerate-and-diff check is only meaningful if CI and contributors "
        "run the same recipe."
    )
    assert f"make check-{target}" in code, (
        f"{workflow} must verify with `make check-{target}` — regenerating without diffing "
        "checks nothing."
    )


@pytest.mark.parametrize("workflow,target,page", OWNERSHIP)
def test_the_checkout_ref_is_not_a_falsy_ternary(workflow: str, target: str, page: str):
    """`A && '' || B` is always B, so the workflow would verify the wrong tree.

    Actions' `&&` and `||` yield operand values rather than booleans, which makes the
    familiar ternary spelling a trap whenever the true branch is falsy: an empty string
    collapses straight through to the false branch. Both of these workflows shipped exactly
    that for one run, and PR #39 verified `main` instead of itself — the check passed and
    proved nothing about the change under review.
    """
    # Comments only, and the comment above the ref quotes the trap to explain it.
    code = "\n".join(_code_lines((WORKFLOWS / workflow).read_text()))
    for trap in ("&& '' ||", '&& "" ||', "&& ''||"):
        assert trap not in code, (
            f"{workflow} uses a ternary with an empty true branch. Actions evaluates "
            f"`cond && '' || other` to `other` for every event, so the ref this resolves to "
            "is not the one it looks like. Give the true branch a non-empty value."
        )


@pytest.mark.parametrize("workflow,target,page", OWNERSHIP)
def test_the_pull_request_run_verifies_the_pull_request(workflow: str, target: str, page: str):
    """A verification that checks out the default branch on a PR verifies nothing.

    `github.ref` is `refs/pull/N/merge` on a pull request — the merge result, which is what
    actually lands. Only a release needs the override, because its ref is the tag rather
    than the branch the page is committed on.
    """
    text = (WORKFLOWS / workflow).read_text()
    ref = re.search(r"^\s+ref: (.+)$", text, re.M)
    assert ref, f"{workflow} must pin the checkout ref explicitly"
    expr = ref.group(1)
    assert "github.ref" in expr, (
        f"{workflow} must verify the triggering ref (so a PR verifies itself); got {expr!r}"
    )
    assert "release" in expr, (
        f"{workflow} must special-case the release event, whose ref is the tag and not where "
        f"the page is committed; got {expr!r}"
    )


@pytest.mark.parametrize("workflow,target,page", OWNERSHIP)
def test_the_workflow_refuses_a_tree_that_lacks_the_recipe(workflow: str, target: str, page: str):
    """`make <target>` can exit 0 having done nothing at all.

    With no Makefile in the tree, make falls back to implicit rules — and `leaderboard` is a
    real directory in this repository, so make calls the target up to date and prints
    "Nothing to be done for 'leaderboard'" with status 0. That is how a run regenerated
    nothing, uploaded the committed page as its artifact, and still reported the
    regeneration step green. Same shape as the push step that exited 0 on "no change to
    publish": a step that succeeds without doing its job.
    """
    code = "\n".join(_code_lines((WORKFLOWS / workflow).read_text()))
    assert "test -f Makefile" in code, (
        f"{workflow} must confirm the recipe is present before running it — otherwise a "
        "wrong-tree checkout regenerates nothing and still passes."
    )


@pytest.mark.parametrize("workflow,target,page", OWNERSHIP)
def test_the_gate_cannot_be_masked_by_an_earlier_failure(workflow: str, target: str, page: str):
    text = (WORKFLOWS / workflow).read_text()
    assert "id: regen" in text, f"{workflow} needs an id on the regeneration step for the gate to key off"
    assert "!cancelled() && steps.regen.outcome == 'success'" in text, (
        f"{workflow}'s gate must run even when the staleness check failed. Without the "
        "guard, a stale page aborts the job first and the defense is never judged — which "
        "is exactly how a rejected push used to hide a possible regression."
    )


@pytest.mark.parametrize("workflow,target,page", OWNERSHIP)
def test_the_committed_page_names_the_recipe_that_writes_it(workflow: str, target: str, page: str):
    md = ROOT / "docs" / f"{page}.md"
    if not md.is_file():
        pytest.skip(f"docs/{page}.md is not present in this tree")
    first = md.read_text().strip().split("\n")[0]
    assert f"make {target}" in first, (
        f"docs/{page}.md must name the recipe that regenerates it, so a reader can "
        f"reproduce the page instead of hand-editing it (got: {first!r})"
    )
    assert workflow in first, f"docs/{page}.md must name the workflow that verifies it (got: {first!r})"
    assert "do not edit by hand" in first


def test_the_benchmark_header_is_not_duplicated_out_of_sync():
    """The benchmark header is written by the Makefile; the leaderboard's by Python.

    Only the benchmark's lives in two places (the recipe that writes it and the committed
    file), so only it can drift silently. Pin them together.
    """
    makefile = ROOT / "Makefile"
    md = ROOT / "docs" / "BENCHMARK.md"
    if not (makefile.is_file() and md.is_file()):
        pytest.skip("Makefile or docs/BENCHMARK.md is not present in this tree")
    first = md.read_text().strip().split("\n")[0]
    assert first in makefile.read_text(), (
        "docs/BENCHMARK.md's header is not the one `make benchmark` emits — regenerate it "
        f"(committed header: {first!r})"
    )
