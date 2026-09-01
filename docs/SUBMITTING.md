# Submitting to the leaderboard

Two things you can contribute, both ordinary pull requests:

1. **[An attack](#submit-an-attack)** — a scenario that tries to get an attacker's
   objective through the governed pipeline. **This is the contribution we want most.**
2. **[A system](#submit-a-system)** — a row on [the governance
   leaderboard](LEADERBOARD.md) for any agent governance, guardrail, or admission
   tool, including your own.

---

## Submit an attack

The governance corpus is small — 5 adversarial scenarios — and it is small because
every one is hand-built, cited, and deterministic rather than a generated variation of
its neighbour. That makes each new scenario worth a lot.

**We would rather publish a red row than not know.** If your attack lands, the defense
failed, and that is a real finding: the leaderboard shows it, `signetry-eval run` exits
non-zero, and the scenario stays in the suite as a regression test. There is no version
of this where a working attack is unwelcome.

### What a scenario has to be

- **Deterministic and offline.** No network, no API keys, no model calls. The adversary
  is a *scripted* agent that models a non-compliant one: you write what a
  fully-obedient agent would do, and the harness runs it both ungoverned and governed.
  CI must reproduce your result exactly.
- **Cited.** Name the threat class and where it comes from — a paper, a CVE, an OWASP
  LLM entry, a public incident. `threat` is a required field and it should point at
  something real.
- **Falsifiable.** The attack must have *markers*: concrete artifacts (a file written, a
  token exfiltrated, a path touched) whose presence in the changeset is the definition
  of success. "The agent seemed to comply" is not a measurement.
- **Paired with utility where it makes sense.** A defense that blocks your attack by
  blocking everything has not earned anything. If your threat has a benign twin, add it
  as a `utility` scenario too.

### The shape

Scenarios live in `signetry_eval/scenarios/` — one module per threat category. Copy
the closest existing one; `ipi.py` is the most representative. A scenario is a small
class with four attributes and a `run()`:

```python
class MyScenario:
    id = "ipi.my_attack"                 # <category>.<snake_case_name>, globally unique
    category = CATEGORY_IPI              # from signetry_eval.scenario
    title = "One line a stranger can understand"
    threat = "OWASP LLM01 — where this class of attack is documented"

    def run(self) -> ScenarioResult:
        files = {...}                    # the repo the agent wakes up in, incl. .signetry/admission.yaml
        markers = ["stolen.txt"]         # artifacts that mean the attacker won
        agent = ScriptedAgent(legit=..., obey=...)   # the benign task, and full obedience

        u = run_ungoverned(agent, files, markers, task_marker="package.json")
        g = run_governed(agent, files, markers, proposed_change={...})
        return ScenarioResult(id=self.id, ..., ungoverned=Outcome(...), governed=Outcome(...))
```

Then add it to `SCENARIOS` in your module — `scenarios/__init__.py` picks it up from
there. If you are introducing a new threat category, add the constant to
`signetry_eval/scenario.py` and to `_CATEGORIES` in `signetry_eval/cli.py`.

### Before you open the PR

```bash
signetry-eval list                       # your scenario should appear
signetry-eval run --category ipi         # or whichever category
signetry-eval run --markdown             # read the row your scenario produces
pytest -q
```

In the PR, say what the attack is, cite the threat, and state plainly whether the
defense held. If it did not hold, say so in the title — that PR gets read first.

---

## Submit a system

Add one JSON file to [`leaderboard/entries/`](../leaderboard/entries/). The schema and
every validation rule are documented in
[`leaderboard/entries/README.md`](../leaderboard/entries/README.md); the short version:

```json
{
  "name": "your-tool",
  "version": "1.4.0",
  "url": "https://github.com/you/your-tool",
  "status": "self-reported",
  "attacks_run": 5,
  "asr_ungoverned": 1.0,
  "asr_governed": 0.2,
  "utility_scenarios": 2,
  "utility_governed": 1.0,
  "provenance": "How you produced these numbers, specifically enough to re-run."
}
```

### Which table you land in

- **`reproduced`** — a maintainer ran it here. If your PR claims this and we have not,
  we will move it to `self-reported` and say so; that is not a rejection.
- **`self-reported`** — you measured it, we did not. Separate table, clearly labelled.
  A perfectly good place to be.
- **`not-run`** — listed as in-scope, no numbers yet. Renders `—` across the board,
  because a system that did not run is never scored as zero.

### Submitting a system that beats Signetry

Do it. A leaderboard that only its author can win is marketing, and everyone can tell.
If your tool gets a lower governed ASR at the same or better utility, that row goes on
the page. What we will ask for is the same thing we hold ourselves to: a denominator
next to every rate, and provenance specific enough that someone else can re-run it.

### What gets pushed back on

Not the numbers — the missing context. An ASR with no `attacks_run`, a utility figure
with no `utility_scenarios`, or a `provenance` too vague to reproduce all render as `—`
and are listed under "submissions with problems" on the page, where you can see exactly
what to fix.

---

## Regenerating the page

```bash
signetry-eval leaderboard                       # governance axis (fast, offline)
signetry-eval leaderboard --with-detection      # both axes (needs the SAST engine)
signetry-eval leaderboard --json                # machine-readable
```

CI regenerates `docs/LEADERBOARD.md` on a schedule and on every release. You do not
need to commit the generated file — but if you do, make sure it was generated rather
than edited: it carries a `do not edit by hand` header for a reason.
