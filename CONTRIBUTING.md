# Contributing to signetry-eval

`signetry-eval` is **[Apache-2.0](LICENSE)** — use it, fork it, run it in your own CI,
ship it commercially, no permission needed. This file covers what the licence means for
contributors, why a CLA still applies, and how to get a change merged.

The most valuable contribution here is **a new test case**: an adversarial scenario that
Signetry's defense does *not* yet hold against, or a detection corpus case with cited
provenance. This suite exists to publish the honest number, so a case that makes the
number worse is a good contribution, not a bad one.

## Licensing, in plain terms

- **This repository is Apache-2.0.** You may use, copy, modify, distribute, and
  commercially deploy it, including forks and derivative eval suites. Nothing is gated
  on asking us first.
- **Signetry is open core.** The integration surface — this repo, the
  [GitHub Action](https://github.com/Signetry/action), the
  [editor/agent plugins](https://github.com/Signetry/plugins), the
  [pre-commit guard](https://github.com/Signetry/precommit) — is Apache-2.0. The engine
  ([`Signetry/core`](https://github.com/Signetry/core)) is source-available under
  BUSL-1.1 and converts to Apache-2.0 on **2030-08-31**. See
  [LICENSING.md](https://github.com/Signetry/signetry/blob/main/LICENSING.md).
- **`signetry-core` installs from source, not PyPI.** `pyproject.toml` carries it as a
  pinned `git+https` dependency; that is a distribution choice, not a restriction on
  what you may do with this repo.

### The CLA still applies — and why

Open source and a CLA are not in tension. Because Signetry is open core, code
legitimately moves **across the licence line**: a harness or adapter that starts life
here (Apache-2.0) may later belong inside the engine (BUSL-1.1), and engine code may
move out to the integration surface. The [CLA](CLA.md) gives the maintainer the
relicensing rights that make those moves possible without tracking down every past
contributor for permission.

What it does **not** do is take anything from you: you keep the full Apache-2.0 grant on
this repository, exactly like every other user, and you keep the right to use your own
work however you like elsewhere. Contributors are credited in
[CONTRIBUTORS.md](CONTRIBUTORS.md), the Git history, and release notes.

## Signing the CLA (required before merge)

This is enforced by a bot. When you open a pull request, the **CLA Assistant** check
will ask you to sign the [Contributor License Agreement](CLA.md). Reply on the PR
with exactly:

```
I have read the CLA Document and I hereby sign the CLA
```

Your acceptance is recorded in `signatures/cla.json`. A PR **cannot be merged** until
the CLA is signed.

## Development setup

Python **3.11+** (CI runs 3.11, 3.12 and 3.13).

```bash
pip install -e ".[dev]"      # pulls signetry-core from its source repo (not on PyPI)
```

A `uv.lock` is committed, so `uv sync --extra dev` installs the exact locked set if you
prefer [uv](https://docs.astral.sh/uv/).

## Lint and test (what CI runs)

```bash
ruff check signetry_eval/ tests/
pytest -q
```

Both commands are exactly what `.github/workflows/eval.yml` runs on every push and PR.
Ruff is configured in `pyproject.toml` (line length 110, rules `E,F,W,I,RUF`).

The detection benchmark is gated, so run the gate locally before pushing a corpus
change:

```bash
signetry-eval corpus --min-recall 1.0 --max-fp 0
```

CI runs that same gate whenever the installed `signetry-core` exposes the detection
engine (`scan_repository`), and the release workflow enforces it unconditionally.

## Running the suite

```bash
signetry-eval run                   # human summary (ASR / utility)
signetry-eval run --markdown        # publishable report
signetry-eval run --json            # machine-readable
signetry-eval run --category ipi    # one threat category
signetry-eval list                  # list scenarios

signetry-eval corpus                # detection head-to-head (recall, FP, by-language)
signetry-eval corpus --markdown     # publishable comparison table
signetry-eval corpus --semgrep      # add the optional Semgrep layer (report-only)
signetry-eval realrepo              # live scan of real vulnerable repos (needs network + git)
```

`signetry-eval run` exits non-zero if the defense did not hold on every adversarial
scenario, so it doubles as a CI regression guard.

## Adding an adversarial scenario

1. Pick the threat category (`ipi`, `skill_poison`, `minja`, `utility`) and edit the
   matching module in [`signetry_eval/scenarios/`](signetry_eval/scenarios).
2. Implement the `Scenario` protocol from
   [`signetry_eval/scenario.py`](signetry_eval/scenario.py) — `run() -> ScenarioResult`
   — and append it to that module's `SCENARIOS` list, which
   `signetry_eval/scenarios/__init__.py` aggregates into `ALL_SCENARIOS`.
3. Run the attack **both** ungoverned and governed through the harness, so the report
   carries the honest baseline beside the defended number.
4. Keep it **deterministic and offline**: a scripted adversary that models a
   non-compliant agent. No network, no API keys.
5. Add a test under `tests/`.

No governance logic belongs in this repo — it is imported from `signetry-core`. This
repo poses attacks and scores outcomes.

## Adding a detection corpus case

1. Add a `Case` (see
   [`signetry_eval/detection/corpus/schema.py`](signetry_eval/detection/corpus/schema.py))
   to the family module it belongs to in
   [`signetry_eval/detection/corpus/`](signetry_eval/detection/corpus) — `public.py`,
   `academic.py`, `crafted.py`, `hard.py`, `multilang.py`, or `xfile_lang.py`. Each
   family module's `CASES` list is aggregated in that package's `__init__.py`.
2. Give it a **cited `provenance`** string (OWASP, a public CVE, an academic CWE/SARD-family
   pattern, or an explicitly crafted edge case). Cases are minimal reimplementations of
   publicly documented patterns, labelled with the canonical CWE — never copied verbatim
   out of a copyrighted corpus.
3. List ground truth in `expected` (CWE + category + file). An **empty `expected` means a
   SAFE decoy**: any finding on it counts as a false positive.
4. Case ids must be unique across families (the package asserts this on import).
5. Run `signetry-eval corpus --min-recall 1.0 --max-fp 0` and add a test.

A SAFE decoy that exposes a real false positive is a *good* result — it is how `LANG-60`
caught a bug in the engine's Go SSRF rule (see `CHANGELOG.md`).

## Pull requests

- Start at the [good-first-issues board](https://github.com/Signetry/signetry/issues/10).
- Keep the diff focused; every new case ships with a test.
- An advisory reviewer bot comments on PRs. It never merges and never fails your PR.
- Be decent to each other: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- Found a security problem instead of a bug? Do not open a public issue — see
  [SECURITY.md](SECURITY.md).
