# Contributing to umbra-eval

Thanks for helping make Umbra's evaluation honest and thorough. The most valuable
contribution here is **adding test cases** — every case makes the benchmark and the
adversarial suite stronger and harder to game.

## Setup

```bash
pip install -e ".[dev]"     # pulls umbra-core>=0.5.0 + test tooling
pytest -q                   # run the suite
ruff check umbra_eval/ tests/
```

## Add a detection corpus case (great first PR)

The detection corpus lives in `umbra_eval/detection/corpus/`, grouped by family
(`public`, `academic`, `crafted`, `hard`, `multilang`, `xfile_lang`). To add a case:

1. Append a `Case(...)` to the right family module with:
   - a unique `id`, the `language`, a short `title`,
   - a **`provenance`** string citing the public source (an OWASP category, a CWE,
     a representative CVE, or "crafted" for edge cases) — this keeps the corpus
     auditable,
   - the `files` (source as strings), and
   - `expected` = the ground-truth `ExpectedFinding`s (empty list = a SAFE decoy,
     used to measure false positives).
2. Run `umbra-eval corpus` and `pytest -q`. A vulnerable case must be detected; a
   SAFE case must produce **zero** findings (0 false positives is a hard rule).
3. Do **not** hand-tune the engine to a single case — a case earns its place only
   if the general rules catch it.

Cases must be **minimal reimplementations of publicly documented patterns**, not
copied from a copyrighted corpus.

## Add an adversarial scenario

Scenarios live in `umbra_eval/scenarios/` (categories: `ipi`, `skill_poison`,
`minja`, `utility`). Each models a non-compliant agent deterministically and offline
and is scored ungoverned vs governed through the real `umbra-core` pipeline. Keep
them reproducible — no network, no API keys.

## Honesty rules (non-negotiable)

- No number is rounded up; a tool that didn't run is reported as `not run`, never
  scored as zero.
- Governed ASR is never presented as "injection solved" — the claim is *bounded +
  quarantined + dual-verified + receipted*.

## Ground rules

- Keep governance logic in [`umbra-core`](https://github.com/bkd-dotcom/umbra-core);
  this repo evaluates, it does not reimplement policy.
- CI runs the suite on Python 3.11–3.13 and gates the detection benchmark on 100%
  recall / 0 false positives (deterministic layer).
- Be kind — see [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Report security issues via
  [private advisory](https://github.com/bkd-dotcom/umbra-eval/security/advisories/new),
  not a public issue.
