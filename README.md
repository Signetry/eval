<div align="center">

# umbra-eval

> **Copyright (c) 2026 Binay Dalai. All rights reserved.**
> This repository is strictly for viewing and contributing to the original project. You may not use, copy, modify, distribute, or commercialize this code for your own personal or commercial projects without explicit written permission. Only the original author retains the right to use and monetize this project.


**The public adversarial evaluation suite for [Umbra](https://github.com/bkd-dotcom/umbra-umbrella).**

Measures **attack success rate (ASR)** and **utility-under-defense** for coding-agent
threats — governed by the same [`umbra-core`](https://github.com/bkd-dotcom/umbra-core)
pipeline production uses.

[![Source-available](https://img.shields.io/badge/source-available-informational.svg)](CLA.md)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome%20(CLA)-brightgreen.svg)](https://github.com/bkd-dotcom/umbra-umbrella/issues/10)

</div>

---

Umbra's honest claim is never "prompt injection solved." It is **bounded +
quarantined + dual-verified + receipted**: the governed run keeps the attacker's
objective out of the *admitted* change and caps authority on the evidence, while
the legitimate task still ships with a signed receipt. This suite measures exactly
that — with the ungoverned baseline right beside it, so the number is honest.

Every scenario is **deterministic and offline** (a scripted adversary that *models*
a non-compliant agent — one that obeys instructions it can read). No network, no
API keys, reproducible in CI.

## What it measures

For each scenario, two conditions:

- **Ungoverned** — the agent/tooling runs with no Umbra checkpoint.
- **Governed** — the same run passes through `umbra-core` (`run_admission` /
  `admit_extension`), exactly as production uses it.

…and two questions: **did the attack succeed?** (ASR) and **did the benign task
still complete?** (utility). A defense that blocks everything scores ASR 0 with
zero utility — useless. The number that matters is **ASR under defense at preserved
utility**.

## Detection benchmark (head-to-head)

Beyond the adversarial suite, umbra-eval runs a **public detection benchmark** that
scores Umbra's SAST engine against LLM security scanners on a shared, provenance-
cited corpus — **52 cases across 7 languages** (Python, JavaScript, Go, Java, Ruby,
PHP, C#) in six families (public/OWASP, academic/CWE, crafted, hard cross-file
taint, multilang, cross-file-lang), with safe decoys for false-positive measurement.

| Scanner | Recall | False positives | Cost |
|---|:---:|:---:|---|
| **umbra-core** (deterministic) | **100%** (42/42) | **0** | free · offline · reproducible |
| claude-code-security-review (Claude Opus 4.8) | 90% (38/42) | 0 | paid per scan · non-deterministic |
| @openai/codex-security | not run¹ | — | paid per scan |

¹ Competitor scores replay a committed capture; a tool that wasn't run is shown as
`not run`, never scored as zero.

Umbra reaches this on the **deterministic, offline, free** layer — same result every
run. The optional **Semgrep** layer (`--semgrep`) broadens coverage but can add
false positives (its generic rules don't model every sanitizer); Umbra's
deterministic engine is **0-FP** on the corpus, including sanitizer-aware cases
where Semgrep is not — so the Semgrep layer is opt-in and non-gating. Detection
parity is table stakes; the **governance** Umbra adds on top (earned authority,
injection quarantine, independent verifier, signed receipts) is what the scanners
don't attempt, and is measured by the adversarial suite below.

## Threat categories (mapped to the research)

| Category | Threat | Basis |
|---|---|---|
| `ipi` | Indirect prompt injection via repository text (README / CLAUDE.md) | AgentDojo; OWASP LLM01 |
| `skill_poison` | Poisoned skill docs / hijacking MCP tool descriptions | SkillJect; ToolHijacker / MCPTox |
| `minja` | Memory / session-freshness injection (replay a stale authorization) | MINJA (NeurIPS 2025) |
| `utility` | A benign task / clean extension must **not** be blocked | utility-under-defense |

## Run it

```bash
pip install -e .                 # pulls umbra-core from its source repo (not on PyPI)

umbra-eval run                   # human summary (ASR / utility)
umbra-eval run --markdown        # publishable report
umbra-eval run --json            # machine-readable
umbra-eval run --category ipi    # one threat category
umbra-eval list                  # list scenarios

umbra-eval corpus                # detection head-to-head (recall, FP, by-language)
umbra-eval corpus --markdown     # publishable comparison table
umbra-eval corpus --semgrep      # add the optional Semgrep layer (report-only)
umbra-eval realrepo              # live scan of real vulnerable repos
```

`umbra-eval run` exits non-zero if the defense did not hold on **every** adversarial
scenario, so it doubles as a CI regression guard.

```python
from umbra_eval import run_all
report = run_all()
print(report.overall())          # asr_ungoverned, asr_governed, utility_governed, …
```

## Interpreting the results

- **ASR (governed) → low** means Umbra kept the tested attacks out of the admitted
  change. It is **not** proof of coverage against unseen phrasings — a fixed pattern
  detector can be paraphrased around. New adversarial phrasings belong in this repo
  as new scenarios (adaptive red-teaming), and the curve is published honestly.
- **Utility (governed) → high** means real work still ships under the same defense.
- The **MINJA** scenario shows *why* a receipt can't be replayed: it is bound to the
  base commit, the diff hash, and the plan capability set's hash, so a prior
  authorization cannot bless a different change.

## Design

- No governance logic lives here — it is imported from `umbra-core`. This repo only
  *poses attacks* and *scores outcomes*.
- Scenarios implement a tiny `Scenario` protocol (`run() -> ScenarioResult`) and are
  registered in [`umbra_eval/scenarios`](umbra_eval/scenarios).
- Add a scenario: model the attack, run it ungoverned + governed via the harness,
  and return a `ScenarioResult`.

## Contributing

**Source-available, PRs welcome** (not open source; All Rights Reserved). Contribute under the [CLA](CLA.md) — you're **credited** ([CONTRIBUTORS.md](CONTRIBUTORS.md)) but gain no ownership or right to use/sell it. Start at the [good-first-issues board](https://github.com/bkd-dotcom/umbra-umbrella/issues/10). The best contribution is **a new test case**. Add a detection
**corpus case** (`umbra_eval/detection/corpus/`, with a cited `provenance`; SAFE
decoys must stay 0 false positives) or an **adversarial scenario**
(`umbra_eval/scenarios/`). See [CONTRIBUTING.md](CONTRIBUTING.md) and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Every case ships with a test; CI gates the
benchmark on 100% recall / 0 FP.

Part of the Umbra platform — see the [umbrella overview](https://github.com/bkd-dotcom/umbra-umbrella).

## License

**Copyright (c) 2026 Binay Dalai. All rights reserved.** This code is not open source. You may not use, copy, modify, distribute, or commercialize it for your own personal or commercial purposes without explicit written permission from the author, who alone retains the right to use and monetize this project. See [CONTRIBUTING.md](CONTRIBUTING.md).
