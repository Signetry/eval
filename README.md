<div align="center">

# umbra-eval

**The public adversarial evaluation suite for [Umbra](https://github.com/bkd-dotcom/umbra-umbrella).**

Measures **attack success rate (ASR)** and **utility-under-defense** for coding-agent
threats — governed by the same [`umbra-core`](https://github.com/bkd-dotcom/umbra-core)
pipeline production uses.

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

## Threat categories (mapped to the research)

| Category | Threat | Basis |
|---|---|---|
| `ipi` | Indirect prompt injection via repository text (README / CLAUDE.md) | AgentDojo; OWASP LLM01 |
| `skill_poison` | Poisoned skill docs / hijacking MCP tool descriptions | SkillJect; ToolHijacker / MCPTox |
| `minja` | Memory / session-freshness injection (replay a stale authorization) | MINJA (NeurIPS 2025) |
| `utility` | A benign task / clean extension must **not** be blocked | utility-under-defense |

## Run it

```bash
pip install umbra-eval           # pulls umbra-core>=0.3.0

umbra-eval run                   # human summary (ASR / utility)
umbra-eval run --markdown        # publishable report
umbra-eval run --json            # machine-readable
umbra-eval run --category ipi    # one threat category
umbra-eval list                  # list scenarios
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

Part of the Umbra platform — see the [umbrella overview](https://github.com/bkd-dotcom/umbra-umbrella).

## License

[MIT](LICENSE) © 2026 Binay Dalai.
