# Security Policy

`signetry-eval` is the public adversarial evaluation suite for a **security tool** — the
numbers it publishes are what people use to decide whether to trust Signetry's defense.
We treat reports against it accordingly: a flaw that makes this suite overstate a
defense is a security issue here, not a cosmetic one.

## Supported versions

Fixes land on the latest tagged release of this repository
([releases](https://github.com/Signetry/eval/releases)); install from source
(`pip install -e .`, or `signetry-eval @ git+https://github.com/Signetry/eval@<tag>`).
Always run the latest — the corpus and the pinned `signetry-core` move together.

| Version | Supported |
|---|---|
| `0.3.0` | ✅ current — the governance leaderboard, 60-case OWASP corpus, `signetry-core` `v0.8.0` |
| `0.2.0`–`0.2.3` | ⚠️ superseded — the "pinned" real-repo cases were silently scanning the default-branch tip (see `CHANGELOG.md`) |
| `< 0.2.0` | ❌ upgrade |

## Reporting a vulnerability

**Please do not open a public issue for security reports.**

Use GitHub's private vulnerability reporting on this repo:
**https://github.com/Signetry/eval/security/advisories/new**

Include, where possible: the version or commit, a minimal reproduction (the scenario or
corpus case id, the command, and the report/JSON output), and the impact. We aim to
acknowledge within a few days and to fix confirmed issues promptly, then credit
reporters who wish to be named.

**Report engine vulnerabilities upstream.** A governance bypass, authority escalation,
receipt forgery, or secret exposure in `signetry-core` belongs at
[Signetry/core's advisories](https://github.com/Signetry/core/security/advisories/new) —
this repo imports the engine and never implements governance itself.

## What counts as a vulnerability *here*

This suite's product is an honest measurement, so anything that corrupts the measurement
in the flattering direction is in scope:

- **A scenario that reports the attack as blocked when the attacker's objective actually
  landed** in the admitted change — a false "governed ASR 0".
- **Wrong ground truth in the detection corpus** — a case whose `expected` findings do
  not match the vulnerability actually present, or a SAFE decoy that is in fact
  vulnerable. Either way the published recall / false-positive numbers become wrong.
- **A competitor score that is not what the capture says** — replayed captures must
  score exactly the recorded run, and a tool that was not run must be reported as
  `not run`, never as zero.
- **A pinning or provenance failure** — a case documented as pinned that silently scans
  something else (this happened; see the `0.2.x` note above), or a `provenance` citation
  that does not support the case.
- **Untrusted input escaping the harness** — the scenarios embed adversarial repository
  text (injected READMEs, poisoned skill docs, MCP tool descriptions) on purpose. If any
  of that content can execute code, escape a temporary directory, or reach the network
  during `signetry-eval run`, that is a vulnerability.
- **Anything unsafe in `realrepo`'s clone/checkout handling**, which is the only path
  that touches third-party code.

Out of scope: the suite reporting a *worse* number for Signetry than expected (that is
the point — file a normal issue or a PR with the case), and the optional Semgrep layer's
findings, which are report-only and non-gating by design.

## Honest scope of what this suite proves

- **Scenarios are deterministic and offline.** They script an adversary that *models* a
  non-compliant agent — one that obeys instructions it can read. There is no live model,
  no network, and no API key in `signetry-eval run`. That makes results reproducible; it
  also means they measure the architecture's bound, not a real model's behaviour.
- **Low governed ASR is not proof of coverage.** A fixed-pattern detector can be
  paraphrased around. New adversarial phrasings belong in this repo as new scenarios, and
  the curve is published as it is.
- **`signetry-eval realrepo` is opt-in and needs network + git.** It shallow-clones
  pinned public repositories and runs the engine's **read-only static scan** over them —
  no agent, no code execution on the cloned repo, no credentials required. If pinning
  cannot be honoured it says so in the result note rather than reporting an unpinned scan
  as pinned.
- **Competitor numbers come from committed captures** in
  `signetry_eval/detection/captures/`, because running those scanners live needs paid
  credentials. The capture is the auditable record; re-run it yourself and open an issue
  if it does not reproduce.
