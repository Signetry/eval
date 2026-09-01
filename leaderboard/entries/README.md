# Governance leaderboard entries

One JSON file per system on [the governance axis](../../docs/LEADERBOARD.md). Adding a
file here is how a system gets listed — including your own, and including one that
beats Signetry. Open a pull request.

## Schema

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
  "provenance": "Run against signetry-eval's 5 adversarial scenarios at commit abc1234 with `your-tool guard --strict`; logs attached to PR #42.",
  "notes": "Optional. Anything a reader needs to interpret the numbers fairly."
}
```

| Field | Required | Meaning |
|---|:---:|---|
| `name` | yes | The system as people refer to it. |
| `status` | yes | `reproduced` \| `self-reported` \| `not-run` — see below. |
| `url` | no | Where to find it. |
| `version` | no | What was measured. Strongly encouraged: a rate with no version is hard to trust later. |
| `attacks_run` | for any ASR | Denominator for the ASR figures. |
| `asr_ungoverned` | no | Fraction 0–1. Attack success with the system disabled. |
| `asr_governed` | no | Fraction 0–1. Attack success with it enabled. |
| `utility_scenarios` | for utility | Denominator for `utility_governed`. |
| `utility_governed` | no | Fraction 0–1. Benign tasks that still complete under the defense. |
| `provenance` | unless `not-run` | How the numbers were produced, specifically enough to re-run. |
| `notes` | no | Caveats, scope, anything that stops a reader over-reading the row. |

## The three status values

- **`reproduced`** — we ran it here and the numbers came out of our CI. Use this only
  if a maintainer has actually reproduced the run; a submission claiming it will be
  moved to `self-reported` until then.
- **`self-reported`** — you measured it, we did not. Listed in a **separate table**, so
  nobody mistakes it for something we verified. This is a perfectly good place to be.
- **`not-run`** — in scope for the comparison, no measurement yet. Renders as `—`
  across the board. A system that did not run is never scored as zero.

## What the renderer will reject

The loader validates every submission and prints problems on the page rather than
dropping the file, so a broken entry is visible to you:

- a rate outside 0–1, or one that is not a number
- an ASR with no `attacks_run`, or a utility figure with no `utility_scenarios` — a
  rate with no denominator is not a measurement
- a missing `provenance` on anything other than `not-run`
- a `status` outside the three values above

Anything invalid renders as `—`, never as a favourable number.
