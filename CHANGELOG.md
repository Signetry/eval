# Changelog — signetry-eval

Follows [Keep a Changelog](https://keepachangelog.com/) / [SemVer](https://semver.org/).
Until `1.0.0` the public API may change between minor versions.

## [Unreleased]

### Fixed — the pages that publish the numbers could not publish

`leaderboard.yml` and `benchmark.yml` regenerated their pages and pushed the result
straight to `main`. `main` requires a pull request, so every run that actually had
something to publish was rejected by branch protection (`GH006: Changes must be made
through a pull request`) — the weekly refresh on 2026-09-07 and the `v0.3.0` release run
on 2026-09-01 both failed at the push. The published numbers went stale rather than
current: `docs/LEADERBOARD.json` still labelled the live row `0.7.0` after
`pyproject.toml` had been pinned to `signetry-core v0.8.0`.

Both workflows now **verify instead of publish**. Each regenerates its page, diffs it
against what is committed, and fails if the committed page is stale; `permissions:`
dropped from `contents: write` to `contents: read`, so neither can write to the repository
at all. Refreshing is an ordinary pull request — a governance product whose own numbers
arrive by a bot bypassing branch protection is arguing against its own thesis.

- **Both gates were masked by the failure.** Each workflow ordered its gate — `signetry-eval
  run` for the governed defenses, corpus parity for detection — *after* the push. A rejected
  push aborts the job before the gate, so a broken defense or a detection regression would
  have surfaced as a git error, or not at all. Both gates now carry
  `if: ${{ !cancelled() && steps.regen.outcome == 'success' }}` and are judged whatever the
  page check says.
- **`benchmark.yml` had the same bug and looked green.** Its push step exited 0 on `no
  change to publish`, so the protected-branch failure stayed invisible there until the
  table actually changed.
- **One recipe, in a `Makefile`.** CI inlined its own copy of the generation commands while
  the page told readers to regenerate with `signetry-eval leaderboard --markdown` — which
  omits `--with-detection` and `--version` and so produces a different page. Under a
  regenerate-and-diff check, that drift is a stale-page failure nobody could explain from
  the log. `make leaderboard` and `make benchmark` are now the single recipe: for CI, for
  contributors, and in the instructions printed on the page itself. The generated headers
  name that recipe.
- **`pyproject.toml` is now a trigger path for both.** The pinned `signetry-core` is the
  live row's version label, so bumping the pin without refreshing was precisely the
  staleness that went unnoticed. Both workflows also verify on `pull_request`, so a stale
  page blocks the merge instead of being found a week later by the schedule.
- **A regeneration that regenerates nothing now fails.** `make leaderboard` in a tree with
  no Makefile does not error: `leaderboard/` is a real directory here, so make calls the
  target up to date and exits 0 with "Nothing to be done". That is the same shape as the
  push step that exited 0 on "no change to publish" — a step that reports success without
  doing its job — so both workflows confirm the recipe is present before trusting it.
- `make verify-published-numbers` reproduces the whole check locally.

## [0.3.0] — 2026-09-01

### Added — the Agent Governance Leaderboard

Detection is table stakes. The axis nobody publishes is **governance**: when the
repository itself is hostile, does the agent's change still get admitted, and what does
the defense cost in benign work? [`docs/LEADERBOARD.md`](docs/LEADERBOARD.md) publishes
both axes on one page and **takes third-party submissions**, so the governance axis can
become a real comparison instead of a self-report.

- `signetry_eval/leaderboard.py` renders the page and enforces three rules in code
  rather than by good intentions: an unmeasured number is `—` and never `0%`;
  reproduced and self-reported rows never share a table; every rate is printed next to
  its denominator. A submitted rate with no denominator is refused and shown as
  unmeasured, with the reason listed on the page.
- `signetry-eval leaderboard` (`--with-detection`, `--json`, `--entries`) — a new
  subcommand. Exits non-zero if any governed defense failed.
- `leaderboard/entries/` takes one JSON file per system, schema documented in its
  [README](leaderboard/entries/README.md). The ungoverned baseline ships as its own
  visible row rather than being implied by a column heading.
- [`docs/SUBMITTING.md`](docs/SUBMITTING.md) — how to submit an attack that beats the
  governed pipeline, and how to submit a system, **including one that beats Signetry**.
- `.github/workflows/leaderboard.yml` regenerates the page weekly, on release, and when
  an entry or scenario changes. `benchmark.yml` moved onto the same schedule: both pages
  were previously release-only, so published numbers could be months stale while still
  reading as current. Each workflow owns exactly one page, so every "Generated by …"
  header names the workflow that actually wrote it.

### Fixed — a competitor was scored on cases it was never run on

The corpus benchmark charged a replayed scanner with a **miss** for any case absent from
its capture. Captures are taken at a point in time and this corpus grows, so the 8 cases
added in the 52 → 60 expansion were counted as failures for
`claude-code-security-review` — 5 of them vulnerable. Its published recall read **81%
(38/47)** when the honest figure over the cases it was actually given is **90%
(38/42)**.

That is the same defect this suite calls out everywhere else — a score on evidence that
does not exist — except pointed outward at a named tool, and it inflated our lead by
about nine points.

- A case absent from a scanner's capture is now `covered=False` and excluded from its
  recall, false-positive count, and per-family/per-language breakdowns. An entry that is
  *present* but lists no findings is still a genuine miss; only "never run" is excused.
- Every table now prints **Cases scored** per scanner, and the excluded case ids are
  listed under Notes — excluding them silently would be its own dishonesty, since the
  two scanners are no longer scored over the same set.
- `CorpusScore.recall` returns `None` rather than `0.0` when nothing was measured, and
  the `--min-recall` gate now fails on an unmeasured recall instead of passing it.

### Fixed — unmeasured per-category metrics rendered as 0%

`Report.by_category()` reported `0` for metrics with no evidence behind them: an
attack-only category showed `Utility 0%` (reading as "Signetry destroyed utility here")
and the utility category showed `ASR 0%` over zero attacks. Both are now `None`, render
as `—`, and serialize as `null`. A *measured* zero is still reported as `0%` — the rule
is no unearned numbers, not no zeros.

### Changed — Signetry is now open core; this repo is Apache-2.0

- An [Apache-2.0](LICENSE) **LICENSE** file is now present, replacing the previous
  "All Rights Reserved" terms, as part of Signetry's
  [open-core model](https://github.com/Signetry/signetry/blob/main/LICENSING.md). The
  engine ([`Signetry/core`](https://github.com/Signetry/core)) is source-available under
  BUSL-1.1 and converts to Apache-2.0 on 2030-08-31.
- **This repository has no strings deliberately.** A benchmark nobody can freely run,
  audit, and reproduce is worthless as evidence, so the eval suite carries the most
  permissive licence of anything in the platform — fork it, re-run it, publish results
  that disagree with ours.
- `pyproject.toml` declares `license = "Apache-2.0"` and the OSI Apache classifier,
  replacing `Proprietary — All Rights Reserved`.
- The all-rights-reserved framing is gone from `README.md`, `CONTRIBUTING.md`,
  `CLA.md`, `CONTRIBUTORS.md`, and the CLA workflow's PR comment.
- **The CLA is kept**, and its fallback licence grant is now **non-exclusive** so a
  contributor never loses the right to use their own contribution. See
  [CLA.md](CLA.md) §2–3.

### Added — community health files

- `SECURITY.md`, `CODE_OF_CONDUCT.md` (Contributor Covenant v2.1), and GitHub issue
  templates.

### Added — OWASP breadth in the detection corpus (52 → 60 cases)

- **XXE (CWE-611)** in Java and PHP — `LANG-53`, `LANG-54` (eval#11).
- **Path traversal (CWE-22)** in Go and Java — `LANG-56`, `LANG-57` (eval#12).
- **SSRF (CWE-918)** in Go — `LANG-59` (eval#29), giving the class a second
  language alongside Python.
- Three SAFE decoys probing the precision distinctions these rules must make:
  default-safe PHP XML parsing (entities are off by default on PHP 8+), a constant
  filesystem path, and a **constant host with a user-supplied query string**
  (`LANG-55`, `LANG-58`, `LANG-60`).
- Two **pinned** real-repo cases — OWASP WebGoat (Java) and OWASP RailsGoat
  (Ruby), the first JVM/Ruby targets here; every prior case is Python or
  JavaScript (eval#13).

The `LANG-60` decoy earned its keep immediately: it caught a false positive in
signetry-core's new Go SSRF rule, fixed in Signetry/core#97 before this landed.

### Fixed — pinned real-repo cases were not actually pinned

- `scan_real_repo` cloned with `--depth 1` and then ran `git checkout <sha>` with
  `check=False`. On a shallow clone the object is absent, so the checkout failed
  (`fatal: unable to read tree`), the failure was swallowed, and the scan silently
  ran against the **default-branch tip** — a case documented as "pinned for
  reproducibility" was not pinned. Now fetches the specific object first, and if
  pinning genuinely cannot be honoured it says so in the result note rather than
  reporting an unpinned scan as pinned.

### Changed

- Pin `signetry-core` at `v0.7.0`; the corpus additions above depend on its new
  Go SSRF / Go+Java path-traversal / PHP XXE rules.

### Changed — Signetry rename (breaking)

- Distribution `signetry-eval` and import package `signetry_eval`. The console
  command is `signetry-eval`.
- Environment variables use `SIGNETRY_*`; the config directory is `.signetry/`.
  Product/brand prose updated to **Signetry**.
- Core dependency pinned: `signetry-core @ git+https://github.com/Signetry/core@v0.6.0`
  (was `signetry-core @ ...@v0.5.4`). Imports use `signetry_core`.
- No backward-compatibility fallbacks are provided.

## [0.2.2] — 2026-07-30

### Changed

- Install `signetry-core` from its **source repository** (`git+https://github.com/Signetry/core@v0.5.4`)
  instead of PyPI — signetry-core is All Rights Reserved and no longer distributed on
  PyPI. Enables `tool.hatch.metadata.allow-direct-references`.

## [0.2.1] — 2026-07-30

### Fixed

- Dependency floor raised to `signetry-core>=0.5.0` (was `0.3.0`) so a fresh install
  always has the detection engine (`scan_repository`) the corpus benchmark needs.

### Docs

- README now documents the **detection head-to-head benchmark** (52 cases, 7
  languages; signetry-core 100% recall / 0 false positives vs Claude Opus 4.8 90%),
  the `corpus` / `realrepo` commands, and the honest note that any false positive
  comes from the optional Semgrep layer, not the deterministic engine.

## [0.2.0] — 2026-07-30

### Added — head-to-head detection benchmark

- A public **detection benchmark**: a 52-case, 7-language corpus (Python,
  JavaScript, Go, Java, Ruby, PHP, C#) across six families — public/OWASP,
  academic/CWE, crafted, hard (cross-file taint, framework sinks, true-negative
  traps), multilang, and cross-file-lang — with cited provenance per case and safe
  decoys for false-positive measurement.
- `signetry-eval corpus` scores Signetry (live, via `signetry-core`) against competitor
  scanners (replayed from committed captures), reporting recall, false positives,
  and a by-language breakdown. `--min-recall` / `--max-fp` gate a regression;
  `--semgrep` enables the optional layer.
- `signetry-eval benchmark` (14-vuln fixture head-to-head) and `signetry-eval realrepo`
  (live scan of real vulnerable repos).
- Committed head-to-head result: signetry-core **100% recall / 0 false positives** vs
  claude-code-security-review (Claude Opus 4.8) 90% — deterministic, offline, free.

### CI

- The eval workflow runs the corpus head-to-head as a regression guard and adds a
  non-gating Semgrep-coverage job (informational artifact).

## [0.1.0] — 2026-07-26

- Initial adversarial evaluation suite: ASR (ungoverned vs governed) + utility-
  under-defense across IPI, skill/MCP poisoning, and memory-injection scenarios,
  run against the real `signetry-core` admission pipeline.
