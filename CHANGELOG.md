# Changelog — signetry-eval

Follows [Keep a Changelog](https://keepachangelog.com/) / [SemVer](https://semver.org/).
Until `1.0.0` the public API may change between minor versions.

## [Unreleased]

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
