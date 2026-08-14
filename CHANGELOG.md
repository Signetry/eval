# Changelog — signetry-eval

Follows [Keep a Changelog](https://keepachangelog.com/) / [SemVer](https://semver.org/).
Until `1.0.0` the public API may change between minor versions.

## [Unreleased]

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
