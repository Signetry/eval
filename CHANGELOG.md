# Changelog — umbra-eval

Follows [Keep a Changelog](https://keepachangelog.com/) / [SemVer](https://semver.org/).
Until `1.0.0` the public API may change between minor versions.

## [0.2.2] — 2026-07-30

### Changed

- Install `umbra-core` from its **source repository** (`git+https://github.com/Signetry/core@v0.5.4`)
  instead of PyPI — umbra-core is All Rights Reserved and no longer distributed on
  PyPI. Enables `tool.hatch.metadata.allow-direct-references`.

## [0.2.1] — 2026-07-30

### Fixed

- Dependency floor raised to `umbra-core>=0.5.0` (was `0.3.0`) so a fresh install
  always has the detection engine (`scan_repository`) the corpus benchmark needs.

### Docs

- README now documents the **detection head-to-head benchmark** (52 cases, 7
  languages; umbra-core 100% recall / 0 false positives vs Claude Opus 4.8 90%),
  the `corpus` / `realrepo` commands, and the honest note that any false positive
  comes from the optional Semgrep layer, not the deterministic engine.

## [0.2.0] — 2026-07-30

### Added — head-to-head detection benchmark

- A public **detection benchmark**: a 52-case, 7-language corpus (Python,
  JavaScript, Go, Java, Ruby, PHP, C#) across six families — public/OWASP,
  academic/CWE, crafted, hard (cross-file taint, framework sinks, true-negative
  traps), multilang, and cross-file-lang — with cited provenance per case and safe
  decoys for false-positive measurement.
- `umbra-eval corpus` scores Umbra (live, via `umbra-core`) against competitor
  scanners (replayed from committed captures), reporting recall, false positives,
  and a by-language breakdown. `--min-recall` / `--max-fp` gate a regression;
  `--semgrep` enables the optional layer.
- `umbra-eval benchmark` (14-vuln fixture head-to-head) and `umbra-eval realrepo`
  (live scan of real vulnerable repos).
- Committed head-to-head result: umbra-core **100% recall / 0 false positives** vs
  claude-code-security-review (Claude Opus 4.8) 90% — deterministic, offline, free.

### CI

- The eval workflow runs the corpus head-to-head as a regression guard and adds a
  non-gating Semgrep-coverage job (informational artifact).

## [0.1.0] — 2026-07-26

- Initial adversarial evaluation suite: ASR (ungoverned vs governed) + utility-
  under-defense across IPI, skill/MCP poisoning, and memory-injection scenarios,
  run against the real `umbra-core` admission pipeline.
