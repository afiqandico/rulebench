# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/). The authoritative version string is
`Cargo.toml` and `CITATION.cff` — both must agree.

## [Unreleased]

### Added

- `tests/rule_parsing.rs` — 10 unit tests for the parsing layer (`parse_line`,
  `split_options`, `unquote`, `find_sid_loose`, `Action`). That layer had only
  been exercised indirectly through two fixture files.
- `tests/render_contracts.rs` — 9 contract tests for the renderers consumed by CI
  and downstream scripts: required JSON keys for `check`/`coverage`, internal
  consistency (`rules_total == enabled + disabled`, `dead_ratio == dead/enabled`,
  duplicate count == listed duplicates), text-vs-JSON agreement, Markdown
  heading + table shape, and the `--top` cap semantics.

### Fixed

- `find_sid_loose` accepts a space after the colon (`sid: 123`). That branch only
  runs when the strict pass fails to find a SID, so the tolerance changes nothing
  for valid rulesets — it closes the gap for hand-written rules with loose spacing.
- `coverage --top N` now caps the `unknown` list as well. The doc comment and the
  text renderer both said the cap applied to noisy *and* unknown, but `analyze`
  returned every unknown SID, so `--top 1 --json` disagreed with `--top 1` text.
  Counts (`matched_rules`, `firing_sids`, `dead_rules`) stay independent of `top`;
  only the lists are capped. Dead rules are never capped, on purpose.

### Changed

- `CITATION.cff` added so the artefact can be cited (CFF 1.2.0).
- `Cargo.toml` gains `authors` and `homepage`; `cargo install --path .` is verified
  to produce a working binary (`rulebench --version`, `--help`, fixture run).
- CI runs on push to `master`/`main`, on pull requests, and via `workflow_dispatch`.

## [0.1.0] — 2026-11-08

First release. The two questions an analyst actually asks of a ruleset, one
subcommand each.

### Added

- `rulebench check` — internal ruleset validation: 7-field header, numeric
  `sid`/`rev`, duplicate SIDs, unknown `classtype`, disabled (`#`) rules.
- `rulebench coverage` — cross-references a ruleset against `eve.json`: dead rules
  (never fired), unknown SIDs, and the dead-rule ratio.
- Text and JSON reports (`report`), including the top-N noisiest rules.
- `eve.json`/`eve.json.*` reader tolerant of malformed lines (`eve::read_eve`).
- Quote-aware option splitting, so `msg:"a;b"` does not break the option block.
- 3 CLI integration tests over the fixture ruleset and sample `eve.json`.

[Unreleased]: https://github.com/afiqandico/rulebench/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/afiqandico/rulebench/releases/tag/v0.1.0
