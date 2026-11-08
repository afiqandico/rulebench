# rulebench

**Suricata rule validator and alert-coverage analyzer.** Two questions an analyst
actually asks about a ruleset — *is it internally consistent?* and *is it earning
its keep?* — answered by a single static binary.

`suricata -T` validates that rules load. It does not tell you which rules are
dead, which SIDs collide, or which alerts fire for signatures that no longer
exist in your ruleset. `rulebench` does, without a daemon, a config file, or a
running Suricata instance.

```
$ rulebench check /etc/suricata/rules
rulebench check
  files              : 1
  lines read         : 68,581
  rules parsed       : 68,581 (enabled 52,631 | disabled 15,950)
  invalid lines      : 0
  duplicate SIDs     : 0
  enabled+disabled   : 0
  missing classtype  : 1

$ rulebench coverage --rules /etc/suricata/rules --eve /var/log/suricata/eve.json
rulebench coverage
  rules              : 5 (enabled 4 | disabled 1)
  eve events / alerts: 7 / 5
  unique SIDs fired  : 3 of 4 rules in set (75.00% of enabled rules matched)
  dead rules         : 1 (25.00% of enabled)

top firing signatures:
  sid 2010935           3 alerts     2 srcs  sev 2  ET POLICY Possible External RDP Brute Force
  sid 2027757           1 alerts     1 srcs  sev 3  ET DNS Query to a .top domain

alerts with no matching rule (stale ruleset?):
  sid 2055555           1 alerts  ET CUSTOM rule that no longer exists in the ruleset

dead rules (first few, sorted by SID):
  sid 2024362    ET SCAN Nikto Scan Detected  web-application-attack
```

## Install

```bash
cargo install --path .          # from a clone
cargo build --release           # or: ./target/release/rulebench
```

Dependencies: `clap`, `serde`, `serde_json`. Nothing else.

## Usage

### `check` — internal consistency

```bash
rulebench check path/to/rules [more paths...]
```

Accepts files *or* directories (directories are walked recursively for `*.rules`).
Reports:

| Finding | Meaning |
|---|---|
| invalid lines | line looks like a rule but cannot be parsed (no option block, wrong header width, missing/non-numeric `sid`) |
| duplicate SIDs | the same SID defined more than once, with every `file:line` |
| enabled + disabled | a SID that exists both active and commented out — usually a stale local edit |
| missing classtype | enabled rules without a `classtype` keyword |

Flags: `--json`, `--md`, `--top N`, `--strict`.
Exit codes: `0` clean, `1` invalid lines (or warnings under `--strict`), `2` I/O or usage error.

### `coverage` — ruleset vs. observed alerts

```bash
rulebench coverage --rules rules/ --eve /var/log/suricata/eve.json
```

Reads Suricata EVE JSON (one object per line; non-alert events are counted but
not attributed). Reports:

- **dead rules** — enabled rules that produced zero alerts in the window;
- **top firing signatures** — by alert count, with unique source IPs;
- **unknown SIDs** — alerts whose `signature_id` is absent from the ruleset
  (stale ruleset, or rules removed upstream while Suricata kept the old SID).

Flags: `--json`, `--md`, `--top N`. Multiple `--rules` and `--eve` arguments are
accepted and merged.

### JSON output

Both subcommands emit stable, machine-readable JSON under `--json`, suitable for
CI gates or further aggregation:

```bash
rulebench check rules/ --json | jq '.duplicate_sid_count, .invalid_lines'
```

## Real-world parsing notes

Rulesets from ET/ET-Open are not as tidy as the grammar suggests, so the parser
has two honest concessions:

1. **Quote-aware splitting.** Option values may contain `;` and `:`
   (`msg:"a;b"`), so the block is split with a quote and escape tracker rather
   than `split(';')`.
2. **SID recovery.** Some published rules contain an unescaped inner quote, e.g.
   `pcre:"/^["']?post/Ri"` (SID 2029732 in ET-Open). Strict quote tracking then
   swallows the rest of the block. When the quote state ends unbalanced — or the
   SID is missing — the block is re-read quote-unaware and only the unrecovered
   fields are filled in. A rule is reported invalid only if no `sid:` token
   exists at a field boundary.

Verified against a 68,581-line ET ruleset: 68,581 rules parsed, 0 invalid lines,
1 rule genuinely missing `classtype` (SID 2210059, a Suricata stream rule).

Measured on this machine (release build, `lto` on):

| run | input | time | peak RSS |
|---|---|---|---|
| `check` | 68,581 rules | 0.57 s | ~140 MB |
| `coverage` | 68,581 rules + 1,000,000 eve events (187 MB, synthetic) | 0.94 s | ~140 MB |

## What it does *not* do

This is a static, offline analyzer — not a replacement for Suricata's own parser:

- no full grammar/semantic validation (flowbits, byte_extract, protocol keywords,
  PCRE compilation);
- no `include`/variable resolution, so `$HOME_NET` and friends are reported as text;
- no multi-line rule support (Suricata rules are single-line in practice);
- `coverage` reflects only the eve.json window you pass it — a rule that is silent
  because the traffic never occurred is indistinguishable from a dead rule. Treat
  the dead list as a triage queue, not a delete list.

## Development

```bash
cargo test        # 35 tests: parser edge cases, aggregation, fixtures, real ruleset if present
cargo clippy --all-targets
cargo fmt --check
```

Fixtures live in `fixtures/`: `sample.rules` (includes a duplicate SID, a disabled
rule, and a malformed line) and `sample-eve.jsonl` (alerts, a flow event, a stats
line, and one alert with no matching rule).

## License

MIT — see [LICENSE](LICENSE).
