//! End-to-end checks against the fixtures that ship with the repo.

use std::path::PathBuf;

use rulebench::RuleSet;
use rulebench::coverage::analyze;
use rulebench::eve::read_eve;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(name)
}

#[test]
fn sample_ruleset_validates_as_expected() {
    let set = RuleSet::load(&[fixture("sample.rules")]).expect("load fixtures/sample.rules");

    assert_eq!(set.lines_read, 10);
    assert_eq!(set.rules.len(), 5);
    assert_eq!(set.enabled_count(), 4);
    assert_eq!(set.disabled_count(), 1);
    assert_eq!(set.invalid.len(), 1);
    assert!(set.invalid[0].raw.contains("without parens"));

    let dupes = set.duplicate_sids();
    assert_eq!(dupes.len(), 1);
    assert_eq!(dupes[0].sid, 2010935);

    let r = set
        .rules
        .iter()
        .find(|r| r.sid == 2010935 && !r.disabled)
        .expect("rule 2010935 present");
    assert_eq!(r.msg, "ET POLICY Possible External RDP Brute Force");
    assert_eq!(r.classtype.as_deref(), Some("attempted-admin"));
}

#[test]
fn sample_coverage_finds_dead_and_unknown_sids() {
    let set = RuleSet::load(&[fixture("sample.rules")]).unwrap();
    let eve = read_eve(&[fixture("sample-eve.jsonl")]).unwrap();
    let rep = analyze(&set, &eve, 10);

    assert_eq!(rep.events_total, 7);
    assert_eq!(rep.alerts_total, 5);
    assert_eq!(rep.parse_errors, 0);

    // Two rules share SID 2010935 in the fixture; both count as matched.
    assert_eq!(rep.matched_rules, 3);
    assert_eq!(rep.dead.len(), 1);
    assert_eq!(rep.dead[0].sid, 2024362);

    assert_eq!(rep.unknown.len(), 1);
    assert_eq!(rep.unknown[0].sid, 2055555);

    assert_eq!(rep.noisy[0].sid, 2010935);
    assert_eq!(rep.noisy[0].count, 3);
    assert_eq!(rep.noisy[0].unique_sources, 2);
}

/// Optional: run against a full ET/ET-Open ruleset when one is available locally.
#[test]
fn real_ruleset_parses_if_available() {
    let candidates = [
        "/home/afiq/Documents/04_Projects/Adversarial-ML-IDS-Validation/suricata_rules/suricata.rules",
        "/etc/suricata/rules/suricata.rules",
    ];
    let Some(path) = candidates.iter().map(PathBuf::from).find(|p| p.exists()) else {
        eprintln!("no real ruleset found, skipping");
        return;
    };

    let set = RuleSet::load(&[path]).expect("load real ruleset");
    assert!(set.rules.len() > 10_000, "expected a large ruleset");
    // Every parsed rule must carry a SID, enabled or disabled.
    assert!(set.rules.iter().all(|r| r.sid > 0));
}
