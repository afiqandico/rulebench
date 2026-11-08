//! Render contracts: the JSON/Markdown/plain-text outputs are what CI, README
//! examples and downstream scripts consume, so their shape is pinned here.
//!
//! These are invariants, not golden files: a number may change, but the three
//! renderings must never disagree with each other or with the underlying report.

use std::path::PathBuf;

use rulebench::RuleSet;
use rulebench::coverage::analyze;
use rulebench::eve::read_eve;
use rulebench::report::{
    check_json, check_markdown, check_text, coverage_json, coverage_markdown, coverage_text,
    fmt_num, pct,
};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(name)
}

fn load() -> (RuleSet, rulebench::coverage::CoverageReport) {
    let set = RuleSet::load(&[fixture("sample.rules")]).expect("load sample.rules");
    let eve = read_eve(&[fixture("sample-eve.jsonl")]).expect("load sample-eve.jsonl");
    let rep = analyze(&set, &eve, 10);
    (set, rep)
}

#[test]
fn check_json_exposes_the_documented_keys() {
    let (set, _) = load();
    let v = check_json(&set, 10);
    for key in [
        "files",
        "lines_read",
        "rules_total",
        "rules_enabled",
        "rules_disabled",
        "invalid_lines",
        "invalid",
        "duplicate_sid_count",
        "duplicate_sids",
        "missing_classtype_count",
        "conflicting_disabled_sids",
    ] {
        assert!(v.get(key).is_some(), "check json is missing key {key}");
    }
}

#[test]
fn check_json_counts_are_internally_consistent() {
    let (set, _) = load();
    let v = check_json(&set, 10);
    let total = v["rules_total"].as_u64().unwrap();
    let enabled = v["rules_enabled"].as_u64().unwrap();
    let disabled = v["rules_disabled"].as_u64().unwrap();
    assert_eq!(total, enabled + disabled, "enabled + disabled must equal total");
    assert_eq!(
        v["duplicate_sid_count"].as_u64().unwrap() as usize,
        v["duplicate_sids"].as_array().unwrap().len(),
        "the duplicate count must match the listed duplicates"
    );
}

#[test]
fn check_text_agrees_with_the_json_numbers() {
    let (set, _) = load();
    let v = check_json(&set, 10);
    let text = check_text(&set, 10);
    let expected = format!(
        "rules parsed       : {} (enabled {} | disabled {})",
        v["rules_total"], v["rules_enabled"], v["rules_disabled"]
    );
    assert!(text.contains(&expected), "text rendering drifted:\n{text}");
    assert!(text.contains(&format!("lines read         : {}", v["lines_read"])));
}

#[test]
fn coverage_json_exposes_the_documented_keys() {
    let (_, rep) = load();
    let v = coverage_json(&rep);
    for key in [
        "rules_total",
        "rules_enabled",
        "rules_disabled",
        "eve_events",
        "eve_alerts",
        "eve_parse_errors",
        "known_sids",
        "matched_rules",
        "dead_rules",
        "dead_ratio",
        "firing",
        "dead",
        "unknown",
    ] {
        assert!(v.get(key).is_some(), "coverage json is missing key {key}");
    }
}

#[test]
fn coverage_json_ratio_matches_its_own_lists() {
    let (_, rep) = load();
    let v = coverage_json(&rep);
    let dead = v["dead_rules"].as_u64().unwrap() as f64;
    let enabled = v["rules_enabled"].as_u64().unwrap() as f64;
    let ratio = v["dead_ratio"].as_f64().unwrap();
    assert!(enabled > 0.0, "fixture must have enabled rules");
    assert!(
        (ratio - dead / enabled).abs() < 1e-9,
        "dead_ratio {ratio} != dead_rules/enabled_rules {}",
        dead / enabled
    );
    assert_eq!(v["dead"].as_array().unwrap().len(), dead as usize);
}

#[test]
fn coverage_text_reports_the_same_dead_ratio() {
    let (_, rep) = load();
    let text = coverage_text(&rep, 10);
    let expected = format!("{} ({:.2}% of enabled)", rep.dead.len(), rep.dead_ratio() * 100.0);
    assert!(text.contains(&expected), "text rendering drifted:\n{text}");
    assert!(text.contains(&format!("{} / {}", rep.events_total, rep.alerts_total)));
}

#[test]
fn both_markdown_renderings_start_with_a_heading_and_a_table() {
    let (set, rep) = load();
    let check = check_markdown(&set, 10);
    let coverage = coverage_markdown(&rep, 10);
    for (name, md) in [("check", check), ("coverage", coverage)] {
        let mut lines = md.lines();
        assert!(
            lines.next().unwrap_or("").starts_with("# rulebench "),
            "{name} markdown must start with a level-1 heading"
        );
        assert!(md.contains("| metric | value |"), "{name} markdown lost its metric table");
        assert!(
            md.lines().filter(|l| l.starts_with("| ")).count() >= 3,
            "{name} markdown table has fewer rows than expected"
        );
    }
}

#[test]
fn top_zero_empties_the_capped_lists_but_keeps_the_totals() {
    let set = RuleSet::load(&[fixture("sample.rules")]).unwrap();
    let eve = read_eve(&[fixture("sample-eve.jsonl")]).unwrap();
    let capped = analyze(&set, &eve, 0);
    let full = analyze(&set, &eve, 10);

    assert!(capped.noisy.is_empty(), "top=0 must not list firing signatures");
    assert!(capped.unknown.is_empty(), "top=0 must not list unknown SIDs");
    // The counts are independent of `top`; only the lists are capped.
    assert_eq!(capped.firing_sids, full.firing_sids);
    assert_eq!(capped.matched_rules, full.matched_rules);
    assert_eq!(capped.dead.len(), full.dead.len(), "the dead list is never capped");
}

#[test]
fn number_helpers_handle_their_edges() {
    assert_eq!(fmt_num(0), "0");
    assert_eq!(fmt_num(999), "999");
    assert_eq!(fmt_num(1_000), "1,000");
    assert_eq!(fmt_num(68_581), "68,581");
    assert_eq!(pct(0, 0), "0.00%", "division by zero must not print NaN");
    assert_eq!(pct(1, 4), "25.00%");
    assert_eq!(pct(3, 3), "100.00%");
}
