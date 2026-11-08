//! Cross-referencing a ruleset with observed eve.json alerts.

use std::collections::{BTreeMap, BTreeSet};

use crate::eve::EveStats;
use crate::ruleset::RuleSet;

#[derive(Debug, Clone)]
pub struct DeadRule {
    pub sid: u64,
    pub msg: String,
    pub source_file: String,
    pub line_no: usize,
    pub classtype: Option<String>,
}

#[derive(Debug, Clone)]
pub struct FiredRule {
    pub sid: u64,
    pub signature: String,
    pub count: u64,
    pub severity: Option<u8>,
    pub unique_sources: usize,
}

#[derive(Debug, Clone)]
pub struct UnknownSid {
    pub sid: u64,
    pub signature: String,
    pub count: u64,
}

#[derive(Debug, Default)]
pub struct CoverageReport {
    pub rules_total: usize,
    pub rules_enabled: usize,
    pub rules_disabled: usize,
    pub events_total: u64,
    pub alerts_total: u64,
    pub parse_errors: u64,
    pub known_sids: usize,
    pub matched_rules: usize,
    /// Distinct SIDs that fired at all (independent of the `top` cap on `noisy`).
    pub firing_sids: usize,
    pub dead: Vec<DeadRule>,
    pub noisy: Vec<FiredRule>,
    pub unknown: Vec<UnknownSid>,
}

impl CoverageReport {
    pub fn dead_ratio(&self) -> f64 {
        if self.rules_enabled == 0 {
            0.0
        } else {
            self.dead.len() as f64 / self.rules_enabled as f64
        }
    }
}

/// `top` limits the noisy/unknown lists; the dead list is complete
/// (callers trim it for display).
pub fn analyze(rules: &RuleSet, eve: &EveStats, top: usize) -> CoverageReport {
    let mut all_sids: BTreeSet<u64> = BTreeSet::new();
    for r in &rules.rules {
        all_sids.insert(r.sid);
    }

    let mut dead = Vec::new();
    let mut matched_rules = 0usize;
    for r in rules.enabled() {
        let fired = eve.per_sid.get(&r.sid).map(|s| s.count).unwrap_or(0);
        if fired == 0 {
            dead.push(DeadRule {
                sid: r.sid,
                msg: r.msg.clone(),
                source_file: r.source_file.clone(),
                line_no: r.line_no,
                classtype: r.classtype.clone(),
            });
        } else {
            matched_rules += 1;
        }
    }
    dead.sort_by_key(|d| d.sid);

    let mut fired: Vec<FiredRule> = eve
        .per_sid
        .iter()
        .map(|(sid, s)| FiredRule {
            sid: *sid,
            signature: s.signature.clone(),
            count: s.count,
            severity: s.severity,
            unique_sources: s.sources.len(),
        })
        .collect();
    fired.sort_by(|a, b| b.count.cmp(&a.count).then(a.sid.cmp(&b.sid)));
    let noisy: Vec<FiredRule> = fired.iter().take(top).cloned().collect();

    let mut unknown: Vec<UnknownSid> = eve
        .per_sid
        .iter()
        .filter(|(sid, _)| !all_sids.contains(sid))
        .map(|(sid, s)| UnknownSid {
            sid: *sid,
            signature: s.signature.clone(),
            count: s.count,
        })
        .collect();
    unknown.sort_by(|a, b| b.count.cmp(&a.count).then(a.sid.cmp(&b.sid)));

    CoverageReport {
        rules_total: rules.rules.len(),
        rules_enabled: rules.enabled_count(),
        rules_disabled: rules.disabled_count(),
        events_total: eve.events,
        alerts_total: eve.alerts,
        parse_errors: eve.parse_errors,
        known_sids: all_sids.len(),
        matched_rules,
        firing_sids: eve.per_sid.len(),
        dead,
        noisy,
        unknown,
    }
}

/// Per-rule hit counts, useful for exporting a full table.
pub fn hit_counts(rules: &RuleSet, eve: &EveStats) -> BTreeMap<u64, u64> {
    rules
        .rules
        .iter()
        .map(|r| (r.sid, eve.per_sid.get(&r.sid).map(|s| s.count).unwrap_or(0)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eve::parse_eve_line;
    use crate::rule::{ParseOutcome, parse_line};

    fn ruleset(lines: &[&str]) -> RuleSet {
        let mut set = RuleSet::default();
        for (i, l) in lines.iter().enumerate() {
            if let ParseOutcome::Rule(r) = parse_line(l, i + 1, "mem.rules") {
                set.rules.push(r);
            }
        }
        set
    }

    fn eve(lines: &[&str]) -> EveStats {
        let mut s = EveStats::default();
        for l in lines {
            s.record(parse_eve_line(l).unwrap().unwrap());
        }
        s
    }

    fn alert(sid: u64, src: &str) -> String {
        format!(
            r#"{{"timestamp":"2026-11-08T10:00:00+0800","event_type":"alert","src_ip":"{src}","dest_ip":"10.0.0.1","alert":{{"signature_id":{sid},"signature":"sig {sid}","severity":2}}}}"#
        )
    }

    const R1: &str =
        r#"alert tcp any any -> any any (msg:"one"; classtype:attempted-recon; sid:1;)"#;
    const R2: &str =
        r#"alert tcp any any -> any any (msg:"two"; classtype:attempted-recon; sid:2;)"#;
    const R3: &str = r#"# alert tcp any any -> any any (msg:"three disabled"; classtype:attempted-recon; sid:3;)"#;

    #[test]
    fn identifies_dead_rules() {
        let rs = ruleset(&[R1, R2]);
        let ev = eve(&[&alert(1, "1.1.1.1")]);
        let rep = analyze(&rs, &ev, 10);
        assert_eq!(rep.matched_rules, 1);
        assert_eq!(rep.dead.len(), 1);
        assert_eq!(rep.dead[0].sid, 2);
        assert_eq!(rep.dead_ratio(), 0.5);
    }

    #[test]
    fn disabled_rules_are_not_dead_but_count_in_known_sids() {
        let rs = ruleset(&[R1, R3]);
        let ev = eve(&[&alert(1, "1.1.1.1")]);
        let rep = analyze(&rs, &ev, 10);
        assert_eq!(rep.rules_enabled, 1);
        assert_eq!(rep.rules_disabled, 1);
        assert!(rep.dead.is_empty());
        assert_eq!(rep.known_sids, 2);
    }

    #[test]
    fn alert_without_matching_rule_is_unknown() {
        let rs = ruleset(&[R1]);
        let ev = eve(&[&alert(1, "1.1.1.1"), &alert(999, "2.2.2.2")]);
        let rep = analyze(&rs, &ev, 10);
        assert_eq!(rep.unknown.len(), 1);
        assert_eq!(rep.unknown[0].sid, 999);
        assert_eq!(rep.alerts_total, 2);
    }

    #[test]
    fn noisy_list_is_sorted_by_count_and_capped() {
        let rs = ruleset(&[R1, R2]);
        let a2 = alert(2, "1.1.1.1");
        let ev = eve(&[&a2, &a2, &a2, &alert(1, "3.3.3.3")]);
        let rep = analyze(&rs, &ev, 1);
        assert_eq!(rep.noisy.len(), 1);
        assert_eq!(rep.noisy[0].sid, 2);
        assert_eq!(rep.noisy[0].count, 3);
        assert_eq!(rep.noisy[0].unique_sources, 1);
    }

    #[test]
    fn hit_counts_covers_every_rule() {
        let rs = ruleset(&[R1, R2]);
        let ev = eve(&[&alert(2, "1.1.1.1")]);
        let hits = hit_counts(&rs, &ev);
        assert_eq!(hits.get(&1), Some(&0));
        assert_eq!(hits.get(&2), Some(&1));
    }
}
