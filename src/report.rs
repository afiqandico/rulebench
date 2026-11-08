//! Text / JSON / Markdown rendering of check and coverage results.

use serde_json::{Value, json};

use crate::coverage::CoverageReport;
use crate::ruleset::RuleSet;

/// Group digits with commas: 68581 -> "68,581".
pub fn fmt_num(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

pub fn pct(part: usize, whole: usize) -> String {
    if whole == 0 {
        return "0.00%".to_string();
    }
    format!("{:.2}%", part as f64 * 100.0 / whole as f64)
}

pub fn check_text(set: &RuleSet, top: usize) -> String {
    let dupes = set.duplicate_sids();
    let conflicting = set.conflicting_disabled();
    let missing = set.missing_classtype();
    let mut out = String::new();

    out.push_str("rulebench check\n");
    out.push_str(&format!(
        "  files              : {}\n",
        fmt_num(set.files.len() as u64)
    ));
    out.push_str(&format!(
        "  lines read         : {}\n",
        fmt_num(set.lines_read as u64)
    ));
    out.push_str(&format!(
        "  rules parsed       : {} (enabled {} | disabled {})\n",
        fmt_num(set.rules.len() as u64),
        fmt_num(set.enabled_count() as u64),
        fmt_num(set.disabled_count() as u64)
    ));
    out.push_str(&format!(
        "  invalid lines      : {}\n",
        fmt_num(set.invalid.len() as u64)
    ));
    out.push_str(&format!(
        "  duplicate SIDs     : {}\n",
        fmt_num(dupes.len() as u64)
    ));
    out.push_str(&format!(
        "  enabled+disabled   : {}\n",
        fmt_num(conflicting.len() as u64)
    ));
    out.push_str(&format!(
        "  missing classtype  : {}\n",
        fmt_num(missing.len() as u64)
    ));

    if !set.invalid.is_empty() {
        out.push_str("\ninvalid lines:\n");
        for inv in set.invalid.iter().take(top) {
            out.push_str(&format!(
                "  {}:{}  {}\n        {}\n",
                inv.source_file,
                inv.line_no,
                inv.reason,
                truncate(&inv.raw, 140)
            ));
        }
        if set.invalid.len() > top {
            out.push_str(&format!(
                "  ... {} more\n",
                fmt_num((set.invalid.len() - top) as u64)
            ));
        }
    }

    if !dupes.is_empty() {
        out.push_str("\nduplicate SIDs:\n");
        for d in dupes.iter().take(top) {
            let places: Vec<String> = d
                .occurrences
                .iter()
                .map(|(f, l)| format!("{f}:{l}"))
                .collect();
            out.push_str(&format!(
                "  sid {:<10} x{}  {}\n",
                d.sid,
                d.occurrences.len(),
                places.join(", ")
            ));
        }
        if dupes.len() > top {
            out.push_str(&format!(
                "  ... {} more\n",
                fmt_num((dupes.len() - top) as u64)
            ));
        }
    }

    if !missing.is_empty() {
        out.push_str("\nmissing classtype (first few):\n");
        for r in missing.iter().take(top.min(5)) {
            out.push_str(&format!(
                "  sid {:<10} {}:{}  {}\n",
                r.sid, r.source_file, r.line_no, r.msg
            ));
        }
    }

    out
}

pub fn check_json(set: &RuleSet, top: usize) -> Value {
    let dupes = set.duplicate_sids();
    let conflicting = set.conflicting_disabled();
    json!({
        "files": set.files.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        "lines_read": set.lines_read,
        "rules_total": set.rules.len(),
        "rules_enabled": set.enabled_count(),
        "rules_disabled": set.disabled_count(),
        "invalid_lines": set.invalid.len(),
        "invalid": set.invalid.iter().take(top).map(|i| json!({
            "file": i.source_file,
            "line": i.line_no,
            "reason": i.reason,
            "raw": i.raw,
        })).collect::<Vec<_>>(),
        "duplicate_sids": dupes.iter().take(top).map(|d| json!({
            "sid": d.sid,
            "count": d.occurrences.len(),
            "locations": d.occurrences.iter().map(|(f,l)| format!("{f}:{l}")).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "duplicate_sid_count": dupes.len(),
        "conflicting_disabled_sids": conflicting,
        "missing_classtype_count": set.missing_classtype().len(),
    })
}

pub fn check_markdown(set: &RuleSet, top: usize) -> String {
    let dupes = set.duplicate_sids();
    let mut out = String::new();
    out.push_str("# rulebench check\n\n");
    out.push_str("| metric | value |\n|---|---|\n");
    out.push_str(&format!(
        "| files | {} |\n",
        fmt_num(set.files.len() as u64)
    ));
    out.push_str(&format!(
        "| lines read | {} |\n",
        fmt_num(set.lines_read as u64)
    ));
    out.push_str(&format!(
        "| rules parsed | {} |\n",
        fmt_num(set.rules.len() as u64)
    ));
    out.push_str(&format!(
        "| enabled | {} |\n",
        fmt_num(set.enabled_count() as u64)
    ));
    out.push_str(&format!(
        "| disabled | {} |\n",
        fmt_num(set.disabled_count() as u64)
    ));
    out.push_str(&format!(
        "| invalid lines | {} |\n",
        fmt_num(set.invalid.len() as u64)
    ));
    out.push_str(&format!(
        "| duplicate SIDs | {} |\n",
        fmt_num(dupes.len() as u64)
    ));
    out.push_str(&format!(
        "| enabled+disabled SIDs | {} |\n",
        fmt_num(set.conflicting_disabled().len() as u64)
    ));
    out.push_str(&format!(
        "| missing classtype | {} |\n",
        fmt_num(set.missing_classtype().len() as u64)
    ));

    if !dupes.is_empty() {
        out.push_str("\n## Duplicate SIDs\n\n| SID | occurrences | locations |\n|---|---|---|\n");
        for d in dupes.iter().take(top) {
            let places: Vec<String> = d
                .occurrences
                .iter()
                .map(|(f, l)| format!("{f}:{l}"))
                .collect();
            out.push_str(&format!(
                "| {} | {} | {} |\n",
                d.sid,
                d.occurrences.len(),
                places.join("<br>")
            ));
        }
    }
    if !set.invalid.is_empty() {
        out.push_str("\n## Invalid lines\n\n| file:line | reason |\n|---|---|\n");
        for inv in set.invalid.iter().take(top) {
            out.push_str(&format!(
                "| {}:{} | {} |\n",
                inv.source_file, inv.line_no, inv.reason
            ));
        }
    }
    out
}

pub fn coverage_text(rep: &CoverageReport, top: usize) -> String {
    let mut out = String::new();
    out.push_str("rulebench coverage\n");
    out.push_str(&format!(
        "  rules              : {} (enabled {} | disabled {})\n",
        fmt_num(rep.rules_total as u64),
        fmt_num(rep.rules_enabled as u64),
        fmt_num(rep.rules_disabled as u64)
    ));
    out.push_str(&format!(
        "  eve events / alerts: {} / {}\n",
        fmt_num(rep.events_total),
        fmt_num(rep.alerts_total)
    ));
    if rep.parse_errors > 0 {
        out.push_str(&format!(
            "  eve parse errors   : {}\n",
            fmt_num(rep.parse_errors)
        ));
    }
    out.push_str(&format!(
        "  unique SIDs fired  : {} of {} rules in set ({} of enabled rules matched)\n",
        fmt_num(rep.firing_sids as u64),
        fmt_num(rep.known_sids as u64),
        pct(rep.matched_rules, rep.rules_enabled)
    ));
    out.push_str(&format!(
        "  dead rules         : {} ({} of enabled)\n",
        fmt_num(rep.dead.len() as u64),
        pct(rep.dead.len(), rep.rules_enabled)
    ));

    if !rep.noisy.is_empty() {
        out.push_str("\ntop firing signatures:\n");
        for f in rep.noisy.iter().take(top) {
            out.push_str(&format!(
                "  sid {:<10} {:>8} alerts  {:>4} srcs  sev {}  {}\n",
                f.sid,
                fmt_num(f.count),
                f.unique_sources,
                f.severity
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "-".into()),
                truncate(&f.signature, 70)
            ));
        }
    }

    if !rep.unknown.is_empty() {
        out.push_str("\nalerts with no matching rule (stale ruleset?):\n");
        for u in rep.unknown.iter().take(top) {
            out.push_str(&format!(
                "  sid {:<10} {:>8} alerts  {}\n",
                u.sid,
                fmt_num(u.count),
                truncate(&u.signature, 70)
            ));
        }
    }

    if !rep.dead.is_empty() {
        out.push_str("\ndead rules (first few, sorted by SID):\n");
        for d in rep.dead.iter().take(top) {
            out.push_str(&format!(
                "  sid {:<10} {}  {}\n",
                d.sid,
                truncate(&d.msg, 60),
                d.classtype.as_deref().unwrap_or("-")
            ));
        }
    }
    out
}

pub fn coverage_json(rep: &CoverageReport) -> Value {
    json!({
        "rules_total": rep.rules_total,
        "rules_enabled": rep.rules_enabled,
        "rules_disabled": rep.rules_disabled,
        "known_sids": rep.known_sids,
        "eve_events": rep.events_total,
        "eve_alerts": rep.alerts_total,
        "eve_parse_errors": rep.parse_errors,
        "matched_rules": rep.matched_rules,
        "dead_rules": rep.dead.len(),
        "dead_ratio": rep.dead_ratio(),
        "firing": rep.noisy.iter().map(|f| json!({
            "sid": f.sid,
            "signature": f.signature,
            "count": f.count,
            "severity": f.severity,
            "unique_sources": f.unique_sources,
        })).collect::<Vec<_>>(),
        "unknown": rep.unknown.iter().map(|u| json!({
            "sid": u.sid,
            "signature": u.signature,
            "count": u.count,
        })).collect::<Vec<_>>(),
        "dead": rep.dead.iter().map(|d| json!({
            "sid": d.sid,
            "msg": d.msg,
            "file": d.source_file,
            "line": d.line_no,
            "classtype": d.classtype,
        })).collect::<Vec<_>>(),
    })
}

pub fn coverage_markdown(rep: &CoverageReport, top: usize) -> String {
    let mut out = String::new();
    out.push_str("# rulebench coverage\n\n| metric | value |\n|---|---|\n");
    out.push_str(&format!(
        "| rules total | {} |\n",
        fmt_num(rep.rules_total as u64)
    ));
    out.push_str(&format!(
        "| enabled | {} |\n",
        fmt_num(rep.rules_enabled as u64)
    ));
    out.push_str(&format!(
        "| disabled | {} |\n",
        fmt_num(rep.rules_disabled as u64)
    ));
    out.push_str(&format!("| eve alerts | {} |\n", fmt_num(rep.alerts_total)));
    out.push_str(&format!(
        "| matched rules | {} |\n",
        fmt_num(rep.matched_rules as u64)
    ));
    out.push_str(&format!(
        "| dead rules | {} ({}) |\n",
        fmt_num(rep.dead.len() as u64),
        pct(rep.dead.len(), rep.rules_enabled)
    ));
    out.push_str(&format!(
        "| unknown SIDs | {} |\n",
        fmt_num(rep.unknown.len() as u64)
    ));

    if !rep.noisy.is_empty() {
        out.push_str("\n## Top firing signatures\n\n| SID | alerts | unique srcs | severity | signature |\n|---|---|---|---|---|\n");
        for f in rep.noisy.iter().take(top) {
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                f.sid,
                f.count,
                f.unique_sources,
                f.severity
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "-".into()),
                f.signature.replace('|', "\\|")
            ));
        }
    }
    if !rep.unknown.is_empty() {
        out.push_str("\n## Unknown SIDs\n\n| SID | alerts | signature |\n|---|---|---|\n");
        for u in rep.unknown.iter().take(top) {
            out.push_str(&format!(
                "| {} | {} | {} |\n",
                u.sid,
                u.count,
                u.signature.replace('|', "\\|")
            ));
        }
    }
    out
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_get_thousands_separators() {
        assert_eq!(fmt_num(0), "0");
        assert_eq!(fmt_num(999), "999");
        assert_eq!(fmt_num(1000), "1,000");
        assert_eq!(fmt_num(68581), "68,581");
        assert_eq!(fmt_num(1234567), "1,234,567");
    }

    #[test]
    fn percentages_are_two_decimals() {
        assert_eq!(pct(1, 4), "25.00%");
        assert_eq!(pct(0, 0), "0.00%");
    }

    #[test]
    fn truncate_keeps_short_strings() {
        assert_eq!(truncate("abc", 10), "abc");
        assert_eq!(truncate("abcdef", 4).chars().count(), 4);
    }
}
