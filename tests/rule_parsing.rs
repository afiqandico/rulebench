//! Unit tests for the parsing layer (`src/rule.rs`).
//!
//! Every subcommand in this crate goes through `parse_line`, but before this
//! file it had no direct test: the existing `cli_integration.rs` only exercises
//! it indirectly through two fixture files. These cases pin the behaviour that
//! real ET/ET-Open rulesets rely on (disabled `#` rules, quote-aware option
//! splitting, loose SID recovery) plus the exact rejection reasons.

use rulebench::rule::{
    find_sid_loose, parse_line, split_options, unquote, Action, ParseOutcome, Rule, ACTIONS,
};

const SRC: &str = "unit-test.rules";

const REAL_RULE: &str = r#"alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"ET POLICY Test"; \
flow:established,to_server; content:"GET"; http_method; classtype:attempted-recon; sid:2000001; rev:3;)"#;

fn as_rule(raw: &str) -> Rule {
    match parse_line(raw, 7, SRC) {
        ParseOutcome::Rule(r) => r,
        other => panic!("harus menjadi Rule, dapat {other:?}"),
    }
}

fn as_invalid(raw: &str) -> String {
    match parse_line(raw, 7, SRC) {
        ParseOutcome::Invalid(i) => i.reason,
        other => panic!("harus menjadi Invalid, dapat {other:?}"),
    }
}

#[test]
fn action_roundtrip_is_exact_and_case_sensitive() {
    for name in ACTIONS {
        let parsed = Action::parse(name).unwrap_or_else(|| panic!("'{name}' harus dikenali"));
        assert_eq!(parsed.as_str(), name, "roundtrip untuk '{name}'");
        assert_eq!(parsed.to_string(), name);
    }
    assert!(Action::parse("Alert").is_none(), "parse bersifat case-sensitive");
    assert!(Action::parse("dropz").is_none());
    assert!(Action::parse("").is_none());
}

#[test]
fn valid_rule_fills_every_header_field() {
    let r = as_rule(REAL_RULE);
    assert_eq!(r.source_file, SRC);
    assert_eq!(r.line_no, 7);
    assert!(!r.disabled);
    assert_eq!(r.action, Action::Alert);
    assert_eq!((r.proto.as_str(), r.src.as_str()), ("tcp", "$HOME_NET"));
    assert_eq!((r.sport.as_str(), r.dir.as_str()), ("any", "->"));
    assert_eq!((r.dst.as_str(), r.dport.as_str()), ("$EXTERNAL_NET", "80"));
    assert_eq!(r.sid, 2_000_001);
    assert_eq!(r.rev, Some(3));
    assert_eq!(r.msg, "ET POLICY Test");
    assert_eq!(r.classtype.as_deref(), Some("attempted-recon"));
    assert!(r.has_classtype());
    assert_eq!(r.content_count, 1);
}

#[test]
fn commented_rule_is_kept_marked_disabled() {
    let r = as_rule(&format!("#{REAL_RULE}"));
    assert!(r.disabled, "baris '#' berisi rule = rule nonaktif, bukan komentar biasa");
    assert_eq!(r.sid, 2_000_001);
    assert!(r.raw.starts_with('#'));
}

#[test]
fn blank_and_plain_comment_lines_are_skipped() {
    for line in ["", "   ", "\t", "# catatan biasa tanpa rule", "#  ", "#alert-note"] {
        assert!(
            matches!(parse_line(line, 1, SRC), ParseOutcome::Skipped),
            "baris {line:?} seharusnya Skipped"
        );
    }
}

#[test]
fn missing_option_block_is_rejected_with_reason() {
    let reason = as_invalid("alert tcp any any -> any 80");
    assert!(reason.contains("missing '('"), "alasan: {reason}");
}

#[test]
fn wrong_header_width_is_rejected_and_reports_count() {
    let reason = as_invalid("alert tcp any -> any 80 (sid:1;)");
    assert!(reason.contains("header has 6 fields"), "alasan: {reason}");
    assert!(reason.contains("expected 7"), "alasan: {reason}");
}

#[test]
fn non_numeric_sid_is_rejected() {
    let reason = as_invalid("alert tcp any any -> any 80 (sid:abc;)");
    assert!(reason.contains("non-numeric sid"), "alasan: {reason}");
    assert!(reason.contains("abc"), "alasan harus menyebut nilainya: {reason}");
}

#[test]
fn split_options_ignores_semicolons_inside_quotes() {
    let opts = r#"msg:"a;b:c"; content:"|3b|"; sid:42;"#;
    let parts = split_options(opts);
    assert_eq!(parts.len(), 3, "dapat {parts:?}");
    assert!(parts[0].contains("a;b:c"), "semicolon dalam kutip tidak boleh memecah: {parts:?}");
    assert_eq!(parts[2].trim(), "sid:42");
}

#[test]
fn unquote_strips_one_layer_and_trims() {
    assert_eq!(unquote(r#"  "abc"  "#), "abc");
    assert_eq!(unquote("abc"), "abc");
    assert_eq!(unquote(r#""a"b""#), r#"a"b"#);
    assert_eq!(unquote("\""), "\"", "satu kutip bukan pasangan");
}

#[test]
fn find_sid_loose_recovers_sid_from_messy_option_block() {
    assert_eq!(find_sid_loose("msg:\"x\"; sid:12345; rev:2;"), Some(12_345));
    assert_eq!(find_sid_loose("sid: 777 ;"), Some(777));
    assert_eq!(find_sid_loose("msg:\"tanpa sid\";"), None);
    assert_eq!(find_sid_loose(""), None);
}
