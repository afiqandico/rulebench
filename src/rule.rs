//! Suricata rule parsing.
//!
//! Handles the shape real rulesets take: one rule per line, an optional
//! `#` prefix for disabled rules, and an option block where quoted strings
//! may contain `;` and `:` (so splitting has to be quote-aware).

use std::fmt;

pub const ACTIONS: [&str; 7] = [
    "alert",
    "drop",
    "pass",
    "reject",
    "rejectsrc",
    "rejectdst",
    "rejectboth",
];

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Action {
    Alert,
    Drop,
    Pass,
    Reject,
    Rejectsrc,
    Rejectdst,
    Rejectboth,
}

impl Action {
    pub fn parse(s: &str) -> Option<Action> {
        Some(match s {
            "alert" => Action::Alert,
            "drop" => Action::Drop,
            "pass" => Action::Pass,
            "reject" => Action::Reject,
            "rejectsrc" => Action::Rejectsrc,
            "rejectdst" => Action::Rejectdst,
            "rejectboth" => Action::Rejectboth,
            _ => return None,
        })
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Action::Alert => "alert",
            Action::Drop => "drop",
            Action::Pass => "pass",
            Action::Reject => "reject",
            Action::Rejectsrc => "rejectsrc",
            Action::Rejectdst => "rejectdst",
            Action::Rejectboth => "rejectboth",
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub source_file: String,
    pub line_no: usize,
    pub raw: String,
    /// True when the source line starts with `#` but still parses as a rule
    /// (the common "commented out" convention in ET/ET-Open rulesets).
    pub disabled: bool,
    pub action: Action,
    pub proto: String,
    pub src: String,
    pub sport: String,
    pub dir: String,
    pub dst: String,
    pub dport: String,
    pub sid: u64,
    pub rev: Option<u32>,
    pub msg: String,
    pub classtype: Option<String>,
    pub content_count: usize,
    pub has_reference: bool,
}

impl Rule {
    pub fn has_classtype(&self) -> bool {
        self.classtype.is_some()
    }
}

#[derive(Debug, Clone)]
pub struct InvalidRule {
    pub source_file: String,
    pub line_no: usize,
    pub reason: String,
    pub raw: String,
}

#[derive(Debug)]
pub enum ParseOutcome {
    Rule(Rule),
    /// Blank line or a plain comment.
    Skipped,
    Invalid(InvalidRule),
}

/// Split an option block (`msg:"a;b"; content:"x"; sid:1;`) on `;`,
/// ignoring separators inside double-quoted strings.
pub fn split_options(opts: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut escaped = false;

    for c in opts.chars() {
        if escaped {
            cur.push(c);
            escaped = false;
            continue;
        }
        match c {
            '\\' => {
                cur.push(c);
                escaped = true;
            }
            '"' => {
                in_quotes = !in_quotes;
                cur.push(c);
            }
            ';' if !in_quotes => out.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

/// Strip one layer of surrounding double quotes, if present.
pub fn unquote(s: &str) -> &str {
    let s = s.trim();
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

fn starts_with_action(s: &str) -> bool {
    s.split_whitespace()
        .next()
        .map(|t| ACTIONS.contains(&t))
        .unwrap_or(false)
}

pub fn parse_line(raw: &str, line_no: usize, source_file: &str) -> ParseOutcome {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return ParseOutcome::Skipped;
    }

    let (body, disabled) = match trimmed.strip_prefix('#') {
        Some(rest) => {
            let rest = rest.trim_start();
            if starts_with_action(rest) {
                (rest, true)
            } else {
                return ParseOutcome::Skipped;
            }
        }
        None => (trimmed, false),
    };

    if !starts_with_action(body) {
        return ParseOutcome::Skipped;
    }

    let invalid = |reason: String| {
        ParseOutcome::Invalid(InvalidRule {
            source_file: source_file.to_string(),
            line_no,
            reason,
            raw: trimmed.to_string(),
        })
    };

    let open = match body.find('(') {
        Some(i) => i,
        None => return invalid("missing '(' option block".to_string()),
    };
    let close = match body.rfind(')') {
        Some(i) if i > open => i,
        _ => return invalid("missing closing ')'".to_string()),
    };

    let header = body[..open].trim();
    let opts = &body[open + 1..close];

    let toks: Vec<&str> = header.split_whitespace().collect();
    if toks.len() != 7 {
        return invalid(format!(
            "header has {} fields, expected 7 (action proto src sport dir dst dport)",
            toks.len()
        ));
    }

    let action = match Action::parse(toks[0]) {
        Some(a) => a,
        None => return invalid(format!("unknown action '{}'", toks[0])),
    };

    let mut rule = Rule {
        source_file: source_file.to_string(),
        line_no,
        raw: trimmed.to_string(),
        disabled,
        action,
        proto: toks[1].to_string(),
        src: toks[2].to_string(),
        sport: toks[3].to_string(),
        dir: toks[4].to_string(),
        dst: toks[5].to_string(),
        dport: toks[6].to_string(),
        sid: 0,
        rev: None,
        msg: String::new(),
        classtype: None,
        content_count: 0,
        has_reference: false,
    };

    let (saw_sid, bad_sid, unbalanced) = apply_options(&mut rule, opts, false);

    if let Some(bad) = bad_sid {
        return invalid(format!("non-numeric sid '{bad}'"));
    }

    // Real-world rulesets (ET) contain values like pcre:"/^["']?post/Ri" where an
    // unescaped inner quote breaks strict quote tracking. When that happens (or
    // when the SID is lost) re-read the block quote-unaware and fill only the
    // fields the strict pass could not recover.
    if unbalanced || !saw_sid {
        let _ = apply_options(&mut rule, opts, true);
    }

    if rule.sid == 0 {
        match find_sid_loose(opts) {
            Some(sid) => rule.sid = sid,
            None => return invalid("missing sid".to_string()),
        }
    }

    ParseOutcome::Rule(rule)
}

/// Apply an option block to `rule`. In `loose` mode separators are split
/// without quote tracking and existing fields are never overwritten.
/// Returns `(saw_sid, bad_sid, quote_state_unbalanced)`.
fn apply_options(rule: &mut Rule, opts: &str, loose: bool) -> (bool, Option<String>, bool) {
    let tokens = if loose {
        split_options_loose(opts)
    } else {
        split_options(opts)
    };
    let unbalanced = !loose && quotes_unbalanced(opts);

    let mut saw_sid = false;
    let mut bad_sid: Option<String> = None;
    let mut contents = 0usize;

    for opt in tokens {
        let opt = opt.trim();
        if opt.is_empty() {
            continue;
        }
        let (key, value) = match opt.split_once(':') {
            Some((k, v)) => (k.trim().to_ascii_lowercase(), v.trim()),
            None => (opt.to_ascii_lowercase(), ""),
        };

        match key.as_str() {
            "sid" => {
                saw_sid = true;
                match value.parse::<u64>() {
                    Ok(v) => {
                        if rule.sid == 0 {
                            rule.sid = v;
                        }
                    }
                    Err(_) => bad_sid = Some(value.to_string()),
                }
            }
            "rev" => {
                if rule.rev.is_none() {
                    if let Ok(v) = value.parse::<u32>() {
                        rule.rev = Some(v);
                    }
                }
            }
            "msg" => {
                if rule.msg.is_empty() {
                    rule.msg = unquote(value).to_string();
                }
            }
            "classtype" => {
                if rule.classtype.is_none() {
                    rule.classtype = Some(value.to_string());
                }
            }
            "content" => contents += 1,
            "reference" => rule.has_reference = true,
            _ => {}
        }
    }

    rule.content_count = rule.content_count.max(contents);
    (saw_sid, bad_sid, unbalanced)
}

/// Split on `;` without regard for quoting (recovery mode only).
fn split_options_loose(opts: &str) -> Vec<String> {
    opts.split(';').map(|s| s.to_string()).collect()
}

/// True when the option block ends inside a double-quoted string.
fn quotes_unbalanced(opts: &str) -> bool {
    let mut in_quotes = false;
    let mut escaped = false;
    for c in opts.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' => escaped = true,
            '"' => in_quotes = !in_quotes,
            _ => {}
        }
    }
    in_quotes
}

/// Quote-unaware `sid:` scan, used only when strict parsing loses the SID.
pub fn find_sid_loose(opts: &str) -> Option<u64> {
    let bytes = opts.as_bytes();
    let mut from = 0usize;
    while let Some(pos) = opts[from..].find("sid:") {
        let at = from + pos;
        let boundary_ok = at == 0 || matches!(bytes[at - 1], b';' | b' ' | b'\t' | b'(');
        if boundary_ok {
            let digits: String = opts[at + 4..]
                .trim_start() // `sid: 123` boleh: jalur longgar harus toleran
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            if let Ok(v) = digits.parse::<u64>() {
                return Some(v);
            }
        }
        from = at + 4;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> ParseOutcome {
        parse_line(s, 1, "test.rules")
    }

    fn rule_of(s: &str) -> Rule {
        match parse(s) {
            ParseOutcome::Rule(r) => r,
            other => panic!("expected rule, got {other:?}"),
        }
    }

    #[test]
    fn parses_a_typical_rule() {
        let r = rule_of(
            r#"alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"ET POLICY outbound"; flow:established,to_server; content:"GET"; http_method; classtype:policy-violation; sid:2010935; rev:3;)"#,
        );
        assert_eq!(r.action, Action::Alert);
        assert_eq!(r.proto, "tcp");
        assert_eq!(r.src, "$HOME_NET");
        assert_eq!(r.dir, "->");
        assert_eq!(r.dport, "80");
        assert_eq!(r.sid, 2010935);
        assert_eq!(r.rev, Some(3));
        assert_eq!(r.msg, "ET POLICY outbound");
        assert_eq!(r.classtype.as_deref(), Some("policy-violation"));
        assert_eq!(r.content_count, 1);
        assert!(!r.disabled);
    }

    #[test]
    fn semicolons_inside_quotes_do_not_split_options() {
        let r = rule_of(
            r#"alert tcp any any -> any any (msg:"probe a;b"; content:"x;y"; sid:1; rev:2;)"#,
        );
        assert_eq!(r.msg, "probe a;b");
        assert_eq!(r.content_count, 1);
        assert_eq!(r.sid, 1);
        assert_eq!(r.rev, Some(2));
    }

    #[test]
    fn escaped_quotes_inside_content_are_kept() {
        let opts = split_options(r#"msg:"has \"quote\""; content:"a"; sid:7;"#);
        assert_eq!(opts.len(), 3);
        assert_eq!(opts[0].trim(), r#"msg:"has \"quote\"""#);
    }

    #[test]
    fn disabled_rule_is_parsed_and_flagged() {
        let r = rule_of(r#"# alert tcp any any -> any any (msg:"disabled one"; sid:9;)"#);
        assert!(r.disabled);
        assert_eq!(r.sid, 9);
    }

    #[test]
    fn plain_comments_and_blank_lines_are_skipped() {
        assert!(matches!(parse("   "), ParseOutcome::Skipped));
        assert!(matches!(
            parse("# a human-written note"),
            ParseOutcome::Skipped
        ));
        assert!(matches!(
            parse("# alert-ish but not a rule"),
            ParseOutcome::Skipped
        ));
    }

    #[test]
    fn missing_option_block_is_invalid() {
        match parse("alert tcp any any -> any any") {
            ParseOutcome::Invalid(i) => assert!(i.reason.contains("'('")),
            other => panic!("expected invalid, got {other:?}"),
        }
    }

    #[test]
    fn wrong_header_width_is_invalid() {
        match parse(r#"alert tcp any any (sid:1;)"#) {
            ParseOutcome::Invalid(i) => assert!(i.reason.contains("expected 7")),
            other => panic!("expected invalid, got {other:?}"),
        }
    }

    #[test]
    fn missing_sid_is_invalid() {
        match parse(r#"alert tcp any any -> any any (msg:"no sid";)"#) {
            ParseOutcome::Invalid(i) => assert_eq!(i.reason, "missing sid"),
            other => panic!("expected invalid, got {other:?}"),
        }
    }

    #[test]
    fn non_numeric_sid_is_invalid() {
        match parse(r#"alert tcp any any -> any any (sid:abc;)"#) {
            ParseOutcome::Invalid(i) => assert!(i.reason.contains("non-numeric sid")),
            other => panic!("expected invalid, got {other:?}"),
        }
    }

    #[test]
    fn direction_and_multiple_contents() {
        let r =
            rule_of(r#"drop udp any any <> any 53 (msg:"dns"; content:"a"; content:"b"; sid:3;)"#);
        assert_eq!(r.action, Action::Drop);
        assert_eq!(r.dir, "<>");
        assert_eq!(r.content_count, 2);
        assert_eq!(r.dport, "53");
    }

    #[test]
    fn unquote_handles_bare_values() {
        assert_eq!(unquote("classtype"), "classtype");
        assert_eq!(unquote(r#""quoted""#), "quoted");
    }

    #[test]
    fn recovers_sid_when_pcre_has_unescaped_quote() {
        // Shape taken verbatim from the ET/ET-Open ruleset (2029732).
        let r = rule_of(
            r#"alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET PHISHING Unhidebody"; flow:established,to_client; content:"function unhideBody()"; nocase; pcre:"/^["']?post/Ri"; classtype:social-engineering; sid:2029732; rev:2;)"#,
        );
        assert_eq!(r.sid, 2029732);
        assert_eq!(r.rev, Some(2));
        assert_eq!(r.classtype.as_deref(), Some("social-engineering"));
    }

    #[test]
    fn loose_sid_scan_requires_a_field_boundary() {
        assert_eq!(find_sid_loose(r#"msg:"sid:123"; content:"x";"#), None);
        assert_eq!(find_sid_loose(r#"msg:"a"; sid:42; rev:1;"#), Some(42));
        assert_eq!(find_sid_loose(r#"sid:7"#), Some(7));
    }
}
