//! Loading rule files/directories and cross-rule validation.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::rule::{InvalidRule, ParseOutcome, Rule, parse_line};

#[derive(Debug, Default)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
    pub invalid: Vec<InvalidRule>,
    pub files: Vec<PathBuf>,
    pub lines_read: usize,
}

#[derive(Debug, Clone)]
pub struct DuplicateSid {
    pub sid: u64,
    pub occurrences: Vec<(String, usize)>,
}

impl RuleSet {
    pub fn load(paths: &[PathBuf]) -> io::Result<RuleSet> {
        let files = collect_rule_files(paths)?;
        let mut set = RuleSet {
            files: files.clone(),
            ..RuleSet::default()
        };
        for file in &files {
            set.load_file(file)?;
        }
        Ok(set)
    }

    pub fn load_file(&mut self, path: &Path) -> io::Result<()> {
        let content = fs::read_to_string(path)?;
        let display = path.display().to_string();
        for (idx, line) in content.lines().enumerate() {
            self.lines_read += 1;
            match parse_line(line, idx + 1, &display) {
                ParseOutcome::Rule(r) => self.rules.push(r),
                ParseOutcome::Invalid(i) => self.invalid.push(i),
                ParseOutcome::Skipped => {}
            }
        }
        Ok(())
    }

    pub fn enabled(&self) -> impl Iterator<Item = &Rule> {
        self.rules.iter().filter(|r| !r.disabled)
    }

    pub fn enabled_count(&self) -> usize {
        self.enabled().count()
    }

    pub fn disabled_count(&self) -> usize {
        self.rules.len() - self.enabled_count()
    }

    /// Rules present in the set but without a `classtype` keyword.
    pub fn missing_classtype(&self) -> Vec<&Rule> {
        self.enabled().filter(|r| !r.has_classtype()).collect()
    }

    /// Same SID appearing more than once (across files or within one file).
    pub fn duplicate_sids(&self) -> Vec<DuplicateSid> {
        let mut seen: BTreeMap<u64, Vec<(String, usize)>> = BTreeMap::new();
        for r in &self.rules {
            seen.entry(r.sid)
                .or_default()
                .push((r.source_file.clone(), r.line_no));
        }
        seen.into_iter()
            .filter(|(_, v)| v.len() > 1)
            .map(|(sid, occurrences)| DuplicateSid { sid, occurrences })
            .collect()
    }

    /// SIDs that appear both as an enabled rule and as a commented-out one.
    pub fn conflicting_disabled(&self) -> Vec<u64> {
        let mut enabled = BTreeMap::new();
        let mut disabled = BTreeMap::new();
        for r in &self.rules {
            if r.disabled {
                disabled.insert(r.sid, ());
            } else {
                enabled.insert(r.sid, ());
            }
        }
        enabled
            .keys()
            .filter(|sid| disabled.contains_key(sid))
            .copied()
            .collect()
    }
}

fn collect_rule_files(paths: &[PathBuf]) -> io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for p in paths {
        if p.is_dir() {
            walk(p, &mut out)?;
        } else {
            if !p.exists() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no such file or directory: {}", p.display()),
                ));
            }
            out.push(p.clone());
        }
    }
    out.sort();
    Ok(out)
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            walk(&path, out)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("rules") {
            out.push(path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules_from(lines: &[&str]) -> RuleSet {
        let mut set = RuleSet::default();
        for (i, line) in lines.iter().enumerate() {
            match parse_line(line, i + 1, "mem.rules") {
                ParseOutcome::Rule(r) => set.rules.push(r),
                ParseOutcome::Invalid(inv) => set.invalid.push(inv),
                ParseOutcome::Skipped => {}
            }
        }
        set
    }

    #[test]
    fn counts_enabled_and_disabled() {
        let set = rules_from(&[
            r#"alert tcp any any -> any any (msg:"a"; sid:1; classtype:attempted-recon;)"#,
            r#"# alert tcp any any -> any any (msg:"b"; sid:2; classtype:attempted-recon;)"#,
            r#"alert tcp any any -> any any (msg:"c"; sid:3; classtype:attempted-recon;)"#,
        ]);
        assert_eq!(set.enabled_count(), 2);
        assert_eq!(set.disabled_count(), 1);
    }

    #[test]
    fn detects_duplicate_sids() {
        let set = rules_from(&[
            r#"alert tcp any any -> any any (msg:"a"; sid:100;)"#,
            r#"alert udp any any -> any any (msg:"b"; sid:100;)"#,
            r#"alert tcp any any -> any any (msg:"c"; sid:200;)"#,
        ]);
        let dupes = set.duplicate_sids();
        assert_eq!(dupes.len(), 1);
        assert_eq!(dupes[0].sid, 100);
        assert_eq!(dupes[0].occurrences.len(), 2);
    }

    #[test]
    fn detects_conflicting_disabled_sid() {
        let set = rules_from(&[
            r#"alert tcp any any -> any any (msg:"a"; sid:100;)"#,
            r#"# alert tcp any any -> any any (msg:"a old"; sid:100;)"#,
        ]);
        assert_eq!(set.conflicting_disabled(), vec![100]);
    }

    #[test]
    fn missing_classtype_is_reported() {
        let set = rules_from(&[
            r#"alert tcp any any -> any any (msg:"a"; sid:1; classtype:attempted-recon;)"#,
            r#"alert tcp any any -> any any (msg:"b"; sid:2;)"#,
        ]);
        let missing = set.missing_classtype();
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].sid, 2);
    }

    #[test]
    fn nonexistent_path_is_an_error() {
        let err = RuleSet::load(&[PathBuf::from("/definitely/not/here.rules")]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }
}
