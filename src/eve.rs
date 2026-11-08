//! Parsing Suricata `eve.json` (one JSON object per line) into alert stats.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct EveEvent {
    #[serde(default)]
    pub timestamp: String,
    #[serde(default)]
    pub event_type: String,
    #[serde(default)]
    pub src_ip: Option<String>,
    #[serde(default)]
    pub dest_ip: Option<String>,
    #[serde(default)]
    pub proto: Option<String>,
    #[serde(default)]
    pub alert: Option<EveAlert>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EveAlert {
    pub signature_id: u64,
    #[serde(default)]
    pub signature: String,
    #[serde(default)]
    pub severity: Option<u8>,
    #[serde(default)]
    pub category: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct SidCount {
    pub signature: String,
    pub count: u64,
    pub severity: Option<u8>,
    pub sources: BTreeSet<String>,
    pub destinations: BTreeSet<String>,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
}

#[derive(Debug, Default)]
pub struct EveStats {
    pub files: Vec<PathBuf>,
    pub lines_read: u64,
    pub events: u64,
    pub alerts: u64,
    pub parse_errors: u64,
    pub per_sid: BTreeMap<u64, SidCount>,
}

/// Parse a single line. Blank lines return `Ok(None)`; malformed JSON is an error.
pub fn parse_eve_line(line: &str) -> Result<Option<EveEvent>, serde_json::Error> {
    let t = line.trim();
    if t.is_empty() {
        return Ok(None);
    }
    serde_json::from_str::<EveEvent>(t).map(Some)
}

impl EveStats {
    pub fn record(&mut self, ev: EveEvent) {
        self.events += 1;
        let Some(alert) = ev.alert else {
            return;
        };
        self.alerts += 1;
        let entry = self.per_sid.entry(alert.signature_id).or_default();
        entry.count += 1;
        if entry.signature.is_empty() {
            entry.signature = alert.signature.clone();
        }
        if entry.severity.is_none() {
            entry.severity = alert.severity;
        }
        if let Some(src) = ev.src_ip {
            entry.sources.insert(src);
        }
        if let Some(dst) = ev.dest_ip {
            entry.destinations.insert(dst);
        }
        if !ev.timestamp.is_empty() {
            if entry.first_seen.is_none() {
                entry.first_seen = Some(ev.timestamp.clone());
            }
            entry.last_seen = Some(ev.timestamp);
        }
    }
}

pub fn read_eve(paths: &[PathBuf]) -> io::Result<EveStats> {
    let mut stats = EveStats {
        files: paths.to_vec(),
        ..EveStats::default()
    };
    for path in paths {
        read_one(path, &mut stats)?;
    }
    Ok(stats)
}

fn read_one(path: &Path, stats: &mut EveStats) -> io::Result<()> {
    let file = File::open(path)?;
    let reader = BufReader::with_capacity(256 * 1024, file);
    for line in reader.lines() {
        let line = line?;
        stats.lines_read += 1;
        match parse_eve_line(&line) {
            Ok(Some(ev)) => stats.record(ev),
            Ok(None) => {}
            Err(_) => stats.parse_errors += 1,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALERT: &str = r#"{"timestamp":"2026-11-08T10:00:00.000000+0800","event_type":"alert","src_ip":"192.168.1.5","dest_ip":"10.0.0.1","proto":"TCP","alert":{"signature_id":2010935,"signature":"ET POLICY outbound","severity":2,"category":"Potentially Bad Traffic"}}"#;

    #[test]
    fn parses_an_alert_line() {
        let ev = parse_eve_line(ALERT).unwrap().unwrap();
        assert_eq!(ev.event_type, "alert");
        let alert = ev.alert.unwrap();
        assert_eq!(alert.signature_id, 2010935);
        assert_eq!(alert.severity, Some(2));
    }

    #[test]
    fn non_alert_events_are_not_counted_as_alerts() {
        let mut stats = EveStats::default();
        let flow = r#"{"timestamp":"2026-11-08T10:00:00+0800","event_type":"flow","src_ip":"1.1.1.1","dest_ip":"2.2.2.2"}"#;
        stats.record(parse_eve_line(flow).unwrap().unwrap());
        assert_eq!(stats.events, 1);
        assert_eq!(stats.alerts, 0);
        assert!(stats.per_sid.is_empty());
    }

    #[test]
    fn aggregates_per_signature() {
        let mut stats = EveStats::default();
        for _ in 0..3 {
            stats.record(parse_eve_line(ALERT).unwrap().unwrap());
        }
        assert_eq!(stats.alerts, 3);
        let s = stats.per_sid.get(&2010935).unwrap();
        assert_eq!(s.count, 3);
        assert_eq!(s.sources.len(), 1);
        assert_eq!(
            s.last_seen.as_deref(),
            Some("2026-11-08T10:00:00.000000+0800")
        );
    }

    #[test]
    fn malformed_json_is_an_error_not_a_crash() {
        assert!(parse_eve_line("{not json").is_err());
    }

    #[test]
    fn blank_line_is_skipped() {
        assert!(parse_eve_line("   ").unwrap().is_none());
    }

    #[test]
    fn unknown_extra_fields_are_ignored() {
        let line = r#"{"event_type":"alert","alert":{"signature_id":5,"signature":"x","severity":1,"extra":{"a":1}},"payload":"abc"}"#;
        assert_eq!(
            parse_eve_line(line)
                .unwrap()
                .unwrap()
                .alert
                .unwrap()
                .signature_id,
            5
        );
    }
}
