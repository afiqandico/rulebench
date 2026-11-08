//! rulebench — Suricata rule validator and alert-coverage analyzer.
//!
//! Two questions an analyst asks about a ruleset:
//!   1. is it internally consistent? (`check`)
//!   2. is it actually earning its keep? (`coverage`)

pub mod coverage;
pub mod eve;
pub mod report;
pub mod rule;
pub mod ruleset;

pub use coverage::{CoverageReport, analyze};
pub use ruleset::RuleSet;
