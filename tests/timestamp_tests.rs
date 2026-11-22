#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Pins the exact text of every timestamp the CLI writes or prints, so the
//! clock library behind `promptguard::timestamp` can change without changing
//! a byte of output (issue #67 moved it off chrono).

use promptguard::config::ConfigMetadata;
use promptguard::timestamp::Timestamp;

fn ts(input: &str) -> Timestamp {
    match Timestamp::parse_rfc3339(input) {
        Ok(t) => t,
        Err(e) => panic!("{e}"),
    }
}

fn json(t: Timestamp) -> String {
    match serde_json::to_string(&t) {
        Ok(s) => s,
        Err(e) => panic!("{e}"),
    }
}

#[test]
fn serializes_like_chrono_with_z_and_si_grouped_fraction() {
    assert_eq!(
        json(ts("2026-11-21T09:05:03Z")),
        r#""2026-11-21T09:05:03Z""#
    );
    assert_eq!(
        json(ts("2026-11-21T09:05:03.5Z")),
        r#""2026-11-21T09:05:03.500Z""#
    );
    assert_eq!(
        json(ts("2026-11-21T09:05:03.000120Z")),
        r#""2026-11-21T09:05:03.000120Z""#
    );
    assert_eq!(
        json(ts("2026-11-21T09:05:03.1234567Z")),
        r#""2026-11-21T09:05:03.123456700Z""#
    );
    assert_eq!(
        json(ts("2026-11-21T09:05:03.123456789Z")),
        r#""2026-11-21T09:05:03.123456789Z""#
    );
}

#[test]
fn normalizes_any_offset_to_utc() {
    assert_eq!(
        json(ts("2026-11-21T00:30:00+05:30")),
        r#""2026-11-20T19:00:00Z""#
    );
    assert_eq!(
        json(ts("2026-11-21T23:00:00-02:00")),
        r#""2026-11-22T01:00:00Z""#
    );
}

#[test]
fn rfc3339_uses_numeric_utc_offset() {
    assert_eq!(
        ts("2026-11-21T09:05:03Z").to_rfc3339(),
        "2026-11-21T09:05:03+00:00"
    );
    assert_eq!(
        ts("2026-11-21T09:05:03.25Z").to_rfc3339(),
        "2026-11-21T09:05:03.250+00:00"
    );
    assert_eq!(
        ts("2026-11-21T09:05:03.000001Z").to_rfc3339(),
        "2026-11-21T09:05:03.000001+00:00"
    );
}

#[test]
fn display_seconds_drops_the_fraction() {
    assert_eq!(
        ts("2026-01-02T03:04:05.999Z").display_seconds(),
        "2026-01-02 03:04:05"
    );
}

#[test]
fn file_stamp_truncates_to_milliseconds() {
    assert_eq!(
        ts("2026-01-02T03:04:05Z").file_stamp(),
        "20260102T030405.000Z"
    );
    assert_eq!(
        ts("2026-01-02T03:04:05.9999Z").file_stamp(),
        "20260102T030405.999Z"
    );
}

#[test]
fn deserializes_what_it_serializes() {
    for input in ["2026-11-21T09:05:03Z", "2026-11-21T09:05:03.123456789Z"] {
        let t = ts(input);
        let back: Timestamp = match serde_json::from_str(&json(t)) {
            Ok(b) => b,
            Err(e) => panic!("{e}"),
        };
        assert_eq!(back, t);
    }
}

#[test]
fn rejects_non_rfc3339() {
    assert!(Timestamp::parse_rfc3339("2026-11-21").is_err());
    assert!(serde_json::from_str::<Timestamp>(r#""yesterday""#).is_err());
}

#[test]
fn reads_config_metadata_written_by_earlier_versions() {
    let text = r#"{"last_applied":"2026-08-03T14:22:11.481203Z","cli_version":"2.5.0"}"#;
    let meta: ConfigMetadata = match serde_json::from_str(text) {
        Ok(m) => m,
        Err(e) => panic!("{e}"),
    };
    let Some(last) = meta.last_applied else {
        panic!("last_applied was dropped");
    };
    assert_eq!(json(last), r#""2026-08-03T14:22:11.481203Z""#);
    assert_eq!(last.display_seconds(), "2026-08-03 14:22:11");
}
