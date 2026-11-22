#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Pins the exact text of every timestamp the CLI writes or prints, so the
//! clock library behind `promptguard::timestamp` can change without changing
//! a byte of output (issue #67 moved it off chrono).

use promptguard::config::ConfigMetadata;
use promptguard::timestamp::Timestamp;

fn ts(input: &str) -> Timestamp {
    match Timestamp::parse(input) {
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
    assert!(Timestamp::parse("2026-11-21").is_err());
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

// The forms below are what chrono 0.4.45's `DateTime<Utc>` deserializer
// accepted (its relaxed RFC 3339 parser, `parse_rfc3339_relaxed`). A config
// holding any of them loaded before the switch, so it must still load: a
// failed `last_applied` fails the whole `.promptguard.json`.

fn canonical(input: &str) -> String {
    match serde_json::from_str::<Timestamp>(&serde_json::to_string(input).unwrap()) {
        Ok(t) => json(t),
        Err(e) => panic!("{input:?} was rejected: {e}"),
    }
}

#[test]
fn accepts_a_space_or_lowercase_t_between_date_and_time() {
    assert_eq!(
        canonical("2026-11-21 09:05:03Z"),
        r#""2026-11-21T09:05:03Z""#
    );
    assert_eq!(
        canonical("2026-11-21t09:05:03Z"),
        r#""2026-11-21T09:05:03Z""#
    );
}

#[test]
fn accepts_a_lowercase_z() {
    assert_eq!(
        canonical("2026-11-21T09:05:03z"),
        r#""2026-11-21T09:05:03Z""#
    );
}

#[test]
fn accepts_utc_as_the_offset_in_any_case() {
    // chrono's own Debug and Display form of a DateTime<Utc>.
    assert_eq!(
        canonical("2026-11-21 09:05:03 UTC"),
        r#""2026-11-21T09:05:03Z""#
    );
    assert_eq!(
        canonical("2026-11-21T09:05:03.5utc"),
        r#""2026-11-21T09:05:03.500Z""#
    );
}

#[test]
fn accepts_an_offset_without_a_colon_or_with_spaces() {
    assert_eq!(
        canonical("2026-11-21T09:05:03+0530"),
        r#""2026-11-21T03:35:03Z""#
    );
    assert_eq!(
        canonical("2026-11-21T09:05:03+05 30"),
        r#""2026-11-21T03:35:03Z""#
    );
    assert_eq!(
        canonical("2026-11-21T09:05:03 +05:30"),
        r#""2026-11-21T03:35:03Z""#
    );
}

#[test]
fn accepts_a_unicode_minus_sign_in_the_offset() {
    assert_eq!(
        canonical("2026-11-21T23:00:00\u{2212}02:00"),
        r#""2026-11-22T01:00:00Z""#
    );
}

#[test]
fn accepts_unpadded_fields() {
    assert_eq!(canonical("2026-1-2T3:4:5Z"), r#""2026-01-02T03:04:05Z""#);
    assert_eq!(canonical("26-11-21T09:05:03Z"), r#""0026-11-21T09:05:03Z""#);
}

#[test]
fn accepts_whitespace_between_components_and_around_the_value() {
    assert_eq!(
        canonical("  2026 - 11 - 21T 09 : 05 : 03.25 Z  "),
        r#""2026-11-21T09:05:03.250Z""#
    );
    assert_eq!(
        canonical("2026-11-21 \t09:05:03\nZ"),
        r#""2026-11-21T09:05:03Z""#
    );
}

#[test]
fn truncates_a_fraction_beyond_nanoseconds() {
    assert_eq!(
        canonical("2026-11-21T09:05:03.1234567899Z"),
        r#""2026-11-21T09:05:03.123456789Z""#
    );
}

#[test]
fn accepts_signed_years_outside_four_digits() {
    assert_eq!(
        canonical("+10000-01-01T00:00:00Z"),
        r#""+10000-01-01T00:00:00Z""#
    );
    assert_eq!(
        canonical("-0001-12-31T00:00:00Z"),
        r#""-0001-12-31T00:00:00Z""#
    );
    assert_eq!(
        canonical("+2026-11-21T09:05:03Z"),
        r#""2026-11-21T09:05:03Z""#
    );
    assert_eq!(
        ts("+10000-01-01T00:00:00Z").display_seconds(),
        "+10000-01-01 00:00:00"
    );
    assert_eq!(
        ts("+10000-01-01T00:00:00Z").to_rfc3339(),
        "+10000-01-01T00:00:00+00:00"
    );
    assert_eq!(
        ts("-0001-01-01T00:00:00Z").file_stamp(),
        "-00010101T000000.000Z"
    );
}

#[test]
fn accepts_a_leap_second_as_the_last_instant_of_its_minute() {
    // chrono kept 23:59:60 as a leap second; `time` has none, so it reads as
    // the last nanosecond before the next minute: same order, still loads.
    assert_eq!(
        canonical("2026-12-31T23:59:60Z"),
        r#""2026-12-31T23:59:59.999999999Z""#
    );
}

#[test]
fn still_rejects_what_chrono_rejected() {
    for bad in [
        "2026-11-21T09:05:03",       // no offset
        "2026-11-21T09:05:03+05",    // offset without minutes
        "2026-11-21T09:05:03+0560",  // offset minutes out of range
        "2026-11-21T09:05:03+24:00", // offset a day or more
        "2026-02-30T09:05:03Z",      // no such day
        "2026-11-21T24:00:00Z",      // hour out of range
        "20261-11-21T09:05:03Z",     // five-digit year without a sign
        "2026-11-21T09:05:03 .5Z",   // space before the fraction
        "2026-11-21T09:05:03.Z",     // empty fraction
        "2026-11-21T09:05:03Zjunk",  // trailing text
        "2026-11-21  T09:05:03Z",    // separator after a space
        "2026/11/21T09:05:03Z",      // wrong date separator
        "2026-11-21\t09:05:03Z",     // a tab is not a date-time separator
        "+262144-01-01T00:00:00Z",   // past chrono's last year
    ] {
        assert!(Timestamp::parse(bad).is_err(), "{bad:?} was accepted");
    }
}

#[test]
fn loads_a_config_holding_a_lenient_timestamp() {
    let text = r#"{"last_applied":"2026-08-03 14:22:11.481203 UTC","cli_version":"2.5.0"}"#;
    let meta: ConfigMetadata = serde_json::from_str(text).unwrap();
    assert_eq!(
        json(meta.last_applied.unwrap()),
        r#""2026-08-03T14:22:11.481203Z""#
    );
}
