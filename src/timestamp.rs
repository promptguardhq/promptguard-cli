//! UTC timestamps: the CLI's one clock.
//!
//! Every timestamp the CLI writes or prints goes through [`Timestamp`], which
//! keeps the exact text chrono produced before issue #67 moved the crate off
//! it (RUSTSEC-2026-0543): the `time` crate supplies the clock and RFC 3339
//! parsing, and the formatting below is written out by hand so no library
//! default can change a byte. `tests/timestamp_tests.rs` pins each format.

use std::fmt::Write as _;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, UtcOffset};

/// A string that is not an RFC 3339 timestamp.
#[derive(Debug, thiserror::Error)]
#[error("invalid RFC 3339 timestamp {input:?}")]
pub struct ParseTimestampError {
    input: String,
}

/// An instant, always held in UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(OffsetDateTime);

impl Timestamp {
    /// The current time.
    #[must_use]
    pub fn now() -> Self {
        Self(OffsetDateTime::now_utc())
    }

    /// Parse an RFC 3339 timestamp in any offset, normalized to UTC.
    pub fn parse_rfc3339(input: &str) -> Result<Self, ParseTimestampError> {
        OffsetDateTime::parse(input, &Rfc3339)
            .map(|t| Self(t.to_offset(UtcOffset::UTC)))
            .map_err(|_| ParseTimestampError {
                input: input.to_string(),
            })
    }

    /// `2026-11-21T09:05:03.250+00:00`: RFC 3339 with a numeric offset.
    #[must_use]
    pub fn to_rfc3339(self) -> String {
        let mut out = self.date_time('-', 'T', ':');
        push_fraction(&mut out, self.0.nanosecond());
        out.push_str("+00:00");
        out
    }

    /// `2026-11-21 09:05:03`: for people, seconds precision.
    #[must_use]
    pub fn display_seconds(self) -> String {
        self.date_time('-', ' ', ':')
    }

    /// `20261121T090503.250Z`: compact, millisecond precision (truncated),
    /// safe in a file name.
    #[must_use]
    pub fn file_stamp(self) -> String {
        let t = self.0;
        format!(
            "{:04}{:02}{:02}T{:02}{:02}{:02}.{:03}Z",
            t.year(),
            u8::from(t.month()),
            t.day(),
            t.hour(),
            t.minute(),
            t.second(),
            t.millisecond(),
        )
    }

    fn date_time(self, date_sep: char, mid: char, time_sep: char) -> String {
        let t = self.0;
        format!(
            "{:04}{date_sep}{:02}{date_sep}{:02}{mid}{:02}{time_sep}{:02}{time_sep}{:02}",
            t.year(),
            u8::from(t.month()),
            t.day(),
            t.hour(),
            t.minute(),
            t.second(),
        )
    }
}

/// Append the fraction of a second the way chrono's `SecondsFormat::AutoSi`
/// does: nothing when whole, otherwise 3, 6 or 9 digits, the fewest that are
/// exact.
fn push_fraction(out: &mut String, nanos: u32) {
    let _ = match nanos {
        0 => Ok(()),
        n if n % 1_000_000 == 0 => write!(out, ".{:03}", n / 1_000_000),
        n if n % 1_000 == 0 => write!(out, ".{:06}", n / 1_000),
        n => write!(out, ".{n:09}"),
    };
}

/// Serialized as RFC 3339 with a `Z` suffix and an `AutoSi` fraction
/// (`2026-11-21T09:05:03.250Z`), as chrono's serde support wrote it.
impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut out = self.date_time('-', 'T', ':');
        push_fraction(&mut out, self.0.nanosecond());
        out.push('Z');
        s.serialize_str(&out)
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        Self::parse_rfc3339(&text).map_err(serde::de::Error::custom)
    }
}
