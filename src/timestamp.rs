//! UTC timestamps: the CLI's one clock.
//!
//! Every timestamp the CLI writes or prints goes through [`Timestamp`], which
//! keeps the exact text chrono produced before issue #67 moved the crate off
//! it (RUSTSEC-2026-0543), and reads everything chrono read. The `time` crate
//! supplies the clock and the calendar; parsing and formatting are written out
//! by hand so no library default can change a byte. `tests/timestamp_tests.rs`
//! pins each format and each accepted form.

use std::fmt::Write as _;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time, UtcOffset};

/// chrono's year range (`NaiveDate::MIN` and `MAX`), which bounded what it
/// would read.
const MIN_YEAR: i32 = (i32::MIN >> 13) + 1;
const MAX_YEAR: i32 = (i32::MAX >> 13) - 1;

/// A string that is not a timestamp in any form chrono accepted.
#[derive(Debug, thiserror::Error)]
#[error("invalid timestamp {input:?}")]
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

    /// Parse a timestamp in any offset, normalized to UTC.
    ///
    /// Accepts exactly what chrono 0.4's `DateTime<Utc>` deserializer did
    /// (its relaxed RFC 3339 parser), so every config an earlier version read
    /// still loads: `T`, `t` or a space between date and time; unpadded
    /// fields; whitespace between components and around the value; a year
    /// outside 0-9999 when it carries a sign; any number of fraction digits
    /// (past nine are ignored); and as the offset `Z`, `z`, `UTC` in any case,
    /// or a sign (`+`, `-` or U+2212) with hours and minutes, the two parted
    /// by a colon, whitespace or nothing. A leap second (`:60`) reads as the
    /// last nanosecond of its minute, since `time` has none.
    pub fn parse(input: &str) -> Result<Self, ParseTimestampError> {
        parse_relaxed(input)
            .map(Self)
            .ok_or_else(|| ParseTimestampError {
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
            "{}{:02}{:02}T{:02}{:02}{:02}.{:03}Z",
            Year(t.year()),
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
            "{}{date_sep}{:02}{date_sep}{:02}{mid}{:02}{time_sep}{:02}{time_sep}{:02}",
            Year(t.year()),
            u8::from(t.month()),
            t.day(),
            t.hour(),
            t.minute(),
            t.second(),
        )
    }
}

/// A year as chrono wrote it: four digits within 0-9999, otherwise signed
/// and at least four digits (ISO 8601's expanded form).
struct Year(i32);

impl std::fmt::Display for Year {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if (0..=9999).contains(&self.0) {
            write!(f, "{:04}", self.0)
        } else {
            write!(f, "{:+05}", self.0)
        }
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
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

/// chrono 0.4.45's `parse_rfc3339_relaxed` followed by its `to_datetime`,
/// step for step; `None` wherever chrono returned an error.
fn parse_relaxed(input: &str) -> Option<OffsetDateTime> {
    let mut s = Cursor(input);

    s.skip_space();
    let year = if s.eat('-') {
        s.number(usize::MAX)?.checked_neg()?
    } else if s.eat('+') {
        s.number(usize::MAX)?
    } else {
        s.number(4)?
    };
    let year = i32::try_from(year).ok()?;
    s.skip_space();
    s.expect('-')?;
    let month = s.field(2)?;
    s.skip_space();
    s.expect('-')?;
    let day = s.field(2)?;

    if !(s.eat('T') || s.eat('t') || s.eat(' ')) {
        return None;
    }

    let hour = s.field(2)?;
    s.skip_space();
    s.expect(':')?;
    let minute = s.field(2)?;
    s.skip_space();
    s.expect(':')?;
    let second = s.field(2)?;
    let nanosecond = if s.eat('.') { s.fraction()? } else { 0 };
    s.skip_space();
    let offset = s.offset()?;
    s.skip_space();
    if !s.0.is_empty() {
        return None;
    }

    if !(MIN_YEAR..=MAX_YEAR).contains(&year)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=60).contains(&second)
    {
        return None;
    }
    // chrono stored a leap second as :59 plus a whole second of nanoseconds.
    let (second, nanosecond) = if second == 60 {
        (59, 999_999_999)
    } else {
        (second, nanosecond)
    };
    let month = Month::try_from(u8::try_from(month).ok()?).ok()?;
    let date = Date::from_calendar_date(year, month, u8::try_from(day).ok()?).ok()?;
    let time = Time::from_hms_nano(
        u8::try_from(hour).ok()?,
        u8::try_from(minute).ok()?,
        u8::try_from(second).ok()?,
        nanosecond,
    )
    .ok()?;
    // FixedOffset::east_opt: strictly less than a day either way.
    if offset.abs() >= 86_400 {
        return None;
    }
    let utc = PrimitiveDateTime::new(date, time)
        .assume_offset(UtcOffset::from_whole_seconds(offset).ok()?)
        .checked_to_offset(UtcOffset::UTC)?;
    (MIN_YEAR..=MAX_YEAR).contains(&utc.year()).then_some(utc)
}

/// The unread rest of the input, consumed front to back.
struct Cursor<'a>(&'a str);

impl Cursor<'_> {
    /// chrono's `Item::Space`: any run of Unicode whitespace, or none.
    fn skip_space(&mut self) {
        self.0 = self.0.trim_start();
    }

    fn eat(&mut self, c: char) -> bool {
        match self.0.strip_prefix(c) {
            Some(rest) => {
                self.0 = rest;
                true
            },
            None => false,
        }
    }

    fn expect(&mut self, c: char) -> Option<()> {
        self.eat(c).then_some(())
    }

    /// chrono's `scan::number`: one to `max` ASCII digits.
    fn number(&mut self, max: usize) -> Option<i64> {
        let len = self
            .0
            .bytes()
            .take(max)
            .take_while(u8::is_ascii_digit)
            .count();
        if len == 0 {
            return None;
        }
        let (digits, rest) = self.0.split_at(len);
        let value = digits.bytes().try_fold(0i64, |n, b| {
            n.checked_mul(10)?.checked_add(i64::from(b - b'0'))
        })?;
        self.0 = rest;
        Some(value)
    }

    /// An unsigned numeric item: leading whitespace, then up to `width` digits.
    fn field(&mut self, width: usize) -> Option<i64> {
        self.skip_space();
        self.number(width)
    }

    /// chrono's `scan::nanosecond`, after the `.`: at least one digit, the
    /// first nine scaled to nanoseconds, any more skipped.
    fn fraction(&mut self) -> Option<u32> {
        let before = self.0.len();
        let value = u32::try_from(self.number(9)?).ok()?;
        let digits = u32::try_from(before - self.0.len()).ok()?;
        self.0 = self.0.trim_start_matches(|c: char| c.is_ascii_digit());
        value.checked_mul(10u32.pow(9 - digits))
    }

    /// The offset in seconds east of UTC: `UTC` in any case, `Z` or `z`, or
    /// chrono's `scan::timezone_offset` with a colon or whitespace allowed
    /// between hours and minutes, minutes required, U+2212 allowed as minus.
    fn offset(&mut self) -> Option<i32> {
        if self.0.len() >= 3 && self.0.as_bytes()[..3].eq_ignore_ascii_case(b"UTC") {
            self.0 = &self.0[3..];
            return Some(0);
        }
        if self.eat('Z') || self.eat('z') {
            return Some(0);
        }
        let negative = if self.eat('+') {
            false
        } else if self.eat('-') || self.eat('\u{2212}') {
            true
        } else {
            return None;
        };
        let hours = self.two_digits(b'9')?;
        self.0 = self
            .0
            .trim_start_matches(|c: char| c == ':' || c.is_whitespace());
        let minutes = self.two_digits(b'5')?;
        let seconds = hours * 3600 + minutes * 60;
        Some(if negative { -seconds } else { seconds })
    }

    /// Exactly two ASCII digits, the first no greater than `first_max`.
    fn two_digits(&mut self, first_max: u8) -> Option<i32> {
        match *self.0.as_bytes() {
            [a @ b'0'..=b'9', b @ b'0'..=b'9', ..] if a <= first_max => {
                self.0 = &self.0[2..];
                Some(i32::from(a - b'0') * 10 + i32::from(b - b'0'))
            },
            _ => None,
        }
    }
}
