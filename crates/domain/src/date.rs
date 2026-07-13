/// Returns whether `value` is a real proleptic-Gregorian calendar date in the
/// canonical `YYYY-MM-DD` wire format used by the desktop IPC and SQLite
/// schemas. Year zero is intentionally rejected.
pub fn is_iso_calendar_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes
            .iter()
            .enumerate()
            .any(|(index, byte)| index != 4 && index != 7 && !byte.is_ascii_digit())
    {
        return false;
    }

    let Ok(year) = value[0..4].parse::<u32>() else {
        return false;
    };
    let Ok(month) = value[5..7].parse::<u32>() else {
        return false;
    };
    let Ok(day) = value[8..10].parse::<u32>() else {
        return false;
    };
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 400 == 0 || (year % 4 == 0 && year % 100 != 0) => 29,
        2 => 28,
        _ => return false,
    };

    year > 0 && (1..=days_in_month).contains(&day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_iso_calendar_dates_and_leap_years() {
        for valid in ["0001-01-01", "2000-02-29", "2024-02-29", "9999-12-31"] {
            assert!(is_iso_calendar_date(valid), "expected {valid} to be valid");
        }

        for invalid in [
            "",
            "2024-1-01",
            "2024-01-1",
            "0000-01-01",
            "1900-02-29",
            "2023-02-29",
            "2024-02-30",
            "2024-04-31",
            "2024-13-01",
            "2024-00-10",
            "2024-01-00",
            "2024/01/01",
            "2024-01-01Z",
        ] {
            assert!(
                !is_iso_calendar_date(invalid),
                "expected {invalid} to be invalid"
            );
        }
    }
}
