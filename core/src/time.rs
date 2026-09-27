//! Umrechnung von Windows-FILETIME in lesbare UTC-Zeitangaben.
//!
//! Ohne externe Zeitbibliothek: der Kalender wird aus der Tageszahl berechnet
//! (proleptischer gregorianischer Kalender, Verfahren nach Howard Hinnant).

/// Tage zwischen 1601-01-01 und 1970-01-01.
const DAYS_1601_TO_1970: i64 = 134_774;
/// FILETIME-Schritte (100 ns) je Tag.
const TICKS_PER_DAY: u64 = 864_000_000_000;

/// Formatiert eine FILETIME (100-ns-Schritte seit 1601-01-01 UTC) verlustfrei
/// als ISO 8601 mit sieben Nachkommastellen, z. B. `2024-05-01T12:34:56.1234567Z`.
/// Der Wert 0 bedeutet in NTFS „nicht gesetzt“ und liefert `None`.
pub fn filetime_to_iso(ft: u64) -> Option<String> {
    if ft == 0 {
        return None;
    }
    let days = (ft / TICKS_PER_DAY) as i64;
    let rest = ft % TICKS_PER_DAY;
    let secs = rest / 10_000_000;
    let frac = rest % 10_000_000;
    let (y, m, d) = civil_from_days(days - DAYS_1601_TO_1970);
    Some(format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{frac:07}Z",
        secs / 3600,
        secs / 60 % 60,
        secs % 60
    ))
}

/// Datum aus Tagen seit 1970-01-01.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bekannte_zeitpunkte() {
        assert_eq!(filetime_to_iso(0), None);
        assert_eq!(
            filetime_to_iso(116_444_736_000_000_000).as_deref(),
            Some("1970-01-01T00:00:00.0000000Z")
        );
        assert_eq!(
            filetime_to_iso(132_539_328_000_000_000).as_deref(),
            Some("2021-01-01T00:00:00.0000000Z")
        );
        // Schaltjahr und Nachkommastellen.
        assert_eq!(
            filetime_to_iso(116_444_736_000_000_000 + 951_782_400 * 10_000_000 + 1).as_deref(),
            Some("2000-02-29T00:00:00.0000001Z")
        );
        // Vor 1970 und Grenzwerte ohne Panik.
        assert_eq!(
            filetime_to_iso(1).as_deref(),
            Some("1601-01-01T00:00:00.0000001Z")
        );
        assert!(filetime_to_iso(u64::MAX).is_some());
    }
}
