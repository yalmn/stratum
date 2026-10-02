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

/// Umkehrung von [`filetime_to_iso`]: liest genau dieses Format (Jahr vier-
/// oder fünfstellig, sieben Nachkommastellen, `Z`) zurück in FILETIME.
/// Anderes oder Ungültiges (Monat 13, 25 Uhr, Wert über `u64::MAX`) ergibt
/// `None`.
pub fn iso_to_filetime(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    let jahr_len = b.iter().position(|c| *c == b'-')?;
    if !(4..=5).contains(&jahr_len) || b.len() != jahr_len + 24 {
        return None;
    }
    let zahl = |von: usize, bis: usize| -> Option<u64> {
        let t = b.get(von..bis)?;
        if t.is_empty() || !t.iter().all(u8::is_ascii_digit) {
            return None;
        }
        Some(t.iter().fold(0u64, |n, c| n * 10 + u64::from(c - b'0')))
    };
    let r = &b[jahr_len..];
    if r[0] != b'-'
        || r[3] != b'-'
        || r[6] != b'T'
        || r[9] != b':'
        || r[12] != b':'
        || r[15] != b'.'
        || r[23] != b'Z'
    {
        return None;
    }
    let j = jahr_len;
    let (y, m, d) = (zahl(0, j)?, zahl(j + 1, j + 3)?, zahl(j + 4, j + 6)?);
    let (h, mi, sek) = (
        zahl(j + 7, j + 9)?,
        zahl(j + 10, j + 12)?,
        zahl(j + 13, j + 15)?,
    );
    let frac = zahl(j + 16, j + 23)?;
    if !(1..=12).contains(&m) || h > 23 || mi > 59 || sek > 59 {
        return None;
    }
    let tage = days_from_civil(y as i64, m as u32, d as u32)? + DAYS_1601_TO_1970;
    let tage = u64::try_from(tage).ok()?;
    tage.checked_mul(TICKS_PER_DAY)?
        .checked_add((h * 3600 + mi * 60 + sek) * 10_000_000)?
        .checked_add(frac)
}

/// Tage seit 1970-01-01 aus einem Datum; `None` bei ungültigem Tag.
fn days_from_civil(y: i64, m: u32, d: u32) -> Option<i64> {
    let schalt = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let max = match m {
        2 if schalt => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if d == 0 || d > max {
        return None;
    }
    let y = y - i64::from(m <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = i64::from(if m > 2 { m - 3 } else { m + 9 });
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
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

    #[test]
    fn iso_rundlauf() {
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let mut werte = vec![1, 116_444_736_000_000_000, (1 << 63) - 1, 1 << 63, u64::MAX];
        for _ in 0..200_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            werte.push(x);
            werte.push(x % 200_000_000_000_000_000);
        }
        for ft in werte.into_iter().filter(|v| *v != 0) {
            let iso = filetime_to_iso(ft).unwrap();
            assert_eq!(iso_to_filetime(&iso), Some(ft), "{iso}");
        }
    }

    #[test]
    fn iso_ungueltig() {
        for s in [
            "",
            "2026-04-18",
            "2026-04-18T09:40:47.325713Z",
            "2026-13-18T09:40:47.3257138Z",
            "2026-02-29T09:40:47.3257138Z",
            "2026-04-18T24:00:00.0000000Z",
            "2026-04-18 09:40:47.3257138Z",
            "1600-12-31T23:59:59.9999999Z",
            "99999-12-31T23:59:59.9999999Z",
            "+026-04-18T09:40:47.3257138Z",
            "2026-04-18T09:40:47.3257138Zx",
        ] {
            assert_eq!(iso_to_filetime(s), None, "{s}");
        }
        assert_eq!(
            iso_to_filetime("2024-02-29T00:00:00.0000000Z"),
            Some(133_536_384_000_000_000)
        );
    }
}
