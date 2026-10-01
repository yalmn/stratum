//! Forensische Zeitangaben: mehr als nur ein UTC-Zeitpunkt.
//!
//! Jede Zeitangabe trägt ihre Genauigkeit, den Originalwert aus der Quelle,
//! die Zeitzone, falls der Wert als Ortszeit vorlag und über die Registry
//! umgerechnet wurde, und ihre Bedeutung. Artefaktzeit, Untersuchungszeit und
//! Analystenzeit werden so nie verwechselt. Ortszeiten ohne bekannte Zone
//! werden nicht umgerechnet und sind deshalb keine [`ForensicTime`].

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// FILETIME-Schritte (100 ns) zwischen 1601-01-01 und 1970-01-01.
const FILETIME_UNIX: i64 = 116_444_736_000_000_000;
/// Tage zwischen 1899-12-30 (OLE-Datum) und 1970-01-01.
const OLE_UNIX_TAGE: f64 = 25_569.0;

/// Genauigkeit einer Zeitangabe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimePrecision {
    /// Nanosekunde.
    Nanosecond,
    /// 100 Nanosekunden (FILETIME).
    HundredNanoseconds,
    /// Mikrosekunde.
    Microsecond,
    /// Millisekunde.
    Millisecond,
    /// Sekunde.
    Second,
    /// Minute.
    Minute,
    /// Tag.
    Day,
    /// Unbekannt.
    Unknown,
}

/// Bedeutung einer Zeitangabe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeSemantics {
    /// Zeitstempel eines Artefakts (z. B. MFT-Zeiten, Registry-LastWrite).
    ArtifactTime,
    /// Zeitpunkt eines Vorgangs auf dem untersuchten System.
    EventTime,
    /// Zeitpunkt der Sicherung der Evidence.
    EvidenceAcquisitionTime,
    /// Zeitpunkt einer Analyse in stratum.
    AnalysisTime,
    /// Zeitpunkt einer Analystenaktion in stratum.
    AnalystActionTime,
    /// Erstmals gesehen laut Threat Intelligence.
    ThreatIntelFirstSeen,
    /// Zuletzt gesehen laut Threat Intelligence.
    ThreatIntelLastSeen,
    /// Zeitpunkt in einer Rekonstruktion (Replay).
    ReplayTime,
}

/// Zeitangabe mit Herkunftsangaben.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForensicTime {
    /// Zeitpunkt in UTC.
    pub utc: DateTime<Utc>,
    /// Originalwert aus der Quelle (z. B. FILETIME als Zahl).
    pub original: Option<String>,
    /// Zeitzone, falls der Wert als Ortszeit vorlag und mit der Zone aus der
    /// Registry umgerechnet wurde (z. B. `W. Europe Standard Time`).
    pub timezone: Option<String>,
    /// Genauigkeit.
    pub precision: TimePrecision,
    /// Bedeutung.
    pub semantics: TimeSemantics,
}

impl ForensicTime {
    /// Aus einer FILETIME (100-ns-Schritte seit 1601-01-01 UTC), verlustfrei.
    /// Der Wert 0 bedeutet in Windows „nicht gesetzt“ und liefert `None`.
    pub fn from_filetime(ft: u64, semantics: TimeSemantics) -> Option<Self> {
        if ft == 0 {
            return None;
        }
        let ticks = i64::try_from(ft).ok()? - FILETIME_UNIX;
        let utc = DateTime::from_timestamp(
            ticks.div_euclid(10_000_000),
            (ticks.rem_euclid(10_000_000) * 100) as u32,
        )?;
        Some(Self {
            utc,
            original: Some(ft.to_string()),
            timezone: None,
            precision: TimePrecision::HundredNanoseconds,
            semantics,
        })
    }

    /// Aus Unix-Sekunden (UTC).
    pub fn from_unix(secs: i64, semantics: TimeSemantics) -> Option<Self> {
        Some(Self {
            utc: DateTime::from_timestamp(secs, 0)?,
            original: Some(secs.to_string()),
            timezone: None,
            precision: TimePrecision::Second,
            semantics,
        })
    }

    /// Aus einem OLE-Datum (Tage seit 1899-12-30, UTC), wie in SRUM. Auf die
    /// Millisekunde gerundet; der Originalwert bleibt erhalten.
    pub fn from_ole_date(tage: f64, semantics: TimeSemantics) -> Option<Self> {
        if !tage.is_finite() || !(1.0..200_000.0).contains(&tage) {
            return None;
        }
        let ms = ((tage - OLE_UNIX_TAGE) * 86_400_000.0).round() as i64;
        Some(Self {
            utc: DateTime::from_timestamp_millis(ms)?,
            original: Some(tage.to_string()),
            timezone: None,
            precision: TimePrecision::Millisecond,
            semantics,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetime_verlustfrei() {
        let t = ForensicTime::from_filetime(134_209_771_526_006_675, TimeSemantics::ArtifactTime)
            .unwrap();
        assert_eq!(
            t.utc.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
            "2026-04-18T09:12:32.600667500Z"
        );
        assert_eq!(t.original.as_deref(), Some("134209771526006675"));
        assert_eq!(t.precision, TimePrecision::HundredNanoseconds);
        assert!(ForensicTime::from_filetime(0, TimeSemantics::ArtifactTime).is_none());
        // Vor 1970.
        let alt = ForensicTime::from_filetime(1, TimeSemantics::ArtifactTime).unwrap();
        assert_eq!(alt.utc.to_rfc3339(), "1601-01-01T00:00:00.000000100+00:00");
    }

    #[test]
    fn ole_datum_wie_in_srum() {
        // Rohwert aus SRUDB.dat (siehe SRUM-Analyzer): 2026-04-18 08:48:00 UTC.
        let tage = f64::from_bits(4_676_572_922_901_150_652);
        let t = ForensicTime::from_ole_date(tage, TimeSemantics::ArtifactTime).unwrap();
        assert_eq!(t.utc.to_rfc3339(), "2026-04-18T08:48:00+00:00");
        assert!(ForensicTime::from_ole_date(f64::NAN, TimeSemantics::ArtifactTime).is_none());
    }

    #[test]
    fn json_form() {
        let t = ForensicTime::from_unix(1_776_505_484, TimeSemantics::EventTime).unwrap();
        let j = serde_json::to_value(&t).unwrap();
        assert_eq!(j["utc"], "2026-04-18T09:44:44Z");
        assert_eq!(j["precision"], "second");
        assert_eq!(j["semantics"], "event_time");
        assert_eq!(serde_json::from_value::<ForensicTime>(j).unwrap(), t);
    }
}
