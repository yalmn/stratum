//! Supertimeline: korreliert alle zeitbehafteten Funde zu einem sortierten
//! Zeitstrahl.
//!
//! Viele Domänen liefern Zeitstempel (Browser-Besuche, Programmausführungen,
//! Anmeldungen, Schattenkopien, ...). Der Zeitstrahl führt sie in einer nach
//! Zeit sortierten Liste zusammen, was Zusammenhänge über Artefaktgrenzen hinweg
//! sichtbar macht. Die Zeit bleibt als Unix-Sekunde (UTC); die Darstellung in
//! der jeweiligen Zeitzone übernimmt die nachgelagerte Schicht.

use serde::Serialize;

use crate::Finding;

/// Ein Eintrag im Zeitstrahl.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TimelineEntry {
    /// Zeitpunkt als Unix-Sekunde (UTC).
    pub unix: i64,
    /// Domäne, aus der der Eintrag stammt.
    pub domain: String,
    /// Art des Zeitpunkts (z. B. "besucht", "ausgefuehrt", "angemeldet").
    pub ereignis: &'static str,
    /// Kurzbezeichnung (Name des Funds).
    pub name: String,
    /// Quelle im Image.
    pub source: String,
}

/// Attribut-Schlüssel mit Zeitstempel und die zugehörige Ereignisbezeichnung,
/// in Prioritätsreihenfolge (der erste vorhandene bestimmt den Eintrag).
const TIME_KEYS: &[(&str, &str)] = &[
    ("zeit_unix", "ereignis"),
    ("besucht_unix", "besucht"),
    ("letzte_ausfuehrung_unix", "ausgefuehrt"),
    ("registriert_unix", "registriert"),
    ("erstellt_unix", "erstellt"),
    ("letzte_aenderung_unix", "geaendert"),
];

/// Baut aus allen Funden den nach Zeit sortierten Zeitstrahl. Funde ohne
/// Zeitstempel werden übersprungen.
pub fn build(findings: &[Finding]) -> Vec<TimelineEntry> {
    let mut entries = Vec::new();
    for f in findings {
        for (key, ereignis) in TIME_KEYS {
            if let Some(val) = f.attributes.get(*key) {
                if let Ok(unix) = val.parse::<i64>() {
                    entries.push(TimelineEntry {
                        unix,
                        domain: f.domain.clone(),
                        ereignis,
                        name: f.name.clone(),
                        source: f.source.clone(),
                    });
                    break;
                }
            }
        }
    }
    entries.sort_by(|a, b| a.unix.cmp(&b.unix).then(a.domain.cmp(&b.domain)));
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(domain: &str, name: &str, key: &str, val: &str) -> Finding {
        Finding::new(domain, name, "q").with(key, val)
    }

    #[test]
    fn sortiert_und_gefiltert() {
        let findings = vec![
            f("browser", "b", "besucht_unix", "200"),
            f("eventlog", "e", "zeit_unix", "100"),
            f("keyword", "ohne_zeit", "kontext", "x"),
            f("prefetch", "p", "letzte_ausfuehrung_unix", "150"),
        ];
        let tl = build(&findings);
        assert_eq!(tl.len(), 3, "Fund ohne Zeit wird ausgelassen");
        assert_eq!(tl[0].unix, 100);
        assert_eq!(tl[0].ereignis, "ereignis");
        assert_eq!(tl[1].unix, 150);
        assert_eq!(tl[1].ereignis, "ausgefuehrt");
        assert_eq!(tl[2].unix, 200);
    }

    #[test]
    fn erster_zeitschluessel_gewinnt() {
        let finding = Finding::new("prefetch", "p", "q")
            .with("letzte_ausfuehrung_unix", "500")
            .with("letzte_aenderung_unix", "400");
        let tl = build(&[finding]);
        assert_eq!(tl.len(), 1);
        assert_eq!(tl[0].unix, 500);
        assert_eq!(tl[0].ereignis, "ausgefuehrt");
    }
}
