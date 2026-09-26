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
    /// Index des ursprünglichen Funds innerhalb desselben Reports.
    pub finding_index: usize,
    /// Attribut des Funds, aus dem dieser Zeitpunkt stammt.
    pub time_key: &'static str,
    /// Physischer Image-Offset, sofern am Fund vorhanden.
    pub offset: Option<u64>,
    /// Herkunft einer Schattenkopie, sofern am Fund vorhanden.
    pub volume: Option<String>,
}

/// Attribut-Schlüssel mit Zeitstempel und die zugehörige Ereignisbezeichnung,
/// Jeder vorhandene gültige Zeitpunkt erzeugt ein eigenes Ereignis.
const TIME_KEYS: &[(&str, &str)] = &[
    ("geloescht_unix", "geloescht"),
    ("letzter_zugriff_unix", "zugegriffen"),
    ("key_letzte_aenderung_unix", "registry_key_geaendert"),
    ("ziel_erstellt_unix", "ziel_erstellt"),
    ("ziel_geaendert_unix", "ziel_geaendert"),
    ("ziel_zugriff_unix", "ziel_zugegriffen"),
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
    for (finding_index, f) in findings.iter().enumerate() {
        for (key, ereignis) in TIME_KEYS {
            if let Some(val) = f.attributes.get(*key) {
                if let Ok(unix) = val.parse::<i64>() {
                    entries.push(TimelineEntry {
                        unix,
                        domain: f.domain.clone(),
                        ereignis,
                        name: f.name.clone(),
                        source: f.source.clone(),
                        finding_index,
                        time_key: key,
                        offset: f.offset,
                        volume: f.attributes.get("volume").cloned(),
                    });
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
    fn neue_zeiten_und_herkunft() {
        let f = Finding::new("papierkorb", "x", "quelle")
            .at(4096)
            .with("geloescht_unix", "100")
            .with("ziel_erstellt_unix", "50")
            .with("key_letzte_aenderung_unix", "ungueltig")
            .with("volume", "VSS#1");
        let timeline = build(&[f]);
        assert_eq!(timeline.len(), 2);
        assert_eq!(timeline[0].ereignis, "ziel_erstellt");
        assert_eq!(timeline[1].ereignis, "geloescht");
        for entry in timeline {
            assert_eq!(entry.offset, Some(4096));
            assert_eq!(entry.volume.as_deref(), Some("VSS#1"));
            assert_eq!(entry.finding_index, 0);
        }
    }

    #[test]
    fn alle_zeitpunkte_bleiben_erhalten() {
        let finding = Finding::new("prefetch", "p", "q")
            .with("letzte_ausfuehrung_unix", "500")
            .with("letzte_aenderung_unix", "400");
        let tl = build(&[finding]);
        assert_eq!(tl.len(), 2);
        assert_eq!(tl[0].unix, 400);
        assert_eq!(tl[1].unix, 500);
        assert_eq!(tl[1].ereignis, "ausgefuehrt");
        assert_eq!(tl[1].finding_index, 0);
        assert_eq!(tl[1].time_key, "letzte_ausfuehrung_unix");
    }
}
