//! Führt mehrere Analyzer parallel aus.

use std::time::Instant;

use rayon::prelude::*;
use serde::Serialize;

use stratum_core::time::filetime_to_iso;

use crate::fsindex::Herkunft;
use crate::{AnalysisContext, Analyzer, Finding};

/// Gesammeltes Ergebnis aller Analyzer.
#[derive(Debug, Default, Serialize)]
pub struct AnalysisResult {
    /// Alle Funde, nach Domäne und Offset sortiert.
    pub findings: Vec<Finding>,
    /// Auffälligkeiten aus allen Domänen.
    pub warnings: Vec<String>,
    /// Laufstatus je Analyzer in der übergebenen Reihenfolge.
    pub analyzers: Vec<AnalyzerStatus>,
}

/// Was ein einzelner Analyzer geliefert hat. Null Funde heißt nur, dass
/// dieser Analyzer nichts gemeldet hat; wie vollständig er die Quellen lesen
/// konnte, stehen dann in seinen Warnungen.
#[derive(Debug, Clone, Serialize)]
pub struct AnalyzerStatus {
    /// Name des Analyzers.
    pub name: &'static str,
    /// Domäne seiner Funde.
    pub domain: String,
    /// Anzahl der Funde.
    pub funde: usize,
    /// Anzahl der Warnungen (Quellen nicht oder nur teilweise lesbar u. a.).
    pub warnungen: usize,
    /// Laufzeit in Millisekunden (Untersuchungszeit, keine Artefaktzeit).
    pub dauer_ms: u64,
}

/// Lässt alle Analyzer gleichzeitig auf demselben Kontext laufen.
///
/// Die Analyzer sind untereinander unabhängig; ein einzelner rechenintensiver
/// Analyzer (z. B. die Keyword-Suche) parallelisiert seine Arbeit zusätzlich
/// intern.
pub fn run_all(ctx: &AnalysisContext<'_>, analyzers: &[Box<dyn Analyzer>]) -> AnalysisResult {
    let parts: Vec<(&'static str, String, crate::Outcome, u64)> = analyzers
        .par_iter()
        .map(|a| {
            let start = Instant::now();
            let outcome = a.run(ctx);
            let ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
            (a.name(), a.domain().to_string(), outcome, ms)
        })
        .collect();

    let mut out = AnalysisResult::default();
    for (name, domain, mut outcome, dauer_ms) in parts {
        out.analyzers.push(AnalyzerStatus {
            name,
            domain: domain.clone(),
            funde: outcome.findings.len(),
            warnungen: outcome.warnings.len(),
            dauer_ms,
        });
        out.findings.append(&mut outcome.findings);
        for w in outcome.warnings {
            out.warnings.push(format!("[{domain}] {w}"));
        }
    }

    // Dateibasierte Analyzer zusätzlich auf den abweichenden Dateien jeder
    // Schattenkopie; die Herkunft wird an jeden Fund gehängt.
    let dateibasiert: Vec<(usize, &Box<dyn Analyzer>)> = analyzers
        .iter()
        .enumerate()
        .filter(|(_, a)| a.dateibasiert())
        .collect();
    for (herkunft, volume_offset, sub) in ctx.snapshot_kontexte() {
        let label = herkunft.label();
        let erstellt = match herkunft {
            Herkunft::Snapshot { erstellt, .. } => filetime_to_iso(erstellt),
            Herkunft::Live => None,
        };
        let parts: Vec<(usize, crate::Outcome, u64)> = dateibasiert
            .par_iter()
            .map(|(i, a)| {
                let start = Instant::now();
                let outcome = a.run(&sub);
                let ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
                (*i, outcome, ms)
            })
            .collect();
        for (i, outcome, ms) in parts {
            let status = &mut out.analyzers[i];
            status.funde += outcome.findings.len();
            status.warnungen += outcome.warnings.len();
            status.dauer_ms += ms;
            let domain = status.domain.clone();
            for mut f in outcome.findings {
                f.attributes.insert("herkunft".into(), label.clone());
                f.attributes
                    .insert("vss_volume_offset".into(), volume_offset.to_string());
                if let Some(e) = &erstellt {
                    f.attributes.insert("vss_erstellt_utc".into(), e.clone());
                }
                out.findings.push(f);
            }
            for w in outcome.warnings {
                out.warnings.push(format!("[{domain}] {label}: {w}"));
            }
        }
    }
    out.findings
        .sort_by(|a, b| a.domain.cmp(&b.domain).then(a.offset.cmp(&b.offset)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsindex::{FileEntry, FsIndex};
    use crate::{NtfsTarget, Outcome};

    /// Meldet je Datei im Pfad-Index einen Fund.
    struct ProDatei(bool);

    impl Analyzer for ProDatei {
        fn domain(&self) -> &str {
            "probe"
        }
        fn run(&self, ctx: &AnalysisContext<'_>) -> Outcome {
            let mut out = Outcome::default();
            for v in &ctx.volumes {
                for e in &v.files {
                    out.findings.push(Finding::new("probe", &e.path, &e.path));
                }
            }
            out
        }
        fn dateibasiert(&self) -> bool {
            self.0
        }
    }

    fn index(herkunft: Herkunft, dateien: &[&str]) -> FsIndex {
        let mut v = FsIndex::leer(
            NtfsTarget {
                index: 0,
                offset: 1024,
                size: 0,
            },
            herkunft,
        );
        v.files = dateien
            .iter()
            .map(|p| FileEntry {
                path: p.to_string(),
                mft_record: 40,
                size: 1,
                parent_record: 5,
            })
            .collect();
        v
    }

    #[test]
    fn snapshot_funde_mit_herkunft() {
        let path = std::env::temp_dir().join(format!("stratum-runner-{}", std::process::id()));
        std::fs::write(&path, [0u8; 16]).unwrap();
        let img = stratum_core::ImageReader::open(&path).unwrap();
        let mut ctx = AnalysisContext::new(&img, Vec::new());
        ctx.volumes = vec![index(Herkunft::Live, &["a.txt"])];
        ctx.snapshot_volumes = vec![
            index(
                Herkunft::Snapshot {
                    store: 1,
                    erstellt: 132_643_644_882_249_863,
                },
                &["geloescht.txt"],
            ),
            // Snapshot ohne abweichende Dateien: kein zweiter Lauf.
            index(
                Herkunft::Snapshot {
                    store: 0,
                    erstellt: 0,
                },
                &[],
            ),
        ];
        let analyzers: Vec<Box<dyn Analyzer>> =
            vec![Box::new(ProDatei(true)), Box::new(ProDatei(false))];
        let r = run_all(&ctx, &analyzers);
        std::fs::remove_file(&path).ok();
        assert_eq!(r.findings.len(), 3);
        let s: Vec<_> = r
            .findings
            .iter()
            .filter(|f| f.attributes.contains_key("herkunft"))
            .collect();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].name, "geloescht.txt");
        assert_eq!(s[0].attributes["herkunft"], "VSS#2");
        assert_eq!(s[0].attributes["vss_volume_offset"], "1024");
        assert_eq!(
            s[0].attributes["vss_erstellt_utc"],
            "2021-05-01T17:41:28.2249863Z"
        );
        assert_eq!((r.analyzers[0].funde, r.analyzers[1].funde), (2, 1));
    }
}
