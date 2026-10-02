//! Rückmeldung eines Laufs auf der Konsole: Meldungen auf stderr,
//! Fortschrittsbalken für Hash und Suche, Zwischenstände des Katalogs.

use std::sync::Mutex;
use std::time::Instant;

use indicatif::{ProgressBar, ProgressStyle};
use stratum_lauf::{Phase, Rueckmeldung};

/// Fortschrittsbalken in Bytes. Zeichnet auf stderr und blendet sich aus, wenn
/// stderr kein Terminal ist, damit der JSON-Report auf stdout sauber bleibt.
pub fn bytes_bar(len: u64, label: &str) -> ProgressBar {
    let pb = ProgressBar::new(len);
    let tmpl = format!(
        "  {label:<8}[{{bar:40}}] {{bytes}}/{{total_bytes}} ({{bytes_per_sec}}, ETA {{eta}})"
    );
    if let Ok(style) = ProgressStyle::with_template(&tmpl) {
        pb.set_style(style.progress_chars("=>-"));
    }
    pb
}

/// Konsole als Rückmeldung.
#[derive(Default)]
pub struct Konsole {
    hashing: Mutex<Option<ProgressBar>>,
    suche: Mutex<Option<ProgressBar>>,
    katalog_start: Mutex<Option<Instant>>,
}

fn balken(platz: &Mutex<Option<ProgressBar>>) -> std::sync::MutexGuard<'_, Option<ProgressBar>> {
    platz.lock().unwrap_or_else(|v| v.into_inner())
}

impl Rueckmeldung for Konsole {
    fn meldung(&self, text: &str) {
        eprintln!("{text}");
    }

    fn phase_beginn(&self, phase: Phase) {
        match phase {
            Phase::Hashing => *balken(&self.hashing) = Some(bytes_bar(0, "Hashing")),
            Phase::Suche => *balken(&self.suche) = Some(bytes_bar(0, "Suche")),
            Phase::Katalog => {
                *self.katalog_start.lock().unwrap_or_else(|v| v.into_inner()) =
                    Some(Instant::now());
            }
            Phase::Analyzer => {}
        }
    }

    fn fortschritt(&self, phase: Phase, erledigt: u64, gesamt: u64) {
        match phase {
            Phase::Hashing | Phase::Suche => {
                let platz = if phase == Phase::Hashing {
                    &self.hashing
                } else {
                    &self.suche
                };
                if let Some(pb) = balken(platz).as_ref() {
                    pb.set_length(gesamt);
                    pb.set_position(erledigt);
                }
            }
            Phase::Katalog => {
                let s = self
                    .katalog_start
                    .lock()
                    .unwrap_or_else(|v| v.into_inner())
                    .map(|t| t.elapsed().as_secs())
                    .unwrap_or(0);
                eprintln!("[*] Dateikatalog: {erledigt} von {gesamt} Einträgen ({s} s)");
            }
            Phase::Analyzer => {}
        }
    }

    fn phase_ende(&self, phase: Phase) {
        let platz = match phase {
            Phase::Hashing => &self.hashing,
            Phase::Suche => &self.suche,
            _ => return,
        };
        if let Some(pb) = balken(platz).take() {
            pb.finish_and_clear();
        }
    }
}
