//! Lauf als Bibliothek: Rückmeldungen und Abbruch, ohne Datenbank.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use stratum_lauf::{analysieren, LaufFehler, Optionen, Phase, Rueckmeldung};

#[derive(Default)]
struct Mitschrift {
    meldungen: Mutex<Vec<String>>,
    phasen: Mutex<Vec<Phase>>,
    abbrechen_nach_hash: AtomicBool,
    hash_fertig: AtomicBool,
}

impl Rueckmeldung for Mitschrift {
    fn meldung(&self, text: &str) {
        self.meldungen.lock().unwrap().push(text.to_string());
    }
    fn phase_beginn(&self, phase: Phase) {
        self.phasen.lock().unwrap().push(phase);
    }
    fn fortschritt(&self, _phase: Phase, _erledigt: u64, _gesamt: u64) {}
    fn phase_ende(&self, phase: Phase) {
        if phase == Phase::Hashing {
            self.hash_fertig.store(true, Ordering::Relaxed);
        }
    }
    fn abbruch_angefordert(&self) -> bool {
        self.abbrechen_nach_hash.load(Ordering::Relaxed) && self.hash_fertig.load(Ordering::Relaxed)
    }
}

fn optionen(image: &std::path::Path) -> Optionen {
    Optionen {
        image: image.to_path_buf(),
        bdp: None,
        hashen: true,
        mitgelieferte_begriffe: true,
        begriffstabellen: Vec::new(),
        raw_sweep: false,
        onion_proxy: None,
        dpapi: None,
        firefox_passwort: None,
        katalog: None,
        datei_hashes: false,
        mft_timeline: None,
        usn_journal: None,
        modell: None,
        fall_id: None,
        gestartet: chrono::Utc::now(),
    }
}

#[test]
fn lauf_ohne_datenbank() {
    let d = tempfile::tempdir().unwrap();
    let img = d.path().join("leer.bin");
    std::fs::write(&img, vec![0u8; 1 << 16]).unwrap();
    let m = Mitschrift::default();
    let e = analysieren(&optionen(&img), None, &m).unwrap();
    assert!(e.sitzung.is_none());
    assert_eq!(e.report.image.size, 1 << 16);
    assert!(e.report.image.hashes.is_some());
    let meldungen = m.meldungen.lock().unwrap();
    assert!(meldungen[0].starts_with("[+] Integritäts-Hashes berechnet"));
    assert_eq!(
        *m.phasen.lock().unwrap(),
        [Phase::Hashing, Phase::Suche, Phase::Analyzer]
    );
}

#[test]
fn abbruch_nach_dem_hash() {
    let d = tempfile::tempdir().unwrap();
    let img = d.path().join("leer.bin");
    std::fs::write(&img, vec![0u8; 1 << 16]).unwrap();
    let modell = d.path().join("modell.json");
    let mut o = optionen(&img);
    o.modell = Some(modell.clone());
    let m = Mitschrift {
        abbrechen_nach_hash: AtomicBool::new(true),
        ..Default::default()
    };
    assert!(matches!(
        analysieren(&o, None, &m),
        Err(LaufFehler::Abgebrochen)
    ));
    // Abgebrochen vor der Partitionserkennung.
    assert!(!m
        .meldungen
        .lock()
        .unwrap()
        .iter()
        .any(|t| t.contains("Partition")));
}

#[test]
fn vorhandene_ausgabe_wird_nicht_ueberschrieben() {
    let d = tempfile::tempdir().unwrap();
    let img = d.path().join("leer.bin");
    std::fs::write(&img, vec![0u8; 4096]).unwrap();
    let katalog = d.path().join("katalog.jsonl");
    std::fs::write(&katalog, b"alt").unwrap();
    let mut o = optionen(&img);
    o.katalog = Some(katalog.clone());
    let f = analysieren(&o, None, &Mitschrift::default())
        .err()
        .expect("muss scheitern");
    assert!(f.to_string().contains("existiert bereits"), "{f}");
    assert_eq!(std::fs::read(&katalog).unwrap(), b"alt");
}
