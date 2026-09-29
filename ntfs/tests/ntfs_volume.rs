//! Integrationstest gegen ein echtes NTFS-Volume.
//!
//! Das Volume wird zur Laufzeit mit `mkntfs` erzeugt und mit `ntfscp` befüllt,
//! beides ohne Root und ohne Einhängen ins Host-Dateisystem. Fehlen die
//! Werkzeuge (z. B. auf einem macOS-Entwicklungsrechner), überspringt sich der
//! Test mit einer Meldung. Auf der forensischen Linux-VM (Paket `ntfs-3g`)
//! läuft er vollständig.

use std::io::Write;
use std::path::Path;
use std::process::Command;

use stratum_core::ImageReader;
use stratum_ntfs::NtfsVolume;

fn have(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .map(|o| o.status.success() || o.status.code().is_some())
        .unwrap_or(false)
}

/// Legt eine leere NTFS-Datei an und kopiert `files` (Zielpfad, Inhalt) hinein.
fn build_ntfs(dir: &Path, files: &[(&str, &[u8])]) -> Option<std::path::PathBuf> {
    if !have("mkntfs") || !have("ntfscp") {
        return None;
    }
    let img = dir.join("vol.ntfs");
    // 8 MiB reichen für ein gültiges NTFS-Volume.
    let size = 8 * 1024 * 1024;
    std::fs::write(&img, vec![0u8; size]).ok()?;

    let ok = Command::new("mkntfs")
        .args(["-F", "-Q", "-L", "TESTVOL"])
        .arg(&img)
        .output()
        .ok()?
        .status
        .success();
    if !ok {
        return None;
    }

    for (name, content) in files {
        let mut src = tempfile::NamedTempFile::new_in(dir).ok()?;
        src.write_all(content).ok()?;
        src.flush().ok()?;
        let ok = Command::new("ntfscp")
            .arg(&img)
            .arg(src.path())
            .arg(name)
            .output()
            .ok()?
            .status
            .success();
        if !ok {
            return None;
        }
    }
    Some(img)
}

#[test]
fn liest_datei_und_verzeichnis() {
    let dir = tempfile::tempdir().unwrap();
    let hive = b"regf-platzhalter-inhalt fuer den test";
    // Grosse Datei (2 MiB, nicht-resident, mehrere Datenlaeufe) mit klarem
    // Muster, um das laufbasierte Lesen zu pruefen.
    let gross: Vec<u8> = (0..2 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect();
    let files: &[(&str, &[u8])] = &[
        ("SYSTEM", hive.as_slice()),
        ("notiz.txt", b"hallo welt"),
        ("gross.bin", gross.as_slice()),
    ];

    let Some(img_path) = build_ntfs(dir.path(), files) else {
        eprintln!("mkntfs/ntfscp nicht vorhanden, Test übersprungen");
        return;
    };

    let img = ImageReader::open(&img_path).unwrap();
    // Das Volume beginnt bei Offset 0 (kein Partitionsschema um das Volume).
    let mut vol = NtfsVolume::open(&img, 0, img.len()).unwrap();

    assert_eq!(vol.label().as_deref(), Some("TESTVOL"));
    assert!(vol.cluster_size() > 0);

    // Datei lesen, groß-/kleinunabhängig, mit Backslash-Trenner.
    let f = vol.read_file("\\system").unwrap().expect("SYSTEM fehlt");
    assert_eq!(f.data, hive);
    assert_eq!(f.meta.size, hive.len() as u64);
    assert!(f.meta.mft_record >= 24, "Nutzdateien liegen ab Record 24");
    assert!(f.meta.created > 0);

    let n = vol.read_file("notiz.txt").unwrap().unwrap();
    assert_eq!(n.data, b"hallo welt");
    assert_eq!(n.meta.size, n.data.len() as u64);

    // Grosse, nicht-residente Datei byte-genau zuruecklesen (prueft die
    // Zusammensetzung der Datenlaeufe).
    let g = vol
        .read_file("gross.bin")
        .unwrap()
        .expect("gross.bin fehlt");
    assert_eq!(g.data.len(), gross.len(), "Laenge muss exakt stimmen");
    assert_eq!(g.meta.size, gross.len() as u64);
    assert_eq!(g.data, gross, "Inhalt muss byte-genau stimmen");

    // Nicht vorhanden.
    assert!(vol.read_file("gibtsnicht").unwrap().is_none());
    assert!(!vol.exists("kein/pfad").unwrap());
    assert!(vol.exists("SYSTEM").unwrap());

    // Wurzelverzeichnis listen: die kopierten Dateien müssen auftauchen.
    let root = vol.list_dir("").unwrap().unwrap();
    let names: Vec<&str> = root.iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&"SYSTEM"), "gefunden: {names:?}");
    assert!(names.contains(&"notiz.txt"), "gefunden: {names:?}");

    // Vollständiger Durchlauf und Lesen über die MFT-Nummer.
    let report = vol.walk_report().unwrap();
    assert!(report.skipped.is_empty(), "{:?}", report.skipped);
    assert!(!report.truncated);
    assert_eq!(report.depth_limited, 0);
    let walked = vol.walk().unwrap();
    assert_eq!(walked, report.entries);
    let notiz = walked
        .iter()
        .find(|e| e.path.eq_ignore_ascii_case("notiz.txt"))
        .expect("notiz.txt im Walk");
    assert!(!notiz.is_directory);
    let by_rec = vol
        .read_file_by_record(notiz.mft_record, &notiz.path)
        .unwrap()
        .unwrap();
    assert_eq!(by_rec.data, b"hallo welt");

    // Metadaten ohne Inhalt: Wurzel (Record 5) als Elternverzeichnis, beide
    // Zeitquellen gesetzt, Stromlängen passend zu den kopierten Dateien.
    assert_eq!(notiz.parent_record, 5);
    let info = vol.record_info(notiz.mft_record, Some(5)).unwrap();
    assert_eq!(info.mft_record, notiz.mft_record);
    assert!(info.in_use);
    assert!(!info.is_directory);
    assert_eq!(info.data_size, Some(10));
    assert!(info.streams.is_empty());
    assert!(info
        .si_times
        .is_some_and(|t| t.created > 0 && t.modified > 0));
    assert!(info.fn_times.is_some_and(|t| t.created > 0));
    assert!(info.file_names.iter().any(|n| {
        n.name.eq_ignore_ascii_case("notiz.txt") && n.parent_record == 5 && n.parent_sequence > 0
    }));
    assert!(info.record_offset.is_some());
    assert!(vol.mft_record_count().unwrap() > notiz.mft_record);
    let gross_eintrag = walked
        .iter()
        .find(|e| e.path.eq_ignore_ascii_case("gross.bin"))
        .expect("gross.bin im Walk");
    let info = vol
        .record_info(gross_eintrag.mft_record, Some(gross_eintrag.parent_record))
        .unwrap();
    assert_eq!(info.data_size, Some(gross.len() as u64));
    // Verzeichnis: Wurzel selbst.
    let wurzel = vol.record_info(5, None).unwrap();
    assert!(wurzel.is_directory);
    assert_eq!(wurzel.data_size, None);
}
