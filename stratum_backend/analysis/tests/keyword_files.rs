//! Datei-gescopte Keyword-Suche gegen ein echtes NTFS-Volume.
//!
//! Baut per `mkntfs` + `ntfscp` (ohne Root, ohne Mount) ein kleines NTFS mit
//! einer Textdatei und prüft, dass der Treffer den echten Dateipfad trägt.
//! Fehlen die Werkzeuge (z. B. auf macOS), überspringt sich der Test.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use stratum_analysis::{run_all, AnalysisContext, Analyzer, KeywordAnalyzer, NtfsTarget};
use stratum_core::ImageReader;
use stratum_search::TermTable;

const TABLE: &str = r#"
[meta]
name = "Test"
version = 1
[[kategorie]]
id = "darknet"
begriffe = ["torrc"]
[[kategorie]]
id = "zugangsdaten"
modus = "paar"
abstand_bytes = 64
links = ["user"]
rechts = ["pw"]
"#;

fn have(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .map(|o| o.status.code().is_some())
        .unwrap_or(false)
}

fn build_ntfs(dir: &Path, files: &[(&str, &[u8])]) -> Option<PathBuf> {
    if !have("mkntfs") || !have("ntfscp") {
        return None;
    }
    let img = dir.join("vol.ntfs");
    std::fs::write(&img, vec![0u8; 8 * 1024 * 1024]).ok()?;
    if !Command::new("mkntfs")
        .args(["-F", "-Q"])
        .arg(&img)
        .output()
        .ok()?
        .status
        .success()
    {
        return None;
    }
    for (name, content) in files {
        let mut src = tempfile::NamedTempFile::new_in(dir).ok()?;
        src.write_all(content).ok()?;
        src.flush().ok()?;
        if !Command::new("ntfscp")
            .arg(&img)
            .arg(src.path())
            .arg(name)
            .output()
            .ok()?
            .status
            .success()
        {
            return None;
        }
    }
    Some(img)
}

#[test]
fn treffer_tragen_den_dateipfad() {
    let dir = tempfile::tempdir().unwrap();
    let files: &[(&str, &[u8])] = &[
        (
            "notiz.txt",
            b"zugang user=alice pw=Sommer2024 und torrc hinweis",
        ),
        (
            "bild.png",
            b"\x89PNG\r\n\x1a\n binaerer inhalt user=x pw=y torrc",
        ),
    ];
    let Some(img_path) = build_ntfs(dir.path(), files) else {
        eprintln!("mkntfs/ntfscp nicht vorhanden, Test übersprungen");
        return;
    };

    let img = ImageReader::open(&img_path).unwrap();
    let ctx = AnalysisContext::build(
        &img,
        vec![NtfsTarget {
            index: 0,
            offset: 0,
            size: img.len(),
        }],
    );
    assert!(!ctx.volumes.is_empty(), "Pfad-Index muss existieren");

    let analyzers: Vec<Box<dyn Analyzer>> = vec![Box::new(KeywordAnalyzer::from_table(
        &TermTable::from_str(TABLE).unwrap(),
    ))];
    let r = run_all(&ctx, &analyzers);

    // torrc muss aus notiz.txt kommen, mit echtem Pfad; die .png wird als
    // Nicht-Textdatei nicht durchsucht.
    let torrc: Vec<_> = r.findings.iter().filter(|f| f.name == "torrc").collect();
    assert_eq!(torrc.len(), 1, "nur die Textdatei zaehlt: {:?}", r.findings);
    assert_eq!(torrc[0].source, "notiz.txt");
    assert!(
        torrc[0].attributes.contains_key("mft_record"),
        "MFT-Nummer als Herkunft"
    );

    assert!(r
        .findings
        .iter()
        .any(|f| f.domain == "zugangsdaten" && f.source == "notiz.txt"));
}
