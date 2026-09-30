//! WebCache-Analyzer mit einer synthetischen WebCacheV01.dat in einem
//! synthetischen NTFS.

#[path = "../../ese/tests/common/bau.rs"]
mod bau;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use bau::{datenbank, Spalte, Tabelle};
use stratum_analysis::{AnalysisContext, Analyzer, NtfsTarget, WebCacheAnalyzer};
use stratum_core::ImageReader;

fn have(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .map(|o| o.status.code().is_some())
        .unwrap_or(false)
}

fn u16text(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn utf16_spalte(id: u16, name: &'static str, typ: u32) -> Spalte {
    Spalte {
        codepage: 1200,
        ..Spalte::neu(id, name, typ)
    }
}

fn mini_webcache() -> Vec<u8> {
    let containers = Tabelle {
        name: "Containers",
        spalten: vec![
            Spalte::neu(1, "ContainerId", 15),
            utf16_spalte(128, "Name", 10),
            utf16_spalte(256, "Directory", 12),
            utf16_spalte(257, "SecureDirectories", 12),
        ],
        zeilen: vec![vec![
            (1, 3i64.to_le_bytes().to_vec()),
            (128, u16text("Content")),
            (256, u16text("C:\\Users\\ich\\INetCache\\IE\\")),
            (257, u16text("AAAAAAAA")),
        ]],
    };
    // 2026-04-18T09:44:44.6680107Z
    let zeit = 134_209_790_846_680_107i64.to_le_bytes().to_vec();
    let cache = Tabelle {
        name: "Container_3",
        spalten: vec![
            Spalte::neu(1, "EntryId", 15),
            Spalte::neu(2, "SecureDirectory", 14),
            Spalte::neu(3, "AccessedTime", 15),
            utf16_spalte(256, "Url", 12),
            utf16_spalte(257, "Filename", 12),
        ],
        zeilen: (1..=3i64)
            .map(|i| {
                vec![
                    (1, i.to_le_bytes().to_vec()),
                    (2, 1u32.to_le_bytes().to_vec()),
                    (3, zeit.clone()),
                    (256, u16text(&format!("https://example.test/{i}"))),
                    (257, u16text(&format!("{i}[1]"))),
                ]
            })
            .collect(),
    };
    datenbank(&[containers, cache], 3)
}

fn build_ntfs(dir: &Path, name: &str, content: &[u8]) -> Option<PathBuf> {
    if !have("mkntfs") || !have("ntfscp") {
        return None;
    }
    let img = dir.join("webcache.ntfs");
    std::fs::write(&img, vec![0u8; 8 * 1024 * 1024]).unwrap();
    assert!(
        Command::new("mkntfs")
            .args(["-F", "-Q"])
            .arg(&img)
            .output()
            .unwrap()
            .status
            .success(),
        "mkntfs konnte das Testvolume nicht erstellen"
    );
    let mut src = tempfile::NamedTempFile::new_in(dir).unwrap();
    src.write_all(content).unwrap();
    src.flush().unwrap();
    assert!(
        Command::new("ntfscp")
            .arg(&img)
            .arg(src.path())
            .arg(name)
            .output()
            .unwrap()
            .status
            .success(),
        "ntfscp konnte die Testdatei nicht kopieren"
    );
    Some(img)
}

#[test]
#[ignore = "benötigt mkntfs und ntfscp; explizit auf der Linux-VM ausführen"]
fn webcache_ueber_ntfs_index() {
    let dir = tempfile::tempdir().unwrap();
    let db = mini_webcache();
    let path = build_ntfs(dir.path(), "WebCacheV01.dat", &db)
        .expect("mkntfs und ntfscp müssen für diesen Integrationstest installiert sein");
    let original = std::fs::read(&path).unwrap();
    let image = ImageReader::open(&path).unwrap();
    let ctx = AnalysisContext::build(
        &image,
        vec![NtfsTarget {
            index: 0,
            offset: 0,
            size: image.len(),
        }],
    );
    let out = WebCacheAnalyzer.run(&ctx);
    assert!(out.warnings.is_empty(), "{:?}", out.warnings);
    // 1 Container, 3 Einträge, Übersicht.
    assert_eq!(out.findings.len(), 5);
    let eintraege: Vec<_> = out
        .findings
        .iter()
        .filter(|f| f.attributes["art"] == "webcache_eintrag")
        .collect();
    assert_eq!(eintraege.len(), 3);
    for f in eintraege {
        assert_eq!(f.source, "WebCacheV01.dat");
        assert!(f.name.starts_with("https://example.test/"));
        assert_eq!(f.attributes["letzter_zugriff_unix"], "1776505484");
        // Die Cache-Datei liegt nicht im Testvolume.
        assert_eq!(f.attributes["cache_datei_im_volume"], "nein");
        assert!(f.attributes["cache_datei"].contains("\\AAAAAAAA\\"));
        // Image-Offset zeigt auf dieselben Bytes wie der Datei-Offset.
        let image_at = f.offset.expect("Image-Offset fehlt") as usize;
        let datei_at: usize = f.attributes["datei_offset"].parse().unwrap();
        assert_eq!(
            original[image_at..image_at + 16],
            db[datei_at..datei_at + 16]
        );
    }
    assert_eq!(out.findings[4].attributes["datensaetze"], "4");
    assert_eq!(std::fs::read(&path).unwrap(), original);
}
