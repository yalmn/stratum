//! SRUM-Analyzer mit einer synthetischen SRUDB.dat in einem synthetischen NTFS.

#[path = "../../ese/tests/common/bau.rs"]
mod bau;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use bau::{datenbank, Spalte, Tabelle};
use stratum_analysis::{AnalysisContext, Analyzer, NtfsTarget, SrumAnalyzer};
use stratum_core::ImageReader;

fn have(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .map(|o| o.status.code().is_some())
        .unwrap_or(false)
}

fn mini_srudb() -> Vec<u8> {
    let name: Vec<u8> = "Dnscache\0"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let idmap = Tabelle {
        name: "SruDbIdMapTable",
        spalten: vec![
            Spalte::neu(1, "IdType", 2),
            Spalte::neu(2, "IdIndex", 4),
            Spalte::neu(256, "IdBlob", 11),
        ],
        zeilen: vec![
            vec![(1, vec![1]), (2, 5i32.to_le_bytes().to_vec()), (256, name)],
            vec![
                (1, vec![3]),
                (2, 7i32.to_le_bytes().to_vec()),
                (256, vec![1, 1, 0, 0, 0, 0, 0, 5, 20, 0, 0, 0]),
            ],
        ],
    };
    // 2026-04-18 09:00:00 UTC als OLE-Datum.
    let ts = (46_130.0f64 + 9.0 / 24.0).to_bits().to_le_bytes().to_vec();
    let netz = Tabelle {
        name: "{973F5D5C-1D90-4944-BE8E-24B94231A174}",
        spalten: vec![
            Spalte::neu(1, "AutoIncId", 4),
            Spalte::neu(2, "TimeStamp", 8),
            Spalte::neu(3, "AppId", 4),
            Spalte::neu(4, "UserId", 4),
            Spalte::neu(5, "BytesSent", 15),
        ],
        zeilen: (1..=3i32)
            .map(|i| {
                vec![
                    (1, i.to_le_bytes().to_vec()),
                    (2, ts.clone()),
                    (3, 5i32.to_le_bytes().to_vec()),
                    (4, 7i32.to_le_bytes().to_vec()),
                    (5, (i64::from(i) * 1000).to_le_bytes().to_vec()),
                ]
            })
            .collect(),
    };
    datenbank(&[idmap, netz], 3)
}

fn build_ntfs(dir: &Path, name: &str, content: &[u8]) -> Option<PathBuf> {
    if !have("mkntfs") || !have("ntfscp") {
        return None;
    }
    let img = dir.join("srum.ntfs");
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
fn srum_ueber_ntfs_index() {
    let dir = tempfile::tempdir().unwrap();
    let db = mini_srudb();
    let path = build_ntfs(dir.path(), "SRUDB.dat", &db)
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
    let out = SrumAnalyzer.run(&ctx);
    assert!(out.warnings.is_empty(), "{:?}", out.warnings);
    assert_eq!(out.findings.len(), 4);
    for f in &out.findings[..3] {
        assert_eq!(f.source, "SRUDB.dat");
        assert_eq!(f.name, "Dnscache");
        assert_eq!(f.attributes["konto"], "S-1-5-20");
        assert_eq!(
            f.attributes["zeitpunkt_utc"],
            "2026-04-18T09:00:00.0000000Z"
        );
        // Image-Offset zeigt auf dieselben Bytes wie der Datei-Offset.
        let image_at = f.offset.expect("Image-Offset fehlt") as usize;
        let datei_at: usize = f.attributes["datei_offset"].parse().unwrap();
        assert_eq!(
            original[image_at..image_at + 16],
            db[datei_at..datei_at + 16]
        );
    }
    assert_eq!(out.findings[2].attributes["BytesSent"], "3000");
    assert_eq!(out.findings[3].attributes["datensaetze"], "3");
    assert_eq!(std::fs::read(&path).unwrap(), original);
}
