//! Dateikatalog gegen ein synthetisches NTFS-Volume.
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use stratum_analysis::{write_catalog, AnalysisContext, NtfsTarget};
use stratum_core::ImageReader;

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
    std::fs::write(&img, vec![0u8; 8 * 1024 * 1024]).unwrap();
    if !Command::new("mkntfs")
        .args(["-F", "-Q"])
        .arg(&img)
        .output()
        .ok()?
        .status
        .success()
    {
        panic!("mkntfs konnte das Testvolume nicht erstellen");
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
            panic!("ntfscp konnte die Testdatei nicht kopieren");
        }
    }
    Some(img)
}

#[test]
#[ignore = "benötigt mkntfs und ntfscp; explizit auf der Linux-VM ausführen"]
fn katalog_ueber_ntfs_index() {
    let dir = tempfile::tempdir().unwrap();
    let path = build_ntfs(
        dir.path(),
        &[("klein.txt", b"hallo"), ("zweite.bin", &[7u8; 5000])],
    )
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
    let mut out = Vec::new();
    let summary = write_catalog(&image, &ctx.volumes, &mut out).unwrap();
    assert_eq!(summary.fehler, 0, "{}", String::from_utf8_lossy(&out));
    assert!(summary.verzeichnisse >= 1, "mindestens $Extend");
    let lines: Vec<serde_json::Value> = String::from_utf8(out.clone())
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len() as u64, summary.eintraege);
    let klein = lines.iter().find(|l| l["pfad"] == "klein.txt").unwrap();
    assert_eq!(klein["typ"], "datei");
    assert_eq!(klein["groesse"], 5);
    assert_eq!(klein["parent_record"], 5);
    assert!(klein["si"]["erstellt"].as_str().unwrap().ends_with('Z'));
    assert!(klein["fn"]["erstellt"].is_string());
    assert!(klein["mft_record_offset"].is_u64());
    let zweite = lines.iter().find(|l| l["pfad"] == "zweite.bin").unwrap();
    assert_eq!(zweite["groesse"], 5000);

    // Gleiches Image, gleicher Katalog.
    let mut again = Vec::new();
    write_catalog(&image, &ctx.volumes, &mut again).unwrap();
    assert_eq!(again, out);
    assert_eq!(std::fs::read(&path).unwrap(), original);
}
