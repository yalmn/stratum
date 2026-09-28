//! MFT-Volltimeline gegen ein synthetisches NTFS-Volume.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use stratum_analysis::{write_mft_timeline, AnalysisContext, NtfsTarget};
use stratum_core::ImageReader;

fn have(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .map(|o| o.status.code().is_some())
        .unwrap_or(false)
}

fn build_ntfs(dir: &Path) -> Option<PathBuf> {
    if !have("mkntfs") || !have("ntfscp") || !have("ntfsrm") {
        return None;
    }
    let image = dir.join("mft-timeline.ntfs");
    std::fs::write(&image, vec![0u8; 16 * 1024 * 1024]).ok()?;
    if !Command::new("mkntfs")
        .args(["-F", "-Q", "-L", "MFTZEIT"])
        .arg(&image)
        .output()
        .ok()?
        .status
        .success()
    {
        return None;
    }
    for name in ["bleibt.txt", "geloescht.txt"] {
        let mut source = tempfile::NamedTempFile::new_in(dir).ok()?;
        source.write_all(name.as_bytes()).ok()?;
        source.flush().ok()?;
        if !Command::new("ntfscp")
            .arg(&image)
            .arg(source.path())
            .arg(name)
            .output()
            .ok()?
            .status
            .success()
        {
            return None;
        }
    }
    if !Command::new("ntfsrm")
        .arg(&image)
        .arg("geloescht.txt")
        .output()
        .ok()?
        .status
        .success()
    {
        return None;
    }
    Some(image)
}

#[test]
#[ignore = "benötigt mkntfs, ntfscp und ntfsrm; explizit auf der Linux-VM ausführen"]
fn aktive_und_geloeschte_datensaetze() {
    let directory = tempfile::tempdir().unwrap();
    let path = build_ntfs(directory.path())
        .expect("mkntfs, ntfscp und ntfsrm müssen auf der VM vorhanden sein");
    let before = std::fs::read(&path).unwrap();
    let image = ImageReader::open(&path).unwrap();
    let context = AnalysisContext::build(
        &image,
        vec![NtfsTarget {
            index: 0,
            offset: 0,
            size: image.len(),
        }],
    );
    let mut output = Vec::new();
    let summary = write_mft_timeline(&image, &context.volumes, &mut output).unwrap();
    assert!(summary.datensaetze >= summary.lesbar);
    assert_eq!(summary.lesbar, summary.belegt + summary.geloescht);
    assert!(summary.geloescht >= 1, "{summary:?}");
    assert!(summary.ereignisse > 0);
    assert_eq!(
        summary.ereignisse,
        summary.si_ereignisse + summary.fn_ereignisse
    );

    let lines: Vec<serde_json::Value> = String::from_utf8(output)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(lines.len() as u64, summary.ereignisse);
    assert!(lines
        .windows(2)
        .all(|w| w[0]["filetime"].as_u64() <= w[1]["filetime"].as_u64()));
    let deleted: Vec<_> = lines
        .iter()
        .filter(|line| line["status"] == "geloescht" && line["name"] == "geloescht.txt")
        .collect();
    assert!(!deleted.is_empty(), "gelöschter Dateiname fehlt");
    for event in deleted {
        assert!(event["mft_record"].is_u64());
        assert!(event["sequenz"].is_u64());
        assert!(event["mft_record_offset"].is_u64());
        assert!(event["zeit_utc"].as_str().unwrap().ends_with('Z'));
        assert!(matches!(
            event["macb"].as_str(),
            Some("M" | "A" | "C" | "B")
        ));
        assert_eq!(event["quelle"], "$FILE_NAME");
    }
    assert_eq!(
        std::fs::read(path).unwrap(),
        before,
        "Image wurde verändert"
    );
}
