//! `Zone.Identifier` aus einem benannten Strom in einem synthetischen NTFS.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use stratum_analysis::{AnalysisContext, Analyzer, NtfsTarget, ZoneIdentifierAnalyzer};
use stratum_core::{hash_bytes, ImageReader};
use stratum_ntfs::NtfsVolume;

const ZONE: &[u8] = b"[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://example.test/start\r\nHostUrl=https://example.test/download.exe\r\n";

fn have(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .map(|output| output.status.code().is_some())
        .unwrap_or(false)
}

fn copy(dir: &Path, image: &Path, destination: &str, stream: Option<&str>, data: &[u8]) {
    let mut source = tempfile::NamedTempFile::new_in(dir).unwrap();
    source.write_all(data).unwrap();
    source.flush().unwrap();
    let mut command = Command::new("ntfscp");
    if let Some(stream) = stream {
        command.args(["-N", stream]);
    }
    let output = command
        .arg(image)
        .arg(source.path())
        .arg(destination)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "ntfscp fehlgeschlagen: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn build_ntfs(dir: &Path) -> Option<PathBuf> {
    if !have("mkntfs") || !have("ntfscp") {
        return None;
    }
    let image = dir.join("zone.ntfs");
    std::fs::write(&image, vec![0u8; 16 * 1024 * 1024]).unwrap();
    let output = Command::new("mkntfs")
        .args(["-F", "-Q", "-L", "ZONETEST"])
        .arg(&image)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "mkntfs fehlgeschlagen: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    copy(dir, &image, "download.exe", None, b"MZ-Testdatei");
    copy(dir, &image, "download.exe", Some("Zone.Identifier"), ZONE);
    Some(image)
}

#[test]
#[ignore = "benötigt mkntfs und ntfscp; explizit auf der Linux-VM ausführen"]
fn zone_identifier_aus_benanntem_strom() {
    let directory = tempfile::tempdir().unwrap();
    let path = build_ntfs(directory.path())
        .expect("mkntfs und ntfscp müssen benannte NTFS-Ströme schreiben können");
    let before = std::fs::read(&path).unwrap();
    let image = ImageReader::open(&path).unwrap();

    let mut volume = NtfsVolume::open(&image, 0, image.len()).unwrap();
    let stream = volume
        .read_stream("download.exe", "Zone.Identifier")
        .unwrap()
        .expect("Zone.Identifier fehlt");
    assert_eq!(stream.data, ZONE);
    assert_eq!(stream.meta.size, ZONE.len() as u64);

    let context = AnalysisContext::build(
        &image,
        vec![NtfsTarget {
            index: 0,
            offset: 0,
            size: image.len(),
        }],
    );
    let output = ZoneIdentifierAnalyzer.run(&context);
    assert!(output.warnings.is_empty(), "{:?}", output.warnings);
    assert_eq!(output.findings.len(), 1);
    let finding = &output.findings[0];
    assert_eq!(finding.domain, "dateiherkunft");
    assert_eq!(finding.source, "download.exe:Zone.Identifier:$DATA");
    assert!(finding.offset.is_some());
    assert_eq!(finding.attributes["zone_id"], "3");
    assert_eq!(finding.attributes["zone_name"], "internet");
    assert_eq!(
        finding.attributes["host_url"],
        "https://example.test/download.exe"
    );
    assert_eq!(finding.attributes["auswertung_status"], "gelesen");
    assert_eq!(finding.attributes["volume_offset"], "0");
    assert_eq!(
        finding.attributes["mft_record_offset"],
        finding.offset.unwrap().to_string()
    );
    let hashes = hash_bytes(ZONE);
    assert_eq!(finding.attributes["strom_sha256"], hashes.sha256);
    assert_eq!(finding.attributes["strom_blake3"], hashes.blake3);
    assert_eq!(
        std::fs::read(path).unwrap(),
        before,
        "Image wurde verändert"
    );
}
