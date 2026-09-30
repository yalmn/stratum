//! USN-Auswertung gegen einen benannten Strom in einem synthetischen NTFS.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use stratum_analysis::{write_usn_journal, AnalysisContext, NtfsTarget};
use stratum_core::ImageReader;

fn have(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .map(|output| output.status.code().is_some())
        .unwrap_or(false)
}

fn v2_record(name: &str) -> Vec<u8> {
    let utf16: Vec<u16> = name.encode_utf16().collect();
    let raw_length = 60 + utf16.len() * 2;
    let length = raw_length.div_ceil(8) * 8;
    let mut data = vec![0u8; length];
    data[0..4].copy_from_slice(&(length as u32).to_le_bytes());
    data[4..6].copy_from_slice(&2u16.to_le_bytes());
    data[8..16].copy_from_slice(&((4u64 << 48) | 42).to_le_bytes());
    data[16..24].copy_from_slice(&((3u64 << 48) | 5).to_le_bytes());
    data[24..32].copy_from_slice(&1234i64.to_le_bytes());
    data[32..40].copy_from_slice(&133_700_000_000_000_000i64.to_le_bytes());
    data[40..44].copy_from_slice(&0x8000_2100u32.to_le_bytes());
    data[56..58].copy_from_slice(&((utf16.len() * 2) as u16).to_le_bytes());
    data[58..60].copy_from_slice(&60u16.to_le_bytes());
    for (index, value) in utf16.into_iter().enumerate() {
        let start = 60 + index * 2;
        data[start..start + 2].copy_from_slice(&value.to_le_bytes());
    }
    data
}

fn build_ntfs(dir: &Path) -> Option<PathBuf> {
    if !have("mkntfs") || !have("ntfscp") {
        return None;
    }
    let image = dir.join("usn.ntfs");
    std::fs::write(&image, vec![0u8; 32 * 1024 * 1024]).ok()?;
    if !Command::new("mkntfs")
        .args(["-F", "-Q", "-L", "USNTEST"])
        .arg(&image)
        .output()
        .ok()?
        .status
        .success()
    {
        return None;
    }

    let mut empty = tempfile::NamedTempFile::new_in(dir).ok()?;
    empty.write_all(b"").ok()?;
    empty.flush().ok()?;
    let destination = "$Extend/$UsnJrnl";
    let _ = Command::new("ntfscp")
        .arg(&image)
        .arg(empty.path())
        .arg(destination)
        .output()
        .ok()?;

    let mut source = tempfile::NamedTempFile::new_in(dir).ok()?;
    let mut journal = v2_record("beispiel.txt");
    journal.resize(4096, 0);
    source.write_all(&journal).ok()?;
    source.flush().ok()?;
    if !Command::new("ntfscp")
        .args(["-N", "$J"])
        .arg(&image)
        .arg(source.path())
        .arg(destination)
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
#[ignore = "benötigt mkntfs und ntfscp; explizit auf der Linux-VM ausführen"]
fn journal_aus_benanntem_ntfs_strom() {
    let directory = tempfile::tempdir().unwrap();
    let path = build_ntfs(directory.path())
        .expect("mkntfs und ntfscp müssen benannte NTFS-Ströme schreiben können");
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
    let summary = write_usn_journal(&image, &context.volumes, &mut output).unwrap();
    assert_eq!(summary.journals, 1);
    assert_eq!(summary.datensaetze, 1);
    assert_eq!(summary.version_2, 1);
    assert_eq!(summary.erstellt, 1);
    assert_eq!(summary.umbenannt_neu, 1);

    let event: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(event["name"], "beispiel.txt");
    assert_eq!(event["mft_record"], 42);
    assert!(event["image_offset"].is_u64());
    assert_eq!(event["quelle"], "$Extend\\$UsnJrnl:$J");
    assert_eq!(
        std::fs::read(path).unwrap(),
        before,
        "Image wurde verändert"
    );
}
