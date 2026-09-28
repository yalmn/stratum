//! MFT-Volltimeline gegen ein synthetisches NTFS-Volume.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use stratum_analysis::{write_mft_timeline, AnalysisContext, NtfsTarget};
use stratum_core::ImageReader;
use stratum_ntfs::NtfsVolume;

const FILE_RECORD_FLAGS_OFFSET: u64 = 0x16;

fn have(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .map(|o| o.status.code().is_some())
        .unwrap_or(false)
}

fn build_ntfs(dir: &Path) -> Option<PathBuf> {
    if !have("mkntfs") || !have("ntfscp") {
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
    mark_deleted(&image, "geloescht.txt")?;
    Some(image)
}

fn mark_deleted(image: &Path, name: &str) -> Option<()> {
    let reader = ImageReader::open(image).ok()?;
    let mut volume = NtfsVolume::open(&reader, 0, reader.len()).ok()?;
    let record = volume
        .walk()
        .ok()?
        .into_iter()
        .find(|entry| entry.path.eq_ignore_ascii_case(name))?
        .mft_record;
    let offset = volume.record_info(record, None).ok()?.record_offset?;
    drop(volume);
    drop(reader);

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(image)
        .ok()?;
    let flags_offset = offset.checked_add(FILE_RECORD_FLAGS_OFFSET)?;
    file.seek(SeekFrom::Start(flags_offset)).ok()?;
    let mut bytes = [0u8; 2];
    file.read_exact(&mut bytes).ok()?;
    let flags = u16::from_le_bytes(bytes) & !1;
    file.seek(SeekFrom::Start(flags_offset)).ok()?;
    file.write_all(&flags.to_le_bytes()).ok()?;
    file.flush().ok()?;
    Some(())
}

#[test]
#[ignore = "benötigt mkntfs und ntfscp; explizit auf der Linux-VM ausführen"]
fn aktive_und_geloeschte_datensaetze() {
    let directory = tempfile::tempdir().unwrap();
    let path =
        build_ntfs(directory.path()).expect("mkntfs und ntfscp müssen auf der VM vorhanden sein");
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
