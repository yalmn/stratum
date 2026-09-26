//! Integration des PowerShell-Analyzers mit einem synthetischen NTFS-Volume.
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use stratum_analysis::{AnalysisContext, Analyzer, NtfsTarget, PowerShellHistoryAnalyzer};
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
fn powershell_ueber_ntfs_index() {
    let dir = tempfile::tempdir().unwrap();
    let path = build_ntfs(
        dir.path(),
        &[
            ("ConsoleHost_history.txt", b"Get-Date\r\nGet-Process\n"),
            ("browser_history.txt", b"NICHT AUSWERTEN"),
        ],
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
    let out = PowerShellHistoryAnalyzer.run(&ctx);
    assert!(out.warnings.is_empty(), "{:?}", out.warnings);
    assert_eq!(out.findings.len(), 2);
    for f in out.findings {
        assert_eq!(f.source, "ConsoleHost_history.txt");
        assert!(f.attributes.contains_key("mft_record"));
        assert_eq!(f.attributes["volume_offset"], "0");
    }
    assert_eq!(std::fs::read(&path).unwrap(), original);
}
