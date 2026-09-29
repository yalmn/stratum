//! Extraktion einer Datei aus einem echten NTFS mit Herkunftsnachweis.
//!
//! Das Volume wird mit `mkntfs` und `ntfscp` ohne Einhängen erzeugt und hinter
//! einen MBR gelegt. Fehlen die Werkzeuge (etwa auf macOS), überspringt sich
//! der Test.

use std::io::Write;
use std::process::Command;

fn have(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .map(|o| o.status.success() || o.status.code().is_some())
        .unwrap_or(false)
}

const START: usize = 1024 * 1024;

/// MBR mit einer NTFS-Partition ab 1 MiB, dahinter das erzeugte Volume.
fn build_image(dir: &std::path::Path, inhalt: &[u8]) -> Option<std::path::PathBuf> {
    if !have("mkntfs") || !have("ntfscp") {
        return None;
    }
    let vol = dir.join("vol.ntfs");
    let groesse = 32 * 1024 * 1024;
    std::fs::write(&vol, vec![0u8; groesse]).ok()?;
    let ok = Command::new("mkntfs")
        .args(["-F", "-Q", "-p", "2048", "-L", "TEST"])
        .arg(&vol)
        .output()
        .ok()?
        .status
        .success();
    let mut quelle = tempfile::NamedTempFile::new_in(dir).ok()?;
    quelle.write_all(inhalt).ok()?;
    quelle.flush().ok()?;
    let ok = ok
        && Command::new("ntfscp")
            .arg(&vol)
            .arg(quelle.path())
            .arg("gross.bin")
            .output()
            .ok()?
            .status
            .success();
    if !ok {
        return None;
    }
    let mut img = vec![0u8; START];
    let e = 446;
    img[e + 4] = 0x07;
    img[e + 8..e + 12].copy_from_slice(&((START / 512) as u32).to_le_bytes());
    img[e + 12..e + 16].copy_from_slice(&((groesse / 512) as u32).to_le_bytes());
    img[510] = 0x55;
    img[511] = 0xAA;
    img.extend_from_slice(&std::fs::read(&vol).ok()?);
    let pfad = dir.join("test.dd");
    std::fs::write(&pfad, img).ok()?;
    Some(pfad)
}

#[test]
fn extraktion_streamt_und_belegt_den_hash() {
    let dir = tempfile::tempdir().unwrap();
    // Mehr als zwei Vorauslesefenster, damit das blockweise Lesen greift.
    let inhalt: Vec<u8> = (0..9 * 1024 * 1024u32).map(|i| (i % 241) as u8).collect();
    let Some(dd) = build_image(dir.path(), &inhalt) else {
        eprintln!("mkntfs/ntfscp nicht vorhanden, Test übersprungen");
        return;
    };
    let original = std::fs::read(&dd).unwrap();
    let ziel = dir.path().join("gross.bin");
    let output = Command::new(env!("CARGO_BIN_EXE_stratum"))
        .arg(&dd)
        .arg("--dump")
        .arg("gross.bin")
        .arg(&ziel)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read(&ziel).unwrap(), inhalt);

    let herkunft: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("gross.bin.herkunft.json")).unwrap())
            .unwrap();
    let erwartet = {
        let out = Command::new("sha256sum").arg(&ziel).output();
        out.ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| s.split_whitespace().next().map(str::to_string))
    };
    if let Some(erwartet) = erwartet {
        assert_eq!(herkunft["inhalt"]["sha256"], erwartet.as_str());
    }
    assert_eq!(herkunft["inhalt"]["geschrieben"], inhalt.len() as u64);
    assert_eq!(herkunft["inhalt"]["groesse_strom"], inhalt.len() as u64);
    assert_eq!(herkunft["quelle"]["volume_offset"], START as u64);
    assert!(herkunft["quelle"]["mft_record_offset"].is_u64());

    // Nichts wird überschrieben, das Image bleibt unverändert.
    let nochmal = Command::new(env!("CARGO_BIN_EXE_stratum"))
        .arg(&dd)
        .arg("--dump")
        .arg("gross.bin")
        .arg(&ziel)
        .output()
        .unwrap();
    assert!(!nochmal.status.success());
    assert_eq!(std::fs::read(&dd).unwrap(), original);
}
