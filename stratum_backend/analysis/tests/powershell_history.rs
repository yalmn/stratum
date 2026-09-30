//! Herkunft und unveränderte Quelldaten bei der Auswertung eines synthetischen Mini-Images.

use std::io::Write;

use stratum_analysis::{build_timeline, parse_powershell_history};
use stratum_core::ImageReader;

#[test]
fn verlauf_aus_mini_image_behaelt_dateipositionen() {
    let history = "Get-Date\r\nWrite-Output 'Grüße'\r\n".as_bytes();
    let mut bytes = vec![0u8; 4096];
    bytes[512..512 + history.len()].copy_from_slice(history);
    let mut fixture = tempfile::NamedTempFile::new().unwrap();
    fixture.write_all(&bytes).unwrap();
    fixture.flush().unwrap();
    let image = ImageReader::open(fixture.path()).unwrap();
    let result = parse_powershell_history(
        image.read_at(512, history.len()).unwrap(),
        "Users\\alice\\ConsoleHost_history.txt",
    );
    assert!(result.warnings.is_empty());
    assert_eq!(result.findings.len(), 2);
    assert!(build_timeline(&result.findings).is_empty());
    for f in &result.findings {
        let offset: u64 = f.attributes["datei_offset"].parse().unwrap();
        let length: usize = f.attributes["datei_laenge"].parse().unwrap();
        assert_eq!(
            image.read_at(512 + offset, length).unwrap(),
            f.attributes["eingabe"].as_bytes()
        );
        assert!(
            f.offset.is_none(),
            "Dateiposition darf kein Image-Offset sein"
        );
    }
    let report = serde_json::to_value(&result.findings).unwrap();
    assert_eq!(report[1]["attributes"]["profil"], "alice");
    assert_eq!(std::fs::read(fixture.path()).unwrap(), bytes);
}
