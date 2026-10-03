//! Gezielter Abruf einzelner Werte, ohne vollständigen Analyselauf:
//! ein Rohfund aus einem Report (`--fund`) und ein System-Masterkey aus dem
//! Image (`--masterkey`).

use std::path::Path;

use anyhow::{bail, Result};
use stratum_analysis::{masterkey_abrufen, AnalysisContext, NtfsTarget};
use stratum_core::ImageReader;

/// Gibt den Rohfund mit dieser Kennung aus dem Report aus. Die Kennung wird
/// aus dem Inhalt nachgerechnet; stimmt sie nicht, ist der Report verändert
/// oder die Kennung falsch, und der Abruf schlägt fehl.
pub fn fund(report: &Path, id: &str) -> Result<()> {
    let r = stratum_lauf::rohfund::lesen(report, id, None)?;
    eprintln!(
        "[+] Fund {id} aus {} (SHA-256 {}), Kennung aus dem Inhalt bestätigt",
        report.display(),
        r.report_sha256
    );
    println!("{}", serde_json::to_string_pretty(&r.fund)?);
    Ok(())
}

/// Entschlüsselt die System-Masterkeys mit dieser GUID und gibt sie mit
/// Fundstelle und verwendetem Schlüssel aus.
pub fn masterkey(img: &ImageReader, targets: Vec<NtfsTarget>, guid: &str) -> Result<()> {
    eprintln!("[*] Lese Registry-Hives und baue Pfad-Index ...");
    let ctx = AnalysisContext::build(img, targets);
    let mut warnungen = Vec::new();
    let treffer = masterkey_abrufen(&ctx, guid, &mut warnungen);
    for w in &warnungen {
        eprintln!("[!] {w}");
    }
    if treffer.is_empty() {
        bail!("Kein System-Masterkey mit GUID {guid} gefunden");
    }
    let ausgabe: Vec<_> = treffer
        .iter()
        .map(|m| {
            serde_json::json!({
                "guid": m.guid,
                "pfad": m.pfad,
                "herkunft": m.herkunft,
                "volume_offset": m.volume_offset,
                "mft_record": m.mft_record,
                "mft_record_offset": m.mft_record_offset,
                "entschluesselt": m.masterkey.is_some(),
                "entschluesselt_mit": m.entschluesselt_mit(),
                "masterkey_hex": m.masterkey_hex(),
            })
        })
        .collect();
    println!("{}", serde_json::to_string_pretty(&ausgabe)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use stratum_analysis::{assign_ids, Finding};

    fn report_mit(f: &Finding, name: &str) -> std::path::PathBuf {
        let p =
            std::env::temp_dir().join(format!("stratum_abruf_{}_{name}.json", std::process::id()));
        let v = serde_json::json!({"findings": [f]});
        std::fs::write(&p, serde_json::to_vec(&v).unwrap()).unwrap();
        p
    }

    #[test]
    fn fund_mit_kennung_und_gegenprobe() {
        let mut f = [Finding::new("usb", "Stick", "SYSTEM").with("serie", "1")];
        assign_ids(&mut f);
        let id = f[0].id.clone();

        let echt = report_mit(&f[0], "echt");
        assert!(fund(&echt, &id).is_ok());
        assert!(fund(&echt, "0000000000000000").is_err());

        // Inhalt nachträglich geändert, Kennung gleich: wird erkannt.
        let mut veraendert = f[0].clone();
        veraendert.attributes.insert("serie".into(), "2".into());
        let falsch = report_mit(&veraendert, "veraendert");
        let fehler = fund(&falsch, &id).unwrap_err().to_string();
        assert!(fehler.contains("passt nicht zum Inhalt"), "{fehler}");

        let _ = std::fs::remove_file(echt);
        let _ = std::fs::remove_file(falsch);
    }
}
