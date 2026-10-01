//! Gezielter Abruf einzelner Werte, ohne vollständigen Analyselauf:
//! ein Rohfund aus einem Report (`--fund`) und ein System-Masterkey aus dem
//! Image (`--masterkey`).

use std::path::Path;

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use stratum_analysis::{assign_ids, masterkey_abrufen, AnalysisContext, Finding, NtfsTarget};
use stratum_core::ImageReader;

/// Gibt den Rohfund mit dieser Kennung aus dem Report aus. Die Kennung wird
/// aus dem Inhalt nachgerechnet; stimmt sie nicht, ist der Report verändert
/// oder die Kennung falsch, und der Abruf schlägt fehl.
pub fn fund(report: &Path, id: &str) -> Result<()> {
    let bytes = std::fs::read(report)
        .with_context(|| format!("Report nicht lesbar: {}", report.display()))?;
    let sha256 = hex(&Sha256::digest(&bytes));
    let v: serde_json::Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("Report ist kein JSON: {}", report.display()))?;
    let funde: Vec<Finding> = serde_json::from_value(v["findings"].clone())
        .context("Report enthält keine lesbare Fundliste")?;
    let Some(f) = funde.into_iter().find(|f| f.id == id) else {
        bail!("Kein Fund mit Kennung {id} im Report");
    };
    let mut nach = [Finding {
        id: String::new(),
        ..f.clone()
    }];
    assign_ids(&mut nach);
    // Inhaltsgleiche Funde tragen `-2`, `-3`, …; verglichen wird der Hash.
    let basis = id.split('-').next().unwrap_or(id);
    if nach[0].id != basis {
        bail!(
            "Kennung {id} passt nicht zum Inhalt (nachgerechnet {}); Report verändert?",
            nach[0].id
        );
    }
    eprintln!(
        "[+] Fund {id} aus {} (SHA-256 {sha256}), Kennung aus dem Inhalt bestätigt",
        report.display()
    );
    println!("{}", serde_json::to_string_pretty(&f)?);
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

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

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
