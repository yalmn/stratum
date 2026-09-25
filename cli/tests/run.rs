//! End-to-End-Test des CLI gegen ein synthetisches Image.
//!
//! Baut ein kleines MBR-Image mit einer NTFS-Signatur und eingebetteten
//! Klartext-Zugangsdaten, ruft die gebaute Binärdatei auf und prüft den
//! JSON-Report.

use std::process::Command;

const SS: usize = 512;

fn build_dd() -> Vec<u8> {
    let mut img = vec![0u8; 64 * SS];
    // MBR-Eintrag 0: NTFS, aktiv, LBA 2, 60 Sektoren.
    let e = 446;
    img[e] = 0x80;
    img[e + 4] = 0x07;
    img[e + 8..e + 12].copy_from_slice(&2u32.to_le_bytes());
    img[e + 12..e + 16].copy_from_slice(&60u32.to_le_bytes());
    img[510] = 0x55;
    img[511] = 0xAA;
    // NTFS-Signatur am Partitionsanfang.
    let b = 2 * SS;
    img[b + 3..b + 11].copy_from_slice(b"NTFS    ");
    img[b + 510] = 0x55;
    img[b + 511] = 0xAA;
    // Klartext-Zugangsdaten und eine Onion-Adresse in der Datenzone.
    let payload = b"config: username=alice pw=Sommer2024! torrc";
    img[10 * SS..10 * SS + payload.len()].copy_from_slice(payload);
    img
}

const TABLE: &str = r#"
[meta]
name = "Testfall"
version = 3

[[kategorie]]
id = "zugangsdaten"
modus = "paar"
abstand_bytes = 64
links = ["username"]
rechts = ["pw"]

[[kategorie]]
id = "darknet"
begriffe = ["torrc"]
"#;

#[test]
fn erzeugt_json_report() {
    let dir = tempfile::tempdir().unwrap();
    let dd = dir.path().join("test.dd");
    let table = dir.path().join("begriffe.toml");
    std::fs::write(&dd, build_dd()).unwrap();
    std::fs::write(&table, TABLE).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_stratum"))
        .arg(&dd)
        .arg("--keywords")
        .arg(&table)
        .output()
        .unwrap();
    assert!(output.status.success(), "Exit: {:?}", output.status);

    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();

    // Integrität.
    assert_eq!(json["image"]["size"], 64 * SS as u64);
    assert_eq!(
        json["image"]["hashes"]["sha256"].as_str().unwrap().len(),
        64
    );

    // Partition.
    assert_eq!(json["partitions"]["scheme"], "mbr");
    assert_eq!(json["partitions"]["partitions"][0]["fs_hint"], "ntfs");

    // Suche: Zugangsdaten-Paar und torrc. Domäne, Name und Attribute im
    // neuen Fund-Schema.
    let findings = json["search"]["findings"].as_array().unwrap();
    assert_eq!(json["search"]["table_version"], 3);
    assert!(findings
        .iter()
        .any(|f| f["domain"] == "zugangsdaten" && f["attributes"]["art"] == "paar"));
    assert!(findings
        .iter()
        .any(|f| f["domain"] == "darknet" && f["name"] == "torrc"));
}

#[test]
fn no_hash_lässt_hashes_weg() {
    let dir = tempfile::tempdir().unwrap();
    let dd = dir.path().join("test.dd");
    std::fs::write(&dd, build_dd()).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_stratum"))
        .arg(&dd)
        .arg("--no-hash")
        .arg("--no-default-keywords")
        .output()
        .unwrap();
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(json["image"].get("hashes").is_none());
    // Ohne mitgelieferte Liste und ohne -k wird nicht gesucht.
    assert!(json.get("search").is_none());
}

#[test]
fn mitgelieferte_liste_laeuft_ohne_keywords() {
    let dir = tempfile::tempdir().unwrap();
    let dd = dir.path().join("test.dd");
    std::fs::write(&dd, build_dd()).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_stratum"))
        .arg(&dd)
        .arg("--no-hash")
        .output()
        .unwrap();
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    // Ohne -k laeuft die eingebaute Liste "Strafverfolgung" automatisch mit.
    let name = json["search"]["table_name"].as_str().unwrap();
    assert!(name.contains("Strafverfolgung"), "Name: {name}");
    // torrc steht in der Datenzone und ist in der Default-Liste enthalten.
    let findings = json["search"]["findings"].as_array().unwrap();
    assert!(findings.iter().any(|f| f["name"] == "torrc"));
}
