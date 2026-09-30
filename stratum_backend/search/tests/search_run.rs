//! Lädt eine Begriffstabelle von der Platte und durchsucht einen
//! zusammengesetzten Datenbereich, wie er beim Scan einer Datei entstünde.

use stratum_search::{Encoding, FindingKind, SearchEngine, TermTable};

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

#[test]
fn tabelle_von_platte_und_scan() {
    let table =
        TermTable::load(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/durchlauf.toml")).unwrap();
    let engine = SearchEngine::new(&table);

    let mut data = Vec::new();
    data.extend_from_slice(b"harmloser vorspann ");
    let pair_at = data.len();
    data.extend_from_slice(b"benutzer=alice passwort=Sommer2024! ");
    data.extend_from_slice(&utf16("login-notiz user=bob pw=hunter2 "));
    let onion = "b".repeat(56);
    data.extend_from_slice(format!("dienst {onion}.onion ").as_bytes());

    // base_offset simuliert die Lage der Datei im Image.
    let base = 0x10_0000u64;
    let r = engine.run(&data, base);

    let pairs: Vec<_> = r
        .findings
        .iter()
        .filter(|f| matches!(f.kind, FindingKind::Paar { .. }))
        .collect();
    assert_eq!(pairs.len(), 2, "ein ASCII- und ein UTF-16-Paar");
    assert!(pairs.iter().any(|f| f.kodierung == Encoding::Ascii));
    assert!(pairs.iter().any(|f| f.kodierung == Encoding::Utf16Le));

    let cred = pairs
        .iter()
        .find(|f| f.kodierung == Encoding::Ascii)
        .unwrap();
    assert_eq!(cred.offset, base + pair_at as u64);
    assert!(cred.kontext.contains("Sommer2024!"));

    let onion_hit = r
        .findings
        .iter()
        .find(|f| f.kategorie == "darknet")
        .and_then(|f| match &f.kind {
            FindingKind::Term { begriff } => Some(begriff.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(onion_hit, format!("{onion}.onion"));
}
