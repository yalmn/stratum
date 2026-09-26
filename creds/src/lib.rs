//! Extraktion lokaler Windows-Konten (Benutzername und NT-Hash) aus den Hives
//! SAM und SYSTEM.
//!
//! Der NT-Hash ist kein Klartext-Passwort. Er ist der Wert, den man
//! anschliessend mit einem Passwort-Cracker (hashcat, John) angreift. Diese
//! Trennung ist gewollt: stratum extrahiert forensisch und nachvollziehbar, das
//! eigentliche Knacken ist ein eigener, dokumentierter Schritt.
//!
//! Ablauf: Bootkey aus dem SYSTEM-Hive (verteilt auf die Class-Werte der
//! Schlüssel JD, Skew1, GBG, Data), daraus mit der F-Struktur des SAM-Hives
//! der Hashed-Bootkey, damit je Konto der NT-Hash aus der V-Struktur.
//!
//! Wichtig zur Gültigkeit: Die Krypto-Bausteine sind gegen veröffentlichte
//! Vektoren geprüft, die Zusammensetzung über synthetische Strukturen. Die
//! abschliessende Bestätigung gegen echte Hives (Vergleich mit samdump2 oder
//! secretsdump.py) gehört auf die forensische VM.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod crypto;
pub mod dpapi;
mod lsa;
mod sam;

use serde::Serialize;

use stratum_registry::{Hive, HiveError};

pub use lsa::{cached_logons, lsa_key, secrets as lsa_secrets, CachedLogon, LsaError, Secret};
pub use sam::{bootkey_from_classes, hashed_bootkey, user_hash, SamError, UserHash, EMPTY_NT_HASH};

/// Die vier Schlüssel unter `Control\Lsa`, deren Class-Werte den Bootkey
/// bilden.
const LSA_KEYS: [&str; 4] = ["JD", "Skew1", "GBG", "Data"];

/// Fehler der Konten-Extraktion.
#[derive(Debug, thiserror::Error)]
pub enum CredsError {
    /// Fehler beim Lesen eines Hives.
    #[error(transparent)]
    Hive(#[from] HiveError),

    /// Fehler bei der SAM-Auswertung.
    #[error(transparent)]
    Sam(#[from] SamError),

    /// Ein nötiger Schlüssel oder Wert fehlt im Hive.
    #[error("{0}")]
    Missing(String),
}

/// Ein lokales Windows-Konto.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Account {
    /// Benutzername.
    pub username: String,
    /// Relative Kennung (RID). 500 ist das eingebaute Administrator-Konto.
    pub rid: u32,
    /// NT-Hash als Hex-Zeichenkette (32 Zeichen).
    pub nt_hash: String,
    /// `false`, wenn kein Hash hinterlegt war (leeres Passwort).
    pub has_password: bool,
    /// Byte-Offset des V-Werts im SAM-Hive, als Herkunftsnachweis.
    pub v_offset: u64,
}

/// Ergebnis der Extraktion.
#[derive(Debug, Clone, Default, Serialize)]
pub struct CredsReport {
    /// Gefundene Konten.
    pub accounts: Vec<Account>,
    /// Auffälligkeiten (z. B. einzelne unlesbare Konten).
    pub warnings: Vec<String>,
}

/// Liest alle lokalen Konten aus einem SYSTEM- und einem SAM-Hive.
pub fn extract_local_accounts(system: &Hive, sam: &Hive) -> Result<CredsReport, CredsError> {
    let bootkey = read_bootkey(system)?;

    let account_key = sam
        .open_key("SAM\\Domains\\Account")?
        .ok_or_else(|| CredsError::Missing("SAM\\Domains\\Account fehlt".into()))?;
    let f = account_key
        .value("F")?
        .ok_or_else(|| CredsError::Missing("Wert F unter Account fehlt".into()))?;
    let hbootkey = sam::hashed_bootkey(f.data(), &bootkey)?;

    let mut report = CredsReport::default();

    let users = sam
        .open_key("SAM\\Domains\\Account\\Users")?
        .ok_or_else(|| CredsError::Missing("Users-Schlüssel fehlt".into()))?;

    for subkey in users.subkeys()? {
        // Konten liegen unter ihrer RID als 8-stelliger Hex-Name; "Names" und
        // ähnliche Hilfsschlüssel werden übersprungen.
        let Ok(rid) = u32::from_str_radix(subkey.name(), 16) else {
            continue;
        };
        let Some(v) = subkey.value("V")? else {
            report
                .warnings
                .push(format!("Konto {rid:08x}: Wert V fehlt, übersprungen"));
            continue;
        };
        match sam::user_hash(v.data(), rid, &hbootkey) {
            Ok(u) => report.accounts.push(Account {
                username: u.username,
                rid: u.rid,
                nt_hash: hex(&u.nt_hash),
                has_password: u.has_hash,
                v_offset: v.file_offset(),
            }),
            Err(e) => report
                .warnings
                .push(format!("Konto {rid:08x} nicht lesbar: {e}")),
        }
    }

    report.accounts.sort_by_key(|a| a.rid);
    Ok(report)
}

/// Leitet den Bootkey (Syskey) aus dem SYSTEM-Hive ab.
pub fn read_bootkey(system: &Hive) -> Result<[u8; 16], CredsError> {
    let current = system
        .open_key("Select")?
        .and_then(|k| k.value("Current").ok().flatten())
        .and_then(|v| v.as_u32())
        .unwrap_or(1);
    let cs = format!("ControlSet{current:03}");

    let mut classes: [String; 4] = Default::default();
    for (i, name) in LSA_KEYS.iter().enumerate() {
        let path = format!("{cs}\\Control\\Lsa\\{name}");
        let key = system
            .open_key(&path)?
            .ok_or_else(|| CredsError::Missing(format!("{path} fehlt")))?;
        classes[i] = key
            .class()?
            .ok_or_else(|| CredsError::Missing(format!("Class-Wert von {path} fehlt")))?;
    }

    Ok(sam::bootkey_from_classes(&classes)?)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Liest die gecachten Domain-Logins (DCC2) aus SYSTEM- und SECURITY-Hive.
pub fn extract_cached_logons(
    system: &Hive,
    security: &Hive,
) -> Result<Vec<CachedLogon>, CredsError> {
    let secrets = extract_lsa_secrets(system, security)?;
    let Some(nklm) = secrets
        .iter()
        .find(|s| s.name.eq_ignore_ascii_case("NL$KM"))
    else {
        return Ok(Vec::new());
    };
    Ok(lsa::cached_logons(security, &nklm.value))
}

/// Liest die LSA-Secrets aus SYSTEM- und SECURITY-Hive (Vista und neuer).
pub fn extract_lsa_secrets(system: &Hive, security: &Hive) -> Result<Vec<Secret>, CredsError> {
    let bootkey = read_bootkey(system)?;
    let key = lsa::lsa_key(security, &bootkey).map_err(|e| CredsError::Missing(e.to_string()))?;
    Ok(lsa::secrets(security, &key))
}

#[cfg(test)]
#[path = "../tests/common/builder.rs"]
mod builder;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::HiveBuilder;
    use crate::crypto::{
        aes128_cbc_encrypt, aes256_ecb_encrypt, des_encrypt_block, sha256_rounds, sid_to_keys,
    };

    const REG_DWORD: u32 = 4;
    const REG_BINARY: u32 = 3;

    /// Verteilt einen bekannten Bootkey auf die vier Class-Hex-Werte.
    fn classes_for(bootkey: &[u8; 16]) -> [String; 4] {
        let perm = [
            0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7,
        ];
        let mut scrambled = [0u8; 16];
        for (i, &p) in perm.iter().enumerate() {
            scrambled[p] = bootkey[i];
        }
        let h = |s: &[u8]| s.iter().map(|b| format!("{b:02x}")).collect::<String>();
        [
            h(&scrambled[0..4]),
            h(&scrambled[4..8]),
            h(&scrambled[8..12]),
            h(&scrambled[12..16]),
        ]
    }

    /// F-Struktur (AES-Pfad) mit einem gewählten Hashed-Bootkey.
    fn build_f(bootkey: &[u8; 16], hbootkey: &[u8; 16]) -> Vec<u8> {
        let iv = [9u8; 16];
        let mut plain = [0u8; 32];
        plain[..16].copy_from_slice(hbootkey);
        let enc = aes128_cbc_encrypt(bootkey, &iv, &plain);
        let mut f = vec![0u8; 0xA8];
        f[0] = 3;
        f[0x78..0x88].copy_from_slice(&iv);
        f[0x88..0xA8].copy_from_slice(&enc);
        f
    }

    /// V-Struktur (AES-Pfad) mit Benutzername und Ziel-NT-Hash.
    fn build_v(username: &str, nt: &[u8; 16], hbootkey: &[u8; 16], rid: u32) -> Vec<u8> {
        const BASE: usize = 0xCC;
        let (k1, k2) = sid_to_keys(rid);
        let mut obf = [0u8; 16];
        obf[..8].copy_from_slice(&des_encrypt_block(&k1, &nt[..8].try_into().unwrap()));
        obf[8..].copy_from_slice(&des_encrypt_block(&k2, &nt[8..].try_into().unwrap()));
        let salt = [3u8; 16];
        let mut plain = [0u8; 32];
        plain[..16].copy_from_slice(&obf);
        let enc = aes128_cbc_encrypt(hbootkey, &salt, &plain);

        let name: Vec<u8> = username.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let nt_rel = name.len();
        let mut v = vec![0u8; BASE + nt_rel + 56];
        v[0x0c..0x10].copy_from_slice(&0u32.to_le_bytes());
        v[0x10..0x14].copy_from_slice(&(name.len() as u32).to_le_bytes());
        v[0xa8..0xac].copy_from_slice(&(nt_rel as u32).to_le_bytes());
        v[0xac..0xb0].copy_from_slice(&56u32.to_le_bytes());
        v[BASE..BASE + name.len()].copy_from_slice(&name);
        let ns = BASE + nt_rel;
        v[ns + 2] = 2;
        v[ns + 8..ns + 24].copy_from_slice(&salt);
        v[ns + 24..ns + 56].copy_from_slice(&enc);
        v
    }

    fn build_system(bootkey: &[u8; 16]) -> Vec<u8> {
        let mut b = HiveBuilder::new();
        let classes = classes_for(bootkey);
        let jd = b.key_with_class("JD", &classes[0], None, &[]);
        let skew = b.key_with_class("Skew1", &classes[1], None, &[]);
        let gbg = b.key_with_class("GBG", &classes[2], None, &[]);
        let data = b.key_with_class("Data", &classes[3], None, &[]);
        let lsa_list = b.lh(&[jd, skew, gbg, data]);
        let lsa = b.key_with_list("Lsa", lsa_list, 4, &[]);
        let ctrl_list = b.lh(&[lsa]);
        let ctrl = b.key_with_list("Control", ctrl_list, 1, &[]);
        let cs_list = b.lh(&[ctrl]);
        let cs = b.key_with_list("ControlSet001", cs_list, 1, &[]);

        let current = b.vk("Current", REG_DWORD, &1u32.to_le_bytes());
        let select = b.key("Select", None, &[current]);

        let root_list = b.lh(&[cs, select]);
        let root = b.key_with_list("ROOT", root_list, 2, &[]);
        b.finish(root)
    }

    fn build_sam(f: &[u8], users: &[(u32, Vec<u8>)]) -> Vec<u8> {
        let mut b = HiveBuilder::new();
        let mut user_keys = Vec::new();
        for (rid, v) in users {
            let vk = b.vk("V", REG_BINARY, v);
            let name = format!("{rid:08X}");
            user_keys.push(b.key(&name, None, &[vk]));
        }
        let users_list = b.lh(&user_keys);
        let users_key = b.key_with_list("Users", users_list, user_keys.len() as u32, &[]);

        let f_val = b.vk("F", REG_BINARY, f);
        let acc_list = b.lh(&[users_key]);
        let account = b.key_with_list("Account", acc_list, 1, &[f_val]);
        let dom_list = b.lh(&[account]);
        let domains = b.key_with_list("Domains", dom_list, 1, &[]);
        let sam_list = b.lh(&[domains]);
        let sam = b.key_with_list("SAM", sam_list, 1, &[]);
        let root_list = b.lh(&[sam]);
        let root = b.key_with_list("ROOT", root_list, 1, &[]);
        b.finish(root)
    }

    #[test]
    fn end_to_end_zwei_konten() {
        let bootkey = [0x5au8; 16];
        let hbootkey = [0x11u8; 16];

        let admin_nt = [
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99,
        ];
        let system = build_system(&bootkey);
        let f = build_f(&bootkey, &hbootkey);
        let sam = build_sam(
            &f,
            &[
                (500, build_v("Administrator", &admin_nt, &hbootkey, 500)),
                (1001, build_v("alice", &EMPTY_NT_HASH, &hbootkey, 1001)),
            ],
        );

        let system_hive = Hive::parse(&system).unwrap();
        let sam_hive = Hive::parse(&sam).unwrap();
        let report = extract_local_accounts(&system_hive, &sam_hive).unwrap();

        assert!(report.warnings.is_empty(), "{:?}", report.warnings);
        assert_eq!(report.accounts.len(), 2);

        let admin = &report.accounts[0];
        assert_eq!(admin.rid, 500);
        assert_eq!(admin.username, "Administrator");
        assert_eq!(admin.nt_hash, hex(&admin_nt));
        assert!(admin.has_password);
        assert!(admin.v_offset > 4096);

        // alice trägt einen echten (verschlüsselten) Hash, der zum bekannten
        // NT-Hash des leeren Passworts entschlüsselt. 31d6...c0 ist MD4("") und
        // damit ein echter externer Prüfwert für die gesamte Kette.
        let alice = &report.accounts[1];
        assert_eq!(alice.username, "alice");
        assert!(alice.has_password);
        assert_eq!(alice.nt_hash, "31d6cfe0d16ae931b73c59d7e0c089c0");
    }

    /// Verschlüsselt einen Wert als LSA_SECRET, wie Windows ihn ablegt:
    /// 28 Byte Kopf, 32 Byte Salz, dann AES-256 über den LSA_SECRET_BLOB.
    fn lsa_secret(key: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut blob = Vec::new();
        blob.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        blob.extend_from_slice(&[0u8; 12]);
        blob.extend_from_slice(payload);
        while !blob.len().is_multiple_of(16) {
            blob.push(0);
        }
        let salt = [0x37u8; 32];
        let tmp = sha256_rounds(key, &salt, 1000);
        let mut out = vec![0u8; 28];
        out.extend_from_slice(&salt);
        out.extend_from_slice(&aes256_ecb_encrypt(&tmp, &blob));
        out
    }

    /// SECURITY-Hive mit PolEKList (LSA-Schlüssel mit dem Bootkey
    /// verschlüsselt) und einem Secret `DPAPI_SYSTEM`.
    fn build_security(bootkey: &[u8; 16], lsa_key: &[u8; 32], secret: &[u8]) -> Vec<u8> {
        // Im PolEKList-Blob liegt der LSA-Schlüssel bei Secret[52..84].
        let mut pol_payload = vec![0u8; 84];
        pol_payload[52..84].copy_from_slice(lsa_key);

        let mut b = HiveBuilder::new();
        let pol_val = b.vk("", REG_BINARY, &lsa_secret(bootkey, &pol_payload));
        let pol = b.key("PolEKList", None, &[pol_val]);
        let cur_val = b.vk("", REG_BINARY, &lsa_secret(lsa_key, secret));
        let curr = b.key("CurrVal", None, &[cur_val]);
        let curr_list = b.lh(&[curr]);
        let dpapi = b.key_with_list("DPAPI_SYSTEM", curr_list, 1, &[]);
        let sec_list = b.lh(&[dpapi]);
        let secrets = b.key_with_list("Secrets", sec_list, 1, &[]);
        let policy_list = b.lh(&[pol, secrets]);
        let policy = b.key_with_list("Policy", policy_list, 2, &[]);
        let root_list = b.lh(&[policy]);
        let root = b.key_with_list("ROOT", root_list, 1, &[]);
        b.finish(root)
    }

    #[test]
    fn lsa_secret_ende_zu_ende() {
        let bootkey: [u8; 16] = std::array::from_fn(|i| i as u8 + 1);
        let lsa_key = [0xa5u8; 32];
        let wert = b"\x01\x00\x00\x00geheimer-dpapi-wert";
        let system = build_system(&bootkey);
        let security = build_security(&bootkey, &lsa_key, wert);
        let secrets = extract_lsa_secrets(
            &Hive::parse(&system).unwrap(),
            &Hive::parse(&security).unwrap(),
        )
        .unwrap();
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].name, "DPAPI_SYSTEM");
        assert_eq!(secrets[0].value, wert);
    }

    #[test]
    fn falscher_bootkey_meldet_fehler_statt_leerer_liste() {
        let system = build_system(&[0x11u8; 16]);
        let security = build_security(&[0x22u8; 16], &[0xa5u8; 32], b"x");
        let r = extract_lsa_secrets(
            &Hive::parse(&system).unwrap(),
            &Hive::parse(&security).unwrap(),
        );
        assert!(matches!(r, Err(CredsError::Missing(_))));
    }

    #[test]
    fn fehlender_lsa_schlüssel_meldet_fehler() {
        // SYSTEM ohne Lsa -> Bootkey nicht ableitbar.
        let mut b = HiveBuilder::new();
        let current = b.vk("Current", REG_DWORD, &1u32.to_le_bytes());
        let select = b.key("Select", None, &[current]);
        let root_list = b.lh(&[select]);
        let root = b.key_with_list("ROOT", root_list, 1, &[]);
        let data = b.finish(root);
        let system = Hive::parse(&data).unwrap();
        let sam_bytes = build_sam(&build_f(&[0u8; 16], &[0u8; 16]), &[]);
        let sam = Hive::parse(&sam_bytes).unwrap();
        assert!(matches!(
            extract_local_accounts(&system, &sam),
            Err(CredsError::Missing(_))
        ));
    }

    #[test]
    fn account_serialisiert_mit_hex() {
        let a = Account {
            username: "Administrator".into(),
            rid: 500,
            nt_hash: hex(&EMPTY_NT_HASH),
            has_password: false,
            v_offset: 0x1234,
        };
        let j = serde_json::to_string(&a).unwrap_or_else(|_| "{}".into());
        assert!(j.contains("31d6cfe0d16ae931b73c59d7e0c089c0"));
    }
}
