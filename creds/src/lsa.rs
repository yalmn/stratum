//! Entschlüsselung der LSA-Secrets aus dem SECURITY-Hive (Vista und neuer,
//! AES-Pfad).
//!
//! LSA-Secrets enthalten unter anderem Klartext-Passwörter von Dienstkonten,
//! den DPAPI-Systemschlüssel und `NL$KM` (Schlüssel für gecachte Domain-Logins).
//! Ablauf: Aus dem Bootkey und `Policy\PolEKList` wird der LSA-Schlüssel
//! abgeleitet, damit werden die Secrets unter `Policy\Secrets\<name>\CurrVal`
//! entschlüsselt.
//!
//! Byte-Offsets und Ableitung folgen der Impacket-Implementierung
//! (secretsdump). Wie bei den SAM-Hashes ist der abschliessende Abgleich gegen
//! echte Hives (secretsdump.py) der VM-Analyse vorbehalten.

use crate::crypto::{aes256_ecb_decrypt, sha256_rounds};
use stratum_registry::Hive;

/// Fehler der LSA-Auswertung.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LsaError {
    /// `Policy\PolEKList` fehlt (kein Vista+-SECURITY-Hive).
    #[error("PolEKList fehlt (kein unterstuetzter SECURITY-Hive)")]
    NoPolEkList,
    /// Eine LSA-Struktur ist zu kurz.
    #[error("LSA-Struktur zu kurz")]
    TooShort,
}

/// Ein entschlüsseltes LSA-Secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Secret {
    /// Name des Secrets (z. B. `DPAPI_SYSTEM`, `NL$KM`, Dienstkontoname).
    pub name: String,
    /// Entschlüsselter Inhalt.
    pub value: Vec<u8>,
}

/// Leitet den LSA-Schlüssel aus Bootkey und `Policy\PolEKList` ab.
pub fn lsa_key(security: &Hive, bootkey: &[u8; 16]) -> Result<[u8; 32], LsaError> {
    let pol = security
        .open_key("Policy\\PolEKList")
        .ok()
        .flatten()
        .and_then(|k| k.value("").ok().flatten())
        .ok_or(LsaError::NoPolEkList)?;
    let enc = &pol.data()[28..]; // EncryptedData ab Offset 28 der LSA_SECRET-Struktur
    let plain = decrypt_secret(enc, bootkey_as_key(bootkey))?;
    // LSA_SECRET_BLOB: Length(4) Unknown(12) Secret(:). Der LSA-Schluessel liegt
    // in Secret ab Offset 52 (also plainText[68..100]).
    let key = plain.get(68..100).ok_or(LsaError::TooShort)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(key);
    Ok(out)
}

/// Entschlüsselt alle Secrets unter `Policy\Secrets` mit dem LSA-Schlüssel.
pub fn secrets(security: &Hive, lsa_key: &[u8; 32]) -> Vec<Secret> {
    let mut out = Vec::new();
    let Ok(Some(root)) = security.open_key("Policy\\Secrets") else {
        return out;
    };
    let Ok(names) = root.subkeys() else {
        return out;
    };
    for name_key in names {
        let name = name_key.name().to_string();
        let Ok(Some(curr)) = name_key.subkey("CurrVal") else {
            continue;
        };
        let Ok(Some(val)) = curr.value("") else {
            continue;
        };
        let data = val.data();
        if data.len() < 32 {
            continue;
        }
        if let Ok(plain) = decrypt_secret(&data[28..], *lsa_key) {
            // Der eigentliche Wert steht in der LSA_SECRET_BLOB ab Offset 16,
            // seine Laenge im Length-Feld.
            if let Some(value) = blob_secret(&plain) {
                out.push(Secret { name, value });
            }
        }
    }
    out
}

/// AES-Entschlüsselung einer LSA_SECRET-EncryptedData mit dem Schema
/// `tmpKey = SHA256(key, enc[0..32], 1000x)`, dann AES-256 (ECB-artig) über
/// `enc[32..]`.
fn decrypt_secret(enc: &[u8], key: [u8; 32]) -> Result<Vec<u8>, LsaError> {
    if enc.len() < 32 {
        return Err(LsaError::TooShort);
    }
    let tmp = sha256_rounds(&key, &enc[..32], 1000);
    Ok(aes256_ecb_decrypt(&tmp, &enc[32..]))
}

/// Extrahiert aus einer entschlüsselten LSA_SECRET_BLOB den Nutzinhalt.
fn blob_secret(plain: &[u8]) -> Option<Vec<u8>> {
    let len = u32::from_le_bytes(plain.get(0..4)?.try_into().ok()?) as usize;
    let secret = plain.get(16..16 + len)?;
    Some(secret.to_vec())
}

/// Der 16-Byte-Bootkey wird für die erste SHA-256-Ableitung auf 32 Byte
/// erweitert, indem er verwendet wird, wie Impacket ihn übergibt (nur die
/// ersten 16 Byte zählen; die Ableitung nutzt ihn als Schlüssel-Präfix).
fn bootkey_as_key(bootkey: &[u8; 16]) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[..16].copy_from_slice(bootkey);
    k
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{aes256_ecb_encrypt, sha256_rounds};

    // Baut einen SECURITY-Hive-artigen PolEKList-Wert, aus dem sich ein
    // gewaehlter LSA-Schluessel wieder ableiten laesst (Round-Trip).
    fn build_poleklist(bootkey: &[u8; 16], lsa_key: &[u8; 32]) -> Vec<u8> {
        // Klartext-Blob: Length(4) + Unknown(12) + Secret. LSA-Key bei Secret[52].
        let mut blob = vec![0u8; 100];
        let secret_len = 84u32; // >= 84, damit Secret[52..84] enthalten ist
        blob[0..4].copy_from_slice(&secret_len.to_le_bytes());
        blob[68..100].copy_from_slice(lsa_key);
        // Auf Vielfaches von 16 auffuellen.
        while !blob.len().is_multiple_of(16) {
            blob.push(0);
        }
        let salt = [0x11u8; 32];
        let mut key32 = [0u8; 32];
        key32[..16].copy_from_slice(bootkey);
        let tmp = sha256_rounds(&key32, &salt, 1000);
        let enc = aes256_ecb_encrypt(&tmp, &blob);
        // LSA_SECRET: 28 Byte Kopf + salt(32) + enc.
        let mut out = vec![0u8; 28];
        out.extend_from_slice(&salt);
        out.extend_from_slice(&enc);
        out
    }

    #[test]
    fn lsa_key_roundtrip() {
        let bootkey = [0x5au8; 16];
        let target = [0x42u8; 32];
        let pol = build_poleklist(&bootkey, &target);
        // decrypt_secret + Offset 68..100 muss den Zielschluessel liefern.
        let key32 = {
            let mut k = [0u8; 32];
            k[..16].copy_from_slice(&bootkey);
            k
        };
        let plain = decrypt_secret(&pol[28..], key32).unwrap();
        assert_eq!(&plain[68..100], &target);
    }

    #[test]
    fn zu_kurz() {
        assert!(matches!(
            decrypt_secret(&[0u8; 10], [0; 32]),
            Err(LsaError::TooShort)
        ));
    }

    #[test]
    fn blob_secret_liest_laenge() {
        let mut blob = vec![0u8; 16 + 5];
        blob[0..4].copy_from_slice(&5u32.to_le_bytes());
        blob[16..21].copy_from_slice(b"hallo");
        assert_eq!(blob_secret(&blob).as_deref(), Some(&b"hallo"[..]));
    }
}
