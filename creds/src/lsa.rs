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

use crate::crypto::{aes128_cbc_decrypt, aes256_ecb_decrypt, sha256_rounds};
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
    /// Der entschlüsselte PolEKList-Inhalt ist unplausibel (falscher Bootkey
    /// oder beschädigter Hive).
    #[error("PolEKList nicht entschlüsselbar (Bootkey passt nicht)")]
    BadKey,
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
                                 // Der Bootkey geht mit seinen 16 Byte in die Ableitung, ohne Auffüllen.
    let plain = decrypt_secret(enc, bootkey)?;
    // Plausibilität: Mit falschem Bootkey steht im Längenfeld Zufall. Ohne
    // diese Prüfung entstünde ein unbrauchbarer Schlüssel und alle Secrets
    // fielen stillschweigend weg.
    let len = plain
        .get(0..4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
        .ok_or(LsaError::TooShort)?;
    if len < 84 || len > plain.len().saturating_sub(16) {
        return Err(LsaError::BadKey);
    }
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
        if let Ok(plain) = decrypt_secret(&data[28..], lsa_key) {
            // Der eigentliche Wert steht in der LSA_SECRET_BLOB ab Offset 16,
            // seine Laenge im Length-Feld.
            if let Some(value) = blob_secret(&plain) {
                out.push(Secret { name, value });
            }
        }
    }
    out
}

/// Ein gecachter Domain-Login (Domain Cached Credentials v2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedLogon {
    /// Benutzername (mit Domäne, falls vorhanden).
    pub username: String,
    /// DCC2-Hash (MSCACHEV2), hex, mit hashcat-Modus 2100 angreifbar.
    pub dcc2_hex: String,
}

/// Entschlüsselt die gecachten Domain-Logins unter `Cache\NL$n` mit dem
/// NL$KM-Secret. `nklm` ist der entschlüsselte Wert des Secrets `NL$KM`.
pub fn cached_logons(security: &Hive, nklm: &[u8]) -> Vec<CachedLogon> {
    let mut out = Vec::new();
    if nklm.len() < 32 {
        return out;
    }
    let mut key = [0u8; 16];
    key.copy_from_slice(&nklm[16..32]); // NL$KM[16..32] ist der AES-Schlüssel

    let Ok(Some(cache)) = security.open_key("Cache") else {
        return out;
    };
    let Ok(values) = cache.values() else {
        return out;
    };
    for v in values {
        let name = v.name();
        if !name.starts_with("NL$") || name.eq_ignore_ascii_case("NL$Control") {
            continue;
        }
        let data = v.data();
        if data.len() < 0x60 {
            continue;
        }
        let user_len = u16::from_le_bytes([data[0], data[1]]) as usize;
        let flags = u32::from_le_bytes([data[0x30], data[0x31], data[0x32], data[0x33]]);
        if flags & 1 == 0 {
            continue; // leerer/unverschlüsselter Slot
        }
        let iv: [u8; 16] = data[0x40..0x50].try_into().unwrap();
        let enc = &data[0x60..];
        if enc.is_empty() {
            continue;
        }
        let plain = aes128_cbc_decrypt(&key, &iv, enc);
        let Some(hash) = plain.get(0..16) else {
            continue;
        };
        // Benutzername liegt ab Offset 0x48 als UTF-16LE.
        let username = plain
            .get(0x48..0x48 + user_len)
            .map(|raw| {
                let units: Vec<u16> = raw
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                String::from_utf16_lossy(&units)
            })
            .unwrap_or_default();
        out.push(CachedLogon {
            username,
            dcc2_hex: hash.iter().map(|b| format!("{b:02x}")).collect(),
        });
    }
    out
}

/// AES-Entschlüsselung einer LSA_SECRET-EncryptedData mit dem Schema
/// `tmpKey = SHA256(key, enc[0..32], 1000x)`, dann AES-256 (ECB-artig) über
/// `enc[32..]`. `key` ist der Bootkey (16 Byte) oder der LSA-Schlüssel
/// (32 Byte) und wird in seiner tatsächlichen Länge gehasht.
fn decrypt_secret(enc: &[u8], key: &[u8]) -> Result<Vec<u8>, LsaError> {
    if enc.len() < 32 {
        return Err(LsaError::TooShort);
    }
    let tmp = sha256_rounds(key, &enc[..32], 1000);
    Ok(aes256_ecb_decrypt(&tmp, &enc[32..]))
}

/// Extrahiert aus einer entschlüsselten LSA_SECRET_BLOB den Nutzinhalt.
fn blob_secret(plain: &[u8]) -> Option<Vec<u8>> {
    let len = u32::from_le_bytes(plain.get(0..4)?.try_into().ok()?) as usize;
    let secret = plain.get(16..16 + len)?;
    Some(secret.to_vec())
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
        let tmp = sha256_rounds(bootkey, &salt, 1000);
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
        let plain = decrypt_secret(&pol[28..], &bootkey).unwrap();
        assert_eq!(&plain[68..100], &target);
    }

    #[test]
    fn zu_kurz() {
        assert!(matches!(
            decrypt_secret(&[0u8; 10], &[0; 32]),
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
