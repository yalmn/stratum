//! Entschlüsselung benutzergebundener DPAPI-Geheimnisse (Windows Data
//! Protection API), soweit sie für gespeicherte Browser-Passwörter nötig ist.
//!
//! Die Kette bei Chromium-Browsern (Edge, Chrome, Brave, Opera):
//!
//! 1. `Login Data` (SQLite) enthält je Eintrag `password_value`, mit AES-256-GCM
//!    verschlüsselt (Präfix `v10`/`v11`).
//! 2. Der GCM-Schlüssel steht in `Local State` (JSON) unter
//!    `os_crypt.encrypted_key`, base64, nach dem 5-Byte-Präfix `DPAPI` ein
//!    DPAPI-Blob (benutzergebunden).
//! 3. Der DPAPI-Blob wird mit einem Masterkey entschlüsselt.
//! 4. Der Masterkey liegt verschlüsselt unter
//!    `AppData\Roaming\Microsoft\Protect\<SID>\<GUID>` und wird aus SHA1 des
//!    Benutzerpassworts und der SID abgeleitet.
//!
//! Der NT-Hash genügt hierfür nicht: der Masterkey hängt an SHA1 des
//! Klartextpassworts, nicht an dessen MD4-Ableitung. Das Passwort (oder sein
//! SHA1, oder ein bereits entschlüsselter Masterkey) ist deshalb eine Eingabe
//! von aussen.
//!
//! Implementiert ist der heute übliche Pfad (SHA-512 + AES-256, Windows Vista
//! bis 11). Ältere Kombinationen (SHA-1 + 3DES, Windows XP) werden erkannt und
//! als nicht unterstützt gemeldet, statt geraten zu werden.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit as GcmKeyInit, Nonce};
use hmac::{Hmac, Mac};
use sha1::{Digest, Sha1};
use sha2::Sha512;

use crate::crypto::aes256_cbc_decrypt;

/// Windows-Algorithmus-Kennungen (CALG_*), wie sie in Masterkey- und
/// DPAPI-Blob-Strukturen stehen.
const CALG_SHA_512: u32 = 0x800e;
const CALG_AES_256: u32 = 0x6610;

/// Fehler der DPAPI-Auswertung.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DpapiError {
    /// Eine Struktur ist kürzer als ihre Kopfdaten vorgeben.
    #[error("Struktur zu kurz: {0}")]
    TooShort(&'static str),
    /// Algorithmus-Kombination, die dieser Pfad (noch) nicht abdeckt.
    #[error("nicht unterstützter Algorithmus (Hash 0x{hash:04x}, Krypto 0x{crypt:04x})")]
    Unsupported {
        /// Hash-Algorithmus-Kennung aus der Struktur.
        hash: u32,
        /// Verschlüsselungs-Algorithmus-Kennung aus der Struktur.
        crypt: u32,
    },
    /// Der HMAC des Masterkeys passt nicht: Passwort oder SID falsch.
    #[error("Masterkey-HMAC passt nicht (Passwort oder SID falsch)")]
    BadHmac,
    /// Das Passwort-Feld eines Browser-Eintrags hat kein bekanntes Präfix.
    #[error("unbekanntes Passwort-Format (kein v10/v11)")]
    UnknownPasswordFormat,
    /// AES-GCM-Entschlüsselung fehlgeschlagen (falscher Schlüssel oder
    /// beschädigte Daten).
    #[error("GCM-Entschlüsselung fehlgeschlagen")]
    GcmFailed,
}

/// Bildet den SHA-1 des Benutzerpassworts (als UTF-16LE), wie ihn die
/// DPAPI-Ableitung erwartet.
pub fn sha1_password(password: &str) -> [u8; 20] {
    let utf16: Vec<u8> = password.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut h = Sha1::new();
    h.update(&utf16);
    h.finalize().into()
}

/// Liest eine kleine ganze Zahl (Little Endian) aus einem Puffer.
fn le_u32(buf: &[u8], at: usize) -> Option<u32> {
    buf.get(at..at + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn le_u64(buf: &[u8], at: usize) -> Option<u64> {
    buf.get(at..at + 8)
        .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

/// Leitet aus Passwort-Hash und SID den Vorschlüssel ab
/// (`HMAC-SHA1(pwd_sha1, UTF-16LE(SID + "\0"))`).
fn prekey(pwd_sha1: &[u8; 20], sid: &str) -> [u8; 20] {
    let mut sid_utf16: Vec<u8> = sid.encode_utf16().flat_map(u16::to_le_bytes).collect();
    sid_utf16.extend_from_slice(&[0, 0]); // abschliessende UTF-16-Null
    let mut mac = Hmac::<Sha1>::new_from_slice(pwd_sha1).expect("HMAC nimmt jede Schlüssellänge");
    mac.update(&sid_utf16);
    mac.finalize().into_bytes().into()
}

/// Kopfgrösse einer MasterKeyFile bis zum Beginn des Masterkey-Blobs.
const MK_HEADER: usize = 132;

/// Der GUID-Name einer Masterkey-Datei steht im Kopf als UTF-16LE-Text.
pub fn masterkey_file_guid(file: &[u8]) -> Result<String, DpapiError> {
    // Version(4) + 2x unk(4) = 12, dann 72 Byte GUID (36 UTF-16-Zeichen).
    let raw = file
        .get(12..12 + 72)
        .ok_or(DpapiError::TooShort("Masterkey-Kopf"))?;
    let units: Vec<u16> = raw
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    Ok(String::from_utf16_lossy(&units))
}

/// Entschlüsselt den Masterkey aus einer MasterKeyFile mit Passwort-Hash und
/// SID (benutzergebundener Pfad). Liefert die 64 Byte des Masterkeys.
pub fn decrypt_masterkey(
    file: &[u8],
    sid: &str,
    pwd_sha1: &[u8; 20],
) -> Result<[u8; 64], DpapiError> {
    decrypt_masterkey_with_prekey(file, &prekey(pwd_sha1, sid))
}

/// Entschlüsselt einen System-Masterkey mit einem der beiden 20-Byte-Schlüssel
/// aus `DPAPI_SYSTEM` (Maschinen- oder Benutzerschlüssel). System-Masterkeys
/// liegen unter `Windows\System32\Microsoft\Protect\S-1-5-18` und brauchen kein
/// Benutzerpasswort; der Schlüssel ist der Vorschlüssel selbst.
pub fn decrypt_system_masterkey(file: &[u8], key: &[u8; 20]) -> Result<[u8; 64], DpapiError> {
    decrypt_masterkey_with_prekey(file, key)
}

/// Gemeinsamer Kern: entschlüsselt den Masterkey einer MasterKeyFile mit einem
/// bereits abgeleiteten 20-Byte-Vorschlüssel.
fn decrypt_masterkey_with_prekey(file: &[u8], pre: &[u8; 20]) -> Result<[u8; 64], DpapiError> {
    let mk_len = le_u64(file, 100).ok_or(DpapiError::TooShort("Masterkey-Längen"))? as usize;
    let blob = file
        .get(MK_HEADER..MK_HEADER + mk_len)
        .ok_or(DpapiError::TooShort("Masterkey-Blob"))?;

    // Masterkey-Blob: Version(4), Salt(16), Runden(4), HashAlgo(4), CryptAlgo(4).
    let salt = blob
        .get(4..20)
        .ok_or(DpapiError::TooShort("Masterkey-Salt"))?;
    let rounds = le_u32(blob, 20).ok_or(DpapiError::TooShort("Masterkey-Runden"))?;
    let hash_algo = le_u32(blob, 24).ok_or(DpapiError::TooShort("Masterkey-HashAlgo"))?;
    let crypt_algo = le_u32(blob, 28).ok_or(DpapiError::TooShort("Masterkey-CryptAlgo"))?;
    let enc = blob
        .get(32..)
        .ok_or(DpapiError::TooShort("Masterkey-Daten"))?;

    if hash_algo != CALG_SHA_512 || crypt_algo != CALG_AES_256 {
        return Err(DpapiError::Unsupported {
            hash: hash_algo,
            crypt: crypt_algo,
        });
    }

    // PBKDF2-HMAC-SHA512 über den Vorschlüssel, Salt = Masterkey-Salt.
    // 32 Byte AES-Schlüssel + 16 Byte IV.
    let mut derived = [0u8; 48];
    pbkdf2::pbkdf2_hmac::<Sha512>(pre, salt, rounds, &mut derived);
    let aes_key: [u8; 32] = derived[..32].try_into().unwrap();
    let iv: [u8; 16] = derived[32..48].try_into().unwrap();

    // AES-256-CBC ohne Auffüllung (die Struktur ist blockausgerichtet).
    if !enc.len().is_multiple_of(16) || enc.len() < 144 {
        return Err(DpapiError::TooShort("Masterkey-Daten unpassend"));
    }
    let plain = aes256_cbc_decrypt(&aes_key, &iv, enc);

    // Klartext: hmacSalt(16) + hmac(64) + ... + Masterkey(64 am Ende).
    let hmac_salt = &plain[0..16];
    let hmac_stored = &plain[16..80];
    let key = &plain[plain.len() - 64..];

    // Prüf-HMAC: encKey = HMAC-SHA512(pre, hmacSalt); erwartet = HMAC-SHA512(encKey, key).
    let mut m1 = Hmac::<Sha512>::new_from_slice(pre).expect("HMAC-Schlüssel");
    m1.update(hmac_salt);
    let enc_key = m1.finalize().into_bytes();
    let mut m2 = Hmac::<Sha512>::new_from_slice(&enc_key).expect("HMAC-Schlüssel");
    m2.update(key);
    let expected = m2.finalize().into_bytes();
    if expected.as_slice() != hmac_stored {
        return Err(DpapiError::BadHmac);
    }

    let mut out = [0u8; 64];
    out.copy_from_slice(key);
    Ok(out)
}

/// Wandelt eine binäre GUID (aus einem DPAPI-Blob) in die Kleinschreib-Textform
/// ohne Klammern um, wie sie die Masterkey-Dateien als Namen tragen.
fn guid_to_string(g: &[u8]) -> Option<String> {
    if g.len() < 16 {
        return None;
    }
    let d1 = u32::from_le_bytes([g[0], g[1], g[2], g[3]]);
    let d2 = u16::from_le_bytes([g[4], g[5]]);
    let d3 = u16::from_le_bytes([g[6], g[7]]);
    Some(format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        d1, d2, d3, g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]
    ))
}

/// Liest die Masterkey-GUID, auf die sich ein DPAPI-Blob bezieht.
pub fn blob_masterkey_guid(blob: &[u8]) -> Result<String, DpapiError> {
    // Version(4) + ProviderGuid(16) + MkVersion(4) = 24, dann Mk-GUID(16).
    let g = blob.get(24..40).ok_or(DpapiError::TooShort("Blob-Kopf"))?;
    guid_to_string(g).ok_or(DpapiError::TooShort("Blob-GUID"))
}

/// Entschlüsselt einen DPAPI-Blob mit dem passenden Masterkey. `entropy` ist
/// optionale Zusatz-Entropie (bei Browser-Schlüsseln nicht verwendet).
pub fn decrypt_dpapi_blob(
    blob: &[u8],
    masterkey: &[u8; 64],
    entropy: Option<&[u8]>,
) -> Result<Vec<u8>, DpapiError> {
    // Kopf bis zur beschreibenden Zeichenkette überspringen:
    // Version(4) ProviderGuid(16) MkVersion(4) MkGuid(16) Flags(4) = 44,
    // DescLen(4) + Desc(DescLen).
    let mut off = 44;
    let desc_len = le_u32(blob, off).ok_or(DpapiError::TooShort("Blob-Desc"))? as usize;
    off += 4 + desc_len;

    let crypt_algo = le_u32(blob, off).ok_or(DpapiError::TooShort("Blob-CryptAlgo"))?;
    off += 4;
    let _crypt_len = le_u32(blob, off).ok_or(DpapiError::TooShort("Blob-CryptLen"))?;
    off += 4;
    let salt_len = le_u32(blob, off).ok_or(DpapiError::TooShort("Blob-SaltLen"))? as usize;
    off += 4;
    let salt = blob
        .get(off..off + salt_len)
        .ok_or(DpapiError::TooShort("Blob-Salt"))?
        .to_vec();
    off += salt_len;
    let hmac_key_len = le_u32(blob, off).ok_or(DpapiError::TooShort("Blob-HmacKeyLen"))? as usize;
    off += 4 + hmac_key_len;
    let hash_algo = le_u32(blob, off).ok_or(DpapiError::TooShort("Blob-HashAlgo"))?;
    off += 4;
    let _hash_len = le_u32(blob, off).ok_or(DpapiError::TooShort("Blob-HashLen"))?;
    off += 4;
    let hmac2_len = le_u32(blob, off).ok_or(DpapiError::TooShort("Blob-Hmac2Len"))? as usize;
    off += 4 + hmac2_len;
    let data_len = le_u32(blob, off).ok_or(DpapiError::TooShort("Blob-DataLen"))? as usize;
    off += 4;
    let data = blob
        .get(off..off + data_len)
        .ok_or(DpapiError::TooShort("Blob-Data"))?;

    if hash_algo != CALG_SHA_512 || crypt_algo != CALG_AES_256 {
        return Err(DpapiError::Unsupported {
            hash: hash_algo,
            crypt: crypt_algo,
        });
    }

    // sessionKey = HMAC-SHA512(masterkey, salt [+ entropy]).
    let mut mac = Hmac::<Sha512>::new_from_slice(masterkey).expect("HMAC-Schlüssel");
    mac.update(&salt);
    if let Some(e) = entropy {
        mac.update(e);
    }
    let session_key = mac.finalize().into_bytes(); // 64 Byte

    // SHA-512-Digest (64) >= AES-256-Schlüssel (32): sessionKey direkt nutzen,
    // Schlüssel = erste 32 Byte, IV = Null.
    let aes_key: [u8; 32] = session_key[..32].try_into().unwrap();
    let iv = [0u8; 16];

    if !data.len().is_multiple_of(16) || data.is_empty() {
        return Err(DpapiError::TooShort("Blob-Data unpassend"));
    }
    Ok(aes256_cbc_decrypt(&aes_key, &iv, data))
}

/// Entschlüsselt den Chromium-Schlüssel aus dem `Local State`-Wert. `key_blob`
/// ist der base64-dekodierte `encrypted_key` inklusive `DPAPI`-Präfix. Liefert
/// den 32-Byte-AES-GCM-Schlüssel.
pub fn chromium_key(key_blob: &[u8], masterkey: &[u8; 64]) -> Result<[u8; 32], DpapiError> {
    let blob = key_blob
        .strip_prefix(b"DPAPI")
        .ok_or(DpapiError::UnknownPasswordFormat)?;
    let plain = decrypt_dpapi_blob(blob, masterkey, None)?;
    let key: [u8; 32] = plain
        .get(..32)
        .ok_or(DpapiError::TooShort("Chromium-Schlüssel"))?
        .try_into()
        .unwrap();
    Ok(key)
}

/// Entschlüsselt ein Chromium-Passwort (`password_value` aus `Login Data`) mit
/// dem AES-GCM-Schlüssel. Erwartet das Format `v10`/`v11`:
/// Präfix(3) + Nonce(12) + Chiffrat + GCM-Tag(16).
pub fn chromium_password(value: &[u8], key: &[u8; 32]) -> Result<String, DpapiError> {
    let rest = value
        .strip_prefix(b"v10")
        .or_else(|| value.strip_prefix(b"v11"))
        .ok_or(DpapiError::UnknownPasswordFormat)?;
    if rest.len() < 12 + 16 {
        return Err(DpapiError::TooShort("Passwort-Chiffrat"));
    }
    let (nonce, ct) = rest.split_at(12);
    let nonce = Nonce::try_from(nonce).map_err(|_| DpapiError::TooShort("Nonce"))?;
    let cipher = Aes256Gcm::new(key.into());
    let plain = cipher
        .decrypt(&nonce, ct)
        .map_err(|_| DpapiError::GcmFailed)?;
    Ok(String::from_utf8_lossy(&plain).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aes256_cbc_encrypt;

    const CALG_SHA1: u32 = 0x8004;
    const CALG_3DES: u32 = 0x6603;

    // Baut eine MasterKeyFile, aus der sich ein gewählter Masterkey mit
    // password/SID wieder ableiten lässt (Round-Trip, gleiche Ableitung wie im
    // Produktionspfad).
    fn build_masterkey_file(
        masterkey: &[u8; 64],
        pre: &[u8; 20],
        salt: &[u8; 16],
        rounds: u32,
    ) -> Vec<u8> {
        // Prüf-HMAC über hmacSalt und Masterkey.
        let hmac_salt = [0x22u8; 16];
        let mut m1 = Hmac::<Sha512>::new_from_slice(pre).unwrap();
        m1.update(&hmac_salt);
        let enc_key = m1.finalize().into_bytes();
        let mut m2 = Hmac::<Sha512>::new_from_slice(&enc_key).unwrap();
        m2.update(masterkey);
        let hmac = m2.finalize().into_bytes();

        let mut plain = Vec::new();
        plain.extend_from_slice(&hmac_salt);
        plain.extend_from_slice(&hmac); // 64
        plain.extend_from_slice(masterkey); // 64
        while !plain.len().is_multiple_of(16) {
            plain.push(0);
        }

        let mut derived = [0u8; 48];
        pbkdf2::pbkdf2_hmac::<Sha512>(pre, salt, rounds, &mut derived);
        let aes_key: [u8; 32] = derived[..32].try_into().unwrap();
        let iv: [u8; 16] = derived[32..48].try_into().unwrap();
        let enc = aes256_cbc_encrypt(&aes_key, &iv, &plain);

        // Masterkey-Blob.
        let mut mk = Vec::new();
        mk.extend_from_slice(&2u32.to_le_bytes()); // Version
        mk.extend_from_slice(salt);
        mk.extend_from_slice(&rounds.to_le_bytes());
        mk.extend_from_slice(&CALG_SHA_512.to_le_bytes());
        mk.extend_from_slice(&CALG_AES_256.to_le_bytes());
        mk.extend_from_slice(&enc);

        // Datei-Kopf: 132 Byte, dann Längen und Blob.
        let mut file = vec![0u8; MK_HEADER];
        file[100..108].copy_from_slice(&(mk.len() as u64).to_le_bytes());
        file.extend_from_slice(&mk);
        file
    }

    #[test]
    fn masterkey_round_trip() {
        let masterkey: [u8; 64] = std::array::from_fn(|i| (i * 7) as u8);
        let sid = "S-1-5-21-111-222-333-1001";
        let pwd_sha1 = sha1_password("KennwortÖ123");
        let file = build_masterkey_file(&masterkey, &prekey(&pwd_sha1, sid), &[0x11; 16], 8000);
        let got = decrypt_masterkey(&file, sid, &pwd_sha1).unwrap();
        assert_eq!(got, masterkey);
    }

    #[test]
    fn system_masterkey_round_trip() {
        // System-Pfad: der 20-Byte-Schlüssel aus DPAPI_SYSTEM ist selbst der
        // Vorschlüssel, keine SID-Ableitung.
        let masterkey: [u8; 64] = std::array::from_fn(|i| (i as u8) ^ 0x5a);
        let key = [0x3cu8; 20];
        let file = build_masterkey_file(&masterkey, &key, &[0x44; 16], 12000);
        assert_eq!(decrypt_system_masterkey(&file, &key).unwrap(), masterkey);
        assert_eq!(
            decrypt_system_masterkey(&file, &[0u8; 20]),
            Err(DpapiError::BadHmac)
        );
    }

    #[test]
    fn falsches_passwort_meldet_hmac_fehler() {
        let masterkey = [0x42u8; 64];
        let sid = "S-1-5-21-1-2-3-1001";
        let file = build_masterkey_file(
            &masterkey,
            &prekey(&sha1_password("richtig"), sid),
            &[7; 16],
            4000,
        );
        let r = decrypt_masterkey(&file, sid, &sha1_password("falsch"));
        assert_eq!(r, Err(DpapiError::BadHmac));
    }

    #[test]
    fn alter_algorithmus_wird_gemeldet() {
        let mut file = vec![0u8; MK_HEADER];
        let mut mk = Vec::new();
        mk.extend_from_slice(&2u32.to_le_bytes());
        mk.extend_from_slice(&[0u8; 16]);
        mk.extend_from_slice(&4000u32.to_le_bytes());
        mk.extend_from_slice(&CALG_SHA1.to_le_bytes());
        mk.extend_from_slice(&CALG_3DES.to_le_bytes());
        mk.extend_from_slice(&[0u8; 160]);
        file[100..108].copy_from_slice(&(mk.len() as u64).to_le_bytes());
        file.extend_from_slice(&mk);
        assert_eq!(
            decrypt_masterkey(&file, "S-1-5-21-1-1-1-1", &[0; 20]),
            Err(DpapiError::Unsupported {
                hash: CALG_SHA1,
                crypt: CALG_3DES
            })
        );
    }

    // Baut einen DPAPI-Blob, der einen Klartext mit gegebenem Masterkey trägt.
    fn build_blob(plain: &[u8], masterkey: &[u8; 64], salt: &[u8], guid: &[u8; 16]) -> Vec<u8> {
        let mut mac = Hmac::<Sha512>::new_from_slice(masterkey).unwrap();
        mac.update(salt);
        let session_key = mac.finalize().into_bytes();
        let aes_key: [u8; 32] = session_key[..32].try_into().unwrap();
        let iv = [0u8; 16];
        let mut buf = plain.to_vec();
        while !buf.len().is_multiple_of(16) {
            buf.push(0);
        }
        let enc = aes256_cbc_encrypt(&aes_key, &iv, &buf);

        let mut b = Vec::new();
        b.extend_from_slice(&1u32.to_le_bytes()); // Version
        b.extend_from_slice(&[0u8; 16]); // ProviderGuid
        b.extend_from_slice(&1u32.to_le_bytes()); // MkVersion
        b.extend_from_slice(guid); // MkGuid
        b.extend_from_slice(&0u32.to_le_bytes()); // Flags
        b.extend_from_slice(&0u32.to_le_bytes()); // DescLen
        b.extend_from_slice(&CALG_AES_256.to_le_bytes());
        b.extend_from_slice(&256u32.to_le_bytes()); // CryptLen
        b.extend_from_slice(&(salt.len() as u32).to_le_bytes());
        b.extend_from_slice(salt);
        b.extend_from_slice(&0u32.to_le_bytes()); // HmacKeyLen
        b.extend_from_slice(&CALG_SHA_512.to_le_bytes());
        b.extend_from_slice(&512u32.to_le_bytes()); // HashLen
        b.extend_from_slice(&0u32.to_le_bytes()); // Hmac2Len
        b.extend_from_slice(&(enc.len() as u32).to_le_bytes());
        b.extend_from_slice(&enc);
        b.extend_from_slice(&0u32.to_le_bytes()); // SignLen
        b
    }

    #[test]
    fn blob_round_trip_und_guid() {
        let masterkey = [0x5au8; 64];
        let guid = [
            0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef,
        ];
        let secret = b"\x01\x02\x03\x04 geheim";
        let blob = build_blob(secret, &masterkey, &[0x33; 16], &guid);
        assert_eq!(
            blob_masterkey_guid(&blob).unwrap(),
            "12345678-9abc-def0-0123-456789abcdef"
        );
        let out = decrypt_dpapi_blob(&blob, &masterkey, None).unwrap();
        assert!(out.starts_with(secret));
    }

    #[test]
    fn chromium_passwort_round_trip() {
        let key = [0x77u8; 32];
        let cipher = Aes256Gcm::new((&key).into());
        let nonce = [0x09u8; 12];
        let ct = cipher
            .encrypt(
                &Nonce::try_from(&nonce[..]).unwrap(),
                b"geheimes-passwort".as_ref(),
            )
            .unwrap();
        let mut value = Vec::from(*b"v10");
        value.extend_from_slice(&nonce);
        value.extend_from_slice(&ct);
        assert_eq!(
            chromium_password(&value, &key).unwrap(),
            "geheimes-passwort"
        );
        assert_eq!(
            chromium_password(b"xyz...", &key),
            Err(DpapiError::UnknownPasswordFormat)
        );
    }
}
