//! Ableitung von Bootkey, Hashed-Bootkey und NT-Hashes aus den rohen
//! `F`- und `V`-Strukturen des SAM-Hives.
//!
//! Die Byte-Offsets folgen der öffentlichen Beschreibung des SAM-Formats
//! (creddump7 / Impacket). Sie sind als benannte Konstanten geführt, damit sie
//! nachprüfbar bleiben. Der modernere AES-Pfad gilt ab Windows 10 1607, der
//! RC4-Pfad für ältere Systeme.

use crate::crypto::{aes128_cbc_decrypt, des_decrypt_block, md5, rc4, sid_to_keys};

/// NT-Hash eines leeren Passworts (MD4 der leeren Eingabe). Wird gemeldet, wenn
/// kein verschlüsselter Hash hinterlegt ist.
pub const EMPTY_NT_HASH: [u8; 16] = [
    0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31, 0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0,
];

const AQWERTY: &[u8] = b"!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0";
const ANUM: &[u8] = b"0123456789012345678901234567890123456789\0";
const NTPASSWORD: &[u8] = b"NTPASSWORD\0";

/// Permutation, die den verwürfelten Bootkey aus den vier Class-Werten
/// (JD, Skew1, GBG, Data) in die richtige Reihenfolge bringt.
const BOOTKEY_PERMUTATION: [usize; 16] = [
    0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7,
];

/// Fehler bei der SAM-Auswertung.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SamError {
    /// Die vier Class-Werte ergeben nicht die erwarteten 16 Bootkey-Bytes.
    #[error("Bootkey unvollständig: {0} von 16 Bytes")]
    BootkeyIncomplete(usize),

    /// Die F-Struktur ist zu kurz oder hat eine unbekannte Revision.
    #[error("F-Struktur ungültig: {0}")]
    BadF(&'static str),

    /// Eine V-Struktur ist zu kurz oder verweist über ihr Ende hinaus.
    #[error("V-Struktur ungültig: {0}")]
    BadV(&'static str),
}

/// Ergebnis der NT-Hash-Ableitung eines Kontos.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserHash {
    /// Relative Kennung des Kontos.
    pub rid: u32,
    /// Benutzername.
    pub username: String,
    /// NT-Hash (16 Bytes).
    pub nt_hash: [u8; 16],
    /// Ob ein Hash hinterlegt war. `false` bedeutet leeres Passwort.
    pub has_hash: bool,
}

/// Setzt den Bootkey aus den vier Class-Werten zusammen.
///
/// Jeder Wert ist ein Hex-Text (aus dem Class-Feld der Schlüssel `JD`,
/// `Skew1`, `GBG`, `Data`). Reihenfolge der Werte muss JD, Skew1, GBG, Data
/// sein.
pub fn bootkey_from_classes(classes: &[String; 4]) -> Result<[u8; 16], SamError> {
    let mut scrambled = Vec::with_capacity(16);
    for c in classes {
        scrambled.extend_from_slice(&unhex(c));
    }
    if scrambled.len() < 16 {
        return Err(SamError::BootkeyIncomplete(scrambled.len()));
    }
    let mut bootkey = [0u8; 16];
    for (i, &p) in BOOTKEY_PERMUTATION.iter().enumerate() {
        bootkey[i] = scrambled[p];
    }
    Ok(bootkey)
}

/// Leitet den Hashed-Bootkey aus der F-Struktur und dem Bootkey ab.
pub fn hashed_bootkey(f: &[u8], bootkey: &[u8; 16]) -> Result<[u8; 16], SamError> {
    if f.len() < 0xA8 {
        return Err(SamError::BadF("kürzer als 0xA8 Bytes"));
    }
    let revision = f[0x00];
    let mut hbootkey = [0u8; 16];
    match revision {
        // Ältere Systeme: RC4.
        2 => {
            let salt = &f[0x70..0x80];
            let enc = &f[0x80..0xA0];
            let key = md5(&[salt, AQWERTY, bootkey, ANUM]);
            let dec = rc4(&key, enc);
            hbootkey.copy_from_slice(&dec[..16]);
        }
        // Windows 10 1607 und neuer: AES-128-CBC.
        3 => {
            let iv: [u8; 16] = f[0x78..0x88].try_into().unwrap();
            let enc = &f[0x88..0xA8];
            let dec = aes128_cbc_decrypt(bootkey, &iv, enc);
            if dec.len() < 16 {
                return Err(SamError::BadF("AES-Ausgabe zu kurz"));
            }
            hbootkey.copy_from_slice(&dec[..16]);
        }
        _ => return Err(SamError::BadF("unbekannte Revision")),
    }
    Ok(hbootkey)
}

/// Liest Benutzername und NT-Hash aus der V-Struktur eines Kontos.
pub fn user_hash(v: &[u8], rid: u32, hbootkey: &[u8; 16]) -> Result<UserHash, SamError> {
    const BASE: usize = 0xCC;
    if v.len() < BASE {
        return Err(SamError::BadV("kürzer als der Zeigertabellen-Kopf"));
    }

    let username = read_utf16(v, le32(v, 0x0c) as usize + BASE, le32(v, 0x10) as usize)
        .ok_or(SamError::BadV("Benutzername ausserhalb"))?;

    // Zeiger auf die NT-Hash-Struktur.
    let nt_off = le32(v, 0xa8) as usize + BASE;
    let nt_len = le32(v, 0xac) as usize;

    let (nt_hash, has_hash) = match decrypt_hash(v, nt_off, nt_len, hbootkey, rid)? {
        Some(obf) => (deobfuscate(&obf, rid), true),
        // Kein Hash hinterlegt (deaktiviertes oder passwortloses Konto): das ist
        // kein Fehler, sondern ein leeres Passwort. Die eingebauten Konten
        // (Administrator, Gast, DefaultAccount) fallen typischerweise hierunter.
        None => (EMPTY_NT_HASH, false),
    };

    Ok(UserHash {
        rid,
        username,
        nt_hash,
        has_hash,
    })
}

/// Entschlüsselt die äussere Schicht (RC4 oder AES) der Hash-Struktur und
/// liefert die noch DES-verschleierten 16 Bytes.
///
/// `Ok(None)` bedeutet: Die Struktur hat ein bekanntes Format, enthält aber
/// keine Hash-Daten. Das ist der Normalfall bei Konten ohne gesetztes Passwort
/// (z. B. die eingebauten Administrator-, Gast- und DefaultAccount-Konten) und
/// wird vom Aufrufer als leeres Passwort gewertet, nicht als Fehler.
fn decrypt_hash(
    v: &[u8],
    off: usize,
    len: usize,
    hbootkey: &[u8; 16],
    rid: u32,
) -> Result<Option<[u8; 16]>, SamError> {
    if len == 0 {
        return Ok(None);
    }
    let header = v
        .get(off..off + 4)
        .ok_or(SamError::BadV("Hash-Kopf ausserhalb"))?;
    let revision = header[2];
    let mut obf = [0u8; 16];

    match revision {
        // RC4: volle Struktur ist 20 Bytes, Hash bei off+4..off+20.
        1 if len >= 20 => {
            let enc = v
                .get(off + 4..off + 20)
                .ok_or(SamError::BadV("RC4-Hash ausserhalb"))?;
            let key = md5(&[&hbootkey[..16], &rid.to_le_bytes(), NTPASSWORD]);
            obf.copy_from_slice(&rc4(&key, enc));
        }
        // AES: volle Struktur ist 56 Bytes, Salt bei off+8..off+24,
        // Chiffrat bei off+24..off+56.
        2 if len >= 56 => {
            let iv: [u8; 16] = v
                .get(off + 8..off + 24)
                .ok_or(SamError::BadV("AES-Salt ausserhalb"))?
                .try_into()
                .unwrap();
            let enc = v
                .get(off + 24..off + 56)
                .ok_or(SamError::BadV("AES-Hash ausserhalb"))?;
            let dec = aes128_cbc_decrypt(hbootkey, &iv, enc);
            if dec.len() < 16 {
                return Err(SamError::BadV("AES-Ausgabe zu kurz"));
            }
            obf.copy_from_slice(&dec[..16]);
        }
        // Bekannte Revision, aber die Struktur trägt keine Hash-Daten: leeres
        // Passwort.
        1 | 2 => return Ok(None),
        _ => return Err(SamError::BadV("unbekannte Hash-Revision")),
    }
    Ok(Some(obf))
}

/// Entfernt die DES-Verschleierung mit den aus der RID abgeleiteten Schlüsseln.
fn deobfuscate(obf: &[u8; 16], rid: u32) -> [u8; 16] {
    let (k1, k2) = sid_to_keys(rid);
    let mut out = [0u8; 16];
    let a: [u8; 8] = obf[..8].try_into().unwrap();
    let b: [u8; 8] = obf[8..].try_into().unwrap();
    out[..8].copy_from_slice(&des_decrypt_block(&k1, &a));
    out[8..].copy_from_slice(&des_decrypt_block(&k2, &b));
    out
}

fn le32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn read_utf16(data: &[u8], off: usize, len: usize) -> Option<String> {
    let raw = data.get(off..off.checked_add(len)?)?;
    let units: Vec<u16> = raw
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    Some(String::from_utf16_lossy(&units))
}

fn unhex(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    b.chunks_exact(2)
        .filter_map(|c| {
            let hi = (c[0] as char).to_digit(16)?;
            let lo = (c[1] as char).to_digit(16)?;
            Some((hi * 16 + lo) as u8)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{aes128_cbc_encrypt, des_encrypt_block};

    fn hexs(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn bootkey_permutation() {
        // scrambled[i] = i, damit bootkey[i] = permutation[i] direkt sichtbar wird.
        let scrambled: Vec<u8> = (0..16).collect();
        let classes = [
            hexs(&scrambled[0..4]),
            hexs(&scrambled[4..8]),
            hexs(&scrambled[8..12]),
            hexs(&scrambled[12..16]),
        ];
        let bk = bootkey_from_classes(&classes).unwrap();
        assert_eq!(bk, BOOTKEY_PERMUTATION.map(|p| p as u8));
    }

    #[test]
    fn bootkey_unvollständig() {
        let classes = ["00".into(), "".into(), "".into(), "".into()];
        assert!(matches!(
            bootkey_from_classes(&classes),
            Err(SamError::BootkeyIncomplete(1))
        ));
    }

    // Baut eine F-Struktur für den AES-Pfad (Revision 3) mit bekanntem
    // Hashed-Bootkey und prüft die Rückgewinnung.
    #[test]
    fn hashed_bootkey_aes_roundtrip() {
        let bootkey = [7u8; 16];
        let hbootkey = [0x42u8; 16];
        let iv = [9u8; 16];
        // 32 Bytes Klartext: erste 16 = hbootkey, Rest beliebig.
        let mut plain = [0u8; 32];
        plain[..16].copy_from_slice(&hbootkey);
        let enc = aes128_cbc_encrypt(&bootkey, &iv, &plain);

        let mut f = vec![0u8; 0xA8];
        f[0x00] = 3;
        f[0x78..0x88].copy_from_slice(&iv);
        f[0x88..0xA8].copy_from_slice(&enc);

        assert_eq!(hashed_bootkey(&f, &bootkey).unwrap(), hbootkey);
    }

    #[test]
    fn f_zu_kurz() {
        assert!(matches!(
            hashed_bootkey(&[0u8; 10], &[0u8; 16]),
            Err(SamError::BadF(_))
        ));
    }

    /// Baut eine V-Struktur für den AES-NT-Hash-Pfad mit gesetztem
    /// Benutzernamen und einem Ziel-NT-Hash und prüft die Rückgewinnung.
    fn build_v_aes(username: &str, nt_hash: &[u8; 16], hbootkey: &[u8; 16], rid: u32) -> Vec<u8> {
        const BASE: usize = 0xCC;
        // Verschleiern: DES-verschlüsseln, dann AES-verschlüsseln.
        let (k1, k2) = sid_to_keys(rid);
        let mut obf = [0u8; 16];
        obf[..8].copy_from_slice(&des_encrypt_block(&k1, &nt_hash[..8].try_into().unwrap()));
        obf[8..].copy_from_slice(&des_encrypt_block(&k2, &nt_hash[8..].try_into().unwrap()));
        let salt = [3u8; 16];
        // 32 Bytes Klartext (obf + Füllung), damit das Chiffrat 32 Bytes hat.
        let mut plain = [0u8; 32];
        plain[..16].copy_from_slice(&obf);
        let enc = aes128_cbc_encrypt(hbootkey, &salt, &plain);

        let name_utf16: Vec<u8> = username.encode_utf16().flat_map(u16::to_le_bytes).collect();

        // Layout: [0..BASE) Kopf, dann Name, dann NT-Struktur.
        let name_off = 0usize; // relativ zu BASE
        let nt_rel = name_utf16.len(); // relativ zu BASE
        let nt_struct_len = 4 + 4 + 16 + 32; // Kopf + Reserve + Salt + Chiffrat
        let total = BASE + nt_rel + nt_struct_len;
        let mut v = vec![0u8; total];

        // Benutzername-Zeiger.
        v[0x0c..0x10].copy_from_slice(&(name_off as u32).to_le_bytes());
        v[0x10..0x14].copy_from_slice(&(name_utf16.len() as u32).to_le_bytes());
        // NT-Hash-Zeiger.
        v[0xa8..0xac].copy_from_slice(&(nt_rel as u32).to_le_bytes());
        v[0xac..0xb0].copy_from_slice(&56u32.to_le_bytes());

        v[BASE + name_off..BASE + name_off + name_utf16.len()].copy_from_slice(&name_utf16);

        let ns = BASE + nt_rel;
        v[ns + 2] = 2; // Revision AES
        v[ns + 8..ns + 24].copy_from_slice(&salt);
        v[ns + 24..ns + 56].copy_from_slice(&enc);
        v
    }

    #[test]
    fn user_hash_aes_roundtrip() {
        let hbootkey = [0x11u8; 16];
        let rid = 1001;
        // Beliebiger Ziel-NT-Hash.
        let target = [
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99,
        ];
        let v = build_v_aes("Alice", &target, &hbootkey, rid);
        let u = user_hash(&v, rid, &hbootkey).unwrap();
        assert_eq!(u.username, "Alice");
        assert_eq!(u.rid, rid);
        assert!(u.has_hash);
        assert_eq!(u.nt_hash, target);
    }

    #[test]
    fn aes_struktur_ohne_hashdaten_ist_leeres_passwort() {
        // Deaktivierte Konten (z. B. Administrator, Gast) tragen eine
        // AES-Struktur mit Revision 2, aber ohne Hash-Daten (Laenge 24 statt 56).
        const BASE: usize = 0xCC;
        let name: Vec<u8> = "Administrator"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let nt_rel = name.len();
        let mut v = vec![0u8; BASE + nt_rel + 24];
        v[0x0c..0x10].copy_from_slice(&0u32.to_le_bytes());
        v[0x10..0x14].copy_from_slice(&(name.len() as u32).to_le_bytes());
        v[0xa8..0xac].copy_from_slice(&(nt_rel as u32).to_le_bytes());
        v[0xac..0xb0].copy_from_slice(&24u32.to_le_bytes());
        v[BASE..BASE + name.len()].copy_from_slice(&name);
        let ns = BASE + nt_rel;
        v[ns + 2] = 2; // Revision AES, aber Laenge 24 -> keine Daten

        let u = user_hash(&v, 500, &[0u8; 16]).unwrap();
        assert_eq!(u.username, "Administrator");
        assert!(!u.has_hash);
        assert_eq!(u.nt_hash, EMPTY_NT_HASH);
    }

    #[test]
    fn user_ohne_hash_ist_leeres_passwort() {
        const BASE: usize = 0xCC;
        let name: Vec<u8> = "Gast".encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut v = vec![0u8; BASE + name.len()];
        v[0x0c..0x10].copy_from_slice(&0u32.to_le_bytes());
        v[0x10..0x14].copy_from_slice(&(name.len() as u32).to_le_bytes());
        v[0xa8..0xac].copy_from_slice(&0u32.to_le_bytes());
        v[0xac..0xb0].copy_from_slice(&0u32.to_le_bytes());
        v[BASE..].copy_from_slice(&name);

        let u = user_hash(&v, 501, &[0u8; 16]).unwrap();
        assert_eq!(u.username, "Gast");
        assert!(!u.has_hash);
        assert_eq!(u.nt_hash, EMPTY_NT_HASH);
    }
}
