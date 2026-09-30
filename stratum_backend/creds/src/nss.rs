//! Entschlüsselung der in Firefox gespeicherten Zugangsdaten (Mozilla NSS).
//!
//! Firefox legt die Zugangsdaten in `logins.json` ab, verschlüsselt mit einem
//! Master-Schlüssel, der wiederum in `key4.db` (SQLite) steht und aus dem
//! optionalen Hauptpasswort abgeleitet wird. Ohne Hauptpasswort (der Normalfall)
//! genügt eine leere Zeichenkette.
//!
//! Ablauf:
//! 1. Aus `key4.db`: `globalSalt` (Tabelle `metaData`, id `password`, Spalte
//!    `item1`) und der Prüfwert `item2`; dazu der verschlüsselte Master-Schlüssel
//!    aus `nssPrivate` (Spalte `a11`, wo `a102` die feste Kennung
//!    `f8000000000000000000000000000001` trägt).
//! 2. `item2` und `a11` sind PBES2-Strukturen (PBKDF2-HMAC-SHA256 + AES-256-CBC).
//!    Der Schlüssel ergibt sich aus `SHA1(globalSalt + Hauptpasswort)`. `item2`
//!    entschlüsselt zu `password-check` und bestätigt so das Passwort; `a11`
//!    liefert den 24-Byte-Master-Schlüssel (3DES).
//! 3. Jeder Eintrag in `logins.json` (`encryptedUsername`, `encryptedPassword`)
//!    ist eine SDR-Struktur mit 3DES-CBC und wird mit dem Master-Schlüssel
//!    entschlüsselt.
//!
//! Das heute übliche Format (AES-256 in `key4.db`, 3DES bei den Einträgen) ist
//! umgesetzt und gegen echte Profile geprüft. Ältere Profile mit 3DES-PBE in
//! `key4.db` oder das alte `key3.db` werden erkannt und als nicht unterstützt
//! gemeldet, statt geraten zu werden.

use sha1::{Digest, Sha1};
use sha2::Sha256;

use crate::crypto::{aes256_cbc_decrypt, tdes_cbc_decrypt};

/// Feste Kennung des SDR-Master-Schlüssels in `nssPrivate` (Spalte `a102`).
pub const CKA_ID: [u8; 16] = [0xf8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];

// OID-Werte (nur der Inhalt, ohne Tag und Länge).
const OID_PBES2: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d];
const OID_PBKDF2: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c];
const OID_AES256_CBC: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a];
const OID_DES_EDE3_CBC: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x03, 0x07];

/// Fehler der NSS-Auswertung.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NssError {
    /// Eine ASN.1-Struktur ist unerwartet aufgebaut oder zu kurz.
    #[error("ASN.1-Struktur unerwartet: {0}")]
    Asn1(&'static str),
    /// Ein nicht unterstütztes (älteres) Verschlüsselungsverfahren.
    #[error("nicht unterstütztes NSS-Verfahren (altes key3.db oder 3DES-key4.db)")]
    Unsupported,
    /// Das Hauptpasswort ist falsch (Prüfwert stimmt nicht).
    #[error("Hauptpasswort falsch (Pruefwert stimmt nicht)")]
    WrongPassword,
    /// Der entschlüsselte Wert ist keine gültige Zeichenkette.
    #[error("entschluesselter Wert ist kein Text")]
    NotText,
}

/// Ein einzelnes ASN.1-DER-Element (Typ, Länge, Inhalt).
struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
}

/// Liest ein einzelnes DER-Element am Anfang von `data` und gibt es samt Rest
/// zurück.
fn read_tlv<'a>(data: &'a [u8]) -> Result<(Tlv<'a>, &'a [u8]), NssError> {
    if data.len() < 2 {
        return Err(NssError::Asn1("zu kurz"));
    }
    let tag = data[0];
    let first = data[1];
    let (len, header) = if first < 0x80 {
        (first as usize, 2)
    } else {
        // Lange Form: die unteren 7 Bit geben die Anzahl der Längenbytes an.
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 || data.len() < 2 + n {
            return Err(NssError::Asn1("Laenge"));
        }
        let mut len = 0usize;
        for &b in &data[2..2 + n] {
            len = (len << 8) | b as usize;
        }
        (len, 2 + n)
    };
    let end = header.checked_add(len).ok_or(NssError::Asn1("Ueberlauf"))?;
    let value = data.get(header..end).ok_or(NssError::Asn1("Inhalt"))?;
    Ok((Tlv { tag, value }, &data[end..]))
}

/// Zerlegt den Inhalt einer SEQUENCE in ihre Elemente.
fn seq_items<'a>(tlv: &Tlv<'a>) -> Result<Vec<Tlv<'a>>, NssError> {
    if tlv.tag != 0x30 {
        return Err(NssError::Asn1("keine SEQUENCE"));
    }
    let mut rest = tlv.value;
    let mut out = Vec::new();
    while !rest.is_empty() {
        let (item, r) = read_tlv(rest)?;
        out.push(item);
        rest = r;
    }
    Ok(out)
}

/// Liest genau ein Element aus einem Puffer (Wurzel eines DER-Blobs).
fn root<'a>(data: &'a [u8]) -> Result<Tlv<'a>, NssError> {
    Ok(read_tlv(data)?.0)
}

/// Liest eine kleine INTEGER als `usize` (für Iterationszahl und Schlüssellänge).
fn int_usize(tlv: &Tlv<'_>) -> Result<usize, NssError> {
    if tlv.tag != 0x02 || tlv.value.is_empty() || tlv.value.len() > 4 {
        return Err(NssError::Asn1("INTEGER"));
    }
    let mut v = 0usize;
    for &b in tlv.value {
        v = (v << 8) | b as usize;
    }
    Ok(v)
}

fn expect(tag: u8, tlv: &Tlv<'_>, what: &'static str) -> Result<(), NssError> {
    if tlv.tag == tag {
        Ok(())
    } else {
        Err(NssError::Asn1(what))
    }
}

/// Entschlüsselt eine PBES2-Struktur (PBKDF2-HMAC-SHA256 + AES-256-CBC), wie sie
/// in `key4.db` für Prüfwert und Master-Schlüssel steht. `password` ist das mit
/// dem globalen Salz vorbereitete Geheimnis (`SHA1(globalSalt + Hauptpasswort)`).
fn pbes2_decrypt(prepared: &[u8], blob: &[u8]) -> Result<Vec<u8>, NssError> {
    // SEQUENCE { SEQUENCE { OID PBES2, SEQUENCE { kdf, enc } }, OCTET cipher }
    let outer = seq_items(&root(blob)?)?;
    let [algo, cipher] = outer.as_slice() else {
        return Err(NssError::Asn1("PBES2-Rahmen"));
    };
    let algo = seq_items(algo)?;
    let [oid, params] = algo.as_slice() else {
        return Err(NssError::Asn1("PBES2-Algo"));
    };
    if oid.tag != 0x06 || oid.value != OID_PBES2 {
        return Err(NssError::Unsupported);
    }
    let params = seq_items(params)?;
    let [kdf, enc] = params.as_slice() else {
        return Err(NssError::Asn1("PBES2-Parameter"));
    };

    // KDF: SEQUENCE { OID PBKDF2, SEQUENCE { salt, iters, keylen, prf } }
    let kdf = seq_items(kdf)?;
    let [kdf_oid, kdf_params] = kdf.as_slice() else {
        return Err(NssError::Asn1("KDF"));
    };
    if kdf_oid.tag != 0x06 || kdf_oid.value != OID_PBKDF2 {
        return Err(NssError::Unsupported);
    }
    let kdf_params = seq_items(kdf_params)?;
    if kdf_params.len() < 3 {
        return Err(NssError::Asn1("PBKDF2-Parameter"));
    }
    expect(0x04, &kdf_params[0], "entrySalt")?;
    let entry_salt = kdf_params[0].value;
    let iters = int_usize(&kdf_params[1])?;
    let keylen = int_usize(&kdf_params[2])?;
    if !(16..=64).contains(&keylen) || iters == 0 {
        return Err(NssError::Asn1("KDF-Werte"));
    }

    // Verschlüsselung: SEQUENCE { OID aes256-CBC, OCTET iv14 }
    let enc = seq_items(enc)?;
    let [enc_oid, iv_item] = enc.as_slice() else {
        return Err(NssError::Asn1("Enc"));
    };
    if enc_oid.tag != 0x06 || enc_oid.value != OID_AES256_CBC {
        return Err(NssError::Unsupported);
    }
    expect(0x04, iv_item, "iv")?;
    // NSS legt die 14 IV-Bytes ohne den DER-Kopf ab; der echte 16-Byte-IV ist
    // die OCTET-STRING-Kodierung selbst, also `04 0e` gefolgt von den 14 Bytes.
    if iv_item.value.len() != 14 {
        return Err(NssError::Asn1("iv-Laenge"));
    }
    let mut iv = [0u8; 16];
    iv[0] = 0x04;
    iv[1] = 0x0e;
    iv[2..].copy_from_slice(iv_item.value);

    expect(0x04, cipher, "cipher")?;
    let ciphertext = cipher.value;
    if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(16) {
        return Err(NssError::Asn1("cipher-Laenge"));
    }

    let mut key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(prepared, entry_salt, iters as u32, &mut key);

    Ok(aes256_cbc_decrypt(&key, &iv, ciphertext))
}

/// Entfernt eine PKCS7-Auffüllung (Blockgröße `block`), falls vorhanden.
fn strip_pkcs7(data: &[u8], block: usize) -> &[u8] {
    let Some(&n) = data.last() else {
        return data;
    };
    let n = n as usize;
    if n >= 1
        && n <= block
        && n <= data.len()
        && data[data.len() - n..].iter().all(|&b| b as usize == n)
    {
        &data[..data.len() - n]
    } else {
        data
    }
}

/// Leitet den 24-Byte-Master-Schlüssel (3DES) aus `key4.db`-Werten ab und prüft
/// dabei das Hauptpasswort über den Prüfwert `item2`.
///
/// `global_salt` = `metaData.item1`, `item2_check` = `metaData.item2`,
/// `a11` = der Wert aus `nssPrivate`. `primary_password` ist leer, wenn kein
/// Hauptpasswort gesetzt ist.
pub fn master_key(
    global_salt: &[u8],
    item2_check: &[u8],
    a11: &[u8],
    primary_password: &str,
) -> Result<Vec<u8>, NssError> {
    let mut h = Sha1::new();
    h.update(global_salt);
    h.update(primary_password.as_bytes());
    let prepared = h.finalize();

    // Prüfwert: muss zu "password-check" entschlüsseln.
    let check = pbes2_decrypt(&prepared, item2_check)?;
    if !strip_pkcs7(&check, 16).starts_with(b"password-check") {
        return Err(NssError::WrongPassword);
    }

    let raw = pbes2_decrypt(&prepared, a11)?;
    let key = strip_pkcs7(&raw, 16);
    if key.len() < 24 {
        return Err(NssError::Asn1("Master-Schluessel zu kurz"));
    }
    Ok(key[..24].to_vec())
}

/// Entschlüsselt einen SDR-Eintrag aus `logins.json` (bereits base64-dekodiert)
/// mit dem Master-Schlüssel. Format:
/// `SEQUENCE { OCTET keyid, SEQUENCE { OID des-ede3-cbc, OCTET iv }, OCTET data }`.
pub fn decrypt_login(entry: &[u8], master_key: &[u8]) -> Result<String, NssError> {
    let items = seq_items(&root(entry)?)?;
    let [_keyid, algo, data] = items.as_slice() else {
        return Err(NssError::Asn1("SDR-Rahmen"));
    };
    let algo = seq_items(algo)?;
    let [oid, iv_item] = algo.as_slice() else {
        return Err(NssError::Asn1("SDR-Algo"));
    };
    if oid.tag != 0x06 || oid.value != OID_DES_EDE3_CBC {
        return Err(NssError::Unsupported);
    }
    expect(0x04, iv_item, "sdr-iv")?;
    if iv_item.value.len() != 8 {
        return Err(NssError::Asn1("sdr-iv-Laenge"));
    }
    expect(0x04, data, "sdr-data")?;
    let ciphertext = data.value;
    if master_key.len() < 24 {
        return Err(NssError::Asn1("Master-Schluessel"));
    }
    if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(8) {
        return Err(NssError::Asn1("sdr-cipher-Laenge"));
    }

    let key: [u8; 24] = master_key[..24].try_into().unwrap();
    let iv: [u8; 8] = iv_item.value.try_into().unwrap();
    let buf = tdes_cbc_decrypt(&key, &iv, ciphertext);
    let plain = strip_pkcs7(&buf, 8);
    String::from_utf8(plain.to_vec()).map_err(|_| NssError::NotText)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tlv_lange_form() {
        // OCTET STRING mit langer Längenform (0x81 0x80 = 128 Byte).
        let mut d = vec![0x04, 0x81, 0x80];
        d.extend(std::iter::repeat_n(0xaa, 128));
        let (tlv, rest) = read_tlv(&d).unwrap();
        assert_eq!(tlv.tag, 0x04);
        assert_eq!(tlv.value.len(), 128);
        assert!(rest.is_empty());
    }

    #[test]
    fn pkcs7_entfernen() {
        assert_eq!(
            strip_pkcs7(&[1, 2, 3, 0x05, 0x05, 0x05, 0x05, 0x05], 8),
            &[1, 2, 3]
        );
        // Ungültige Auffüllung (nicht alle Bytes gleich) bleibt unangetastet.
        assert_eq!(
            strip_pkcs7(&[1, 2, 3, 0x05, 0x00, 0x05, 0x05, 0x05], 8),
            &[1, 2, 3, 0x05, 0x00, 0x05, 0x05, 0x05]
        );
    }

    fn hx(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    // Echte Werte aus einem mit NSS erzeugten Testprofil (leeres Hauptpasswort,
    // Dummy-Zugangsdaten). Gegen firefox_decrypt (echte libnss) verifiziert.
    #[test]
    fn echtes_profil_entschluesselt() {
        let gs = hx("05fca82cd58eb4a7bdb4ae4e9281627ed2947169");
        let item2 = hx("308181306d06092a864886f70d01050d3060304106092a864886f70d01050c303404208eba7a0a268b59726a98a4dfb85d98d5e1a3fc2e4bdb0e0402c51d6c71cd96ec020101020120300a06082a864886f70d0209301b060960864801650304012a040ec31d2ae3387aabd5180f98357c240410fa2664f2ce180b5e26f1debda8f6e5d9");
        let a11 = hx("308191306d06092a864886f70d01050d3060304106092a864886f70d01050c3034042043ec5d4d1c1c954cd9f8adfe36fb660906523379463b23c1bf8911a92c60cdd0020101020120300a06082a864886f70d0209301b060960864801650304012a040ed5cdce109f0f2a9122958bbf494604205a390ca7392df8b3eee9cef96be17557ce3b3814ef4951f479140b518e79cc58");
        let mk = master_key(&gs, &item2, &a11, "").unwrap();
        assert_eq!(mk.len(), 24);

        let user = hx("30420410f8000000000000000000000000000001301406082a864886f70d030704081382ee24a522681e041857b30376735a42d015808031be0e7de31da3e1856a4782e1");
        let pass = hx("303a0410f8000000000000000000000000000001301406082a864886f70d03070408c4370fc76f89e7070410a5732b6c992a0b82849268c7dc199b26");
        assert_eq!(decrypt_login(&user, &mk).unwrap(), "testuser@example.com");
        assert_eq!(decrypt_login(&pass, &mk).unwrap(), "S3hr-Geheim!");
    }

    #[test]
    fn falsches_hauptpasswort() {
        let gs = hx("05fca82cd58eb4a7bdb4ae4e9281627ed2947169");
        let item2 = hx("308181306d06092a864886f70d01050d3060304106092a864886f70d01050c303404208eba7a0a268b59726a98a4dfb85d98d5e1a3fc2e4bdb0e0402c51d6c71cd96ec020101020120300a06082a864886f70d0209301b060960864801650304012a040ec31d2ae3387aabd5180f98357c240410fa2664f2ce180b5e26f1debda8f6e5d9");
        let a11 = hx("308191306d06092a864886f70d01050d3060304106092a864886f70d01050c3034042043ec5d4d1c1c954cd9f8adfe36fb660906523379463b23c1bf8911a92c60cdd0020101020120300a06082a864886f70d0209301b060960864801650304012a040ed5cdce109f0f2a9122958bbf494604205a390ca7392df8b3eee9cef96be17557ce3b3814ef4951f479140b518e79cc58");
        assert_eq!(
            master_key(&gs, &item2, &a11, "falsch"),
            Err(NssError::WrongPassword)
        );
    }

    #[test]
    fn falsches_verfahren_wird_gemeldet() {
        // SEQUENCE { SEQUENCE { OID (nicht PBES2), NULL }, OCTET "" }
        let blob = [
            0x30, 0x0c, 0x30, 0x08, 0x06, 0x04, 0x2a, 0x03, 0x04, 0x05, 0x05, 0x00, 0x04, 0x00,
        ];
        assert_eq!(pbes2_decrypt(&[0u8; 20], &blob), Err(NssError::Unsupported));
    }
}
