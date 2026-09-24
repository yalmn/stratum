//! Krypto-Bausteine für die SAM-Entschlüsselung.
//!
//! Alle Funktionen sind schlanke Hüllen um geprüfte RustCrypto-Crates bzw.
//! (bei RC4) eine kurze eigene Implementierung. Die Bausteine werden gegen
//! veröffentlichte Testvektoren geprüft (siehe Tests), damit die
//! Zusammensetzung in [`crate::sam`] auf gesicherten Grundlagen steht.

use md5::{Digest, Md5};

use aes::Aes128;
use cbc::cipher::array::Array;
use cbc::cipher::consts::{U16, U8};
use cbc::cipher::{BlockCipherDecrypt, BlockModeDecrypt, KeyInit, KeyIvInit};
use des::Des;

/// MD5 über die Verkettung mehrerer Teilstücke.
pub fn md5(parts: &[&[u8]]) -> [u8; 16] {
    let mut h = Md5::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// RC4-Stromchiffre. RC4 ist symmetrisch, dieselbe Funktion ver- und
/// entschlüsselt. Ein leerer Schlüssel liefert die Eingabe unverändert.
pub fn rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return data.to_vec();
    }
    let mut s: [u8; 256] = core::array::from_fn(|i| i as u8);
    let mut j = 0usize;
    for i in 0..256 {
        j = (j + s[i] as usize + key[i % key.len()] as usize) & 0xff;
        s.swap(i, j);
    }
    let mut out = Vec::with_capacity(data.len());
    let (mut i, mut j) = (0usize, 0usize);
    for &b in data {
        i = (i + 1) & 0xff;
        j = (j + s[i] as usize) & 0xff;
        s.swap(i, j);
        let k = s[(s[i] as usize + s[j] as usize) & 0xff];
        out.push(b ^ k);
    }
    out
}

/// Entschlüsselt einen einzelnen 8-Byte-Block mit DES (ECB).
pub fn des_decrypt_block(key8: &[u8; 8], data8: &[u8; 8]) -> [u8; 8] {
    let cipher = Des::new(&Array::<u8, U8>::from(*key8));
    let mut block = Array::<u8, U8>::from(*data8);
    cipher.decrypt_block(&mut block);
    let mut out = [0u8; 8];
    out.copy_from_slice(block.as_slice());
    out
}

/// Verschlüsselt einen einzelnen 8-Byte-Block mit DES (ECB). Nur für Tests.
#[cfg(test)]
pub fn des_encrypt_block(key8: &[u8; 8], data8: &[u8; 8]) -> [u8; 8] {
    use cbc::cipher::BlockCipherEncrypt;
    let cipher = Des::new(&Array::<u8, U8>::from(*key8));
    let mut block = Array::<u8, U8>::from(*data8);
    cipher.encrypt_block(&mut block);
    let mut out = [0u8; 8];
    out.copy_from_slice(block.as_slice());
    out
}

/// AES-128 im CBC-Modus, entschlüsselt ganze Blöcke ohne Padding.
///
/// `data` muss ein Vielfaches von 16 Bytes sein; überzählige Bytes am Ende
/// werden ignoriert.
pub fn aes128_cbc_decrypt(key: &[u8; 16], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let mut dec =
        cbc::Decryptor::<Aes128>::new(&Array::<u8, U16>::from(*key), &Array::<u8, U16>::from(*iv));
    let mut blocks: Vec<Array<u8, U16>> = data
        .chunks_exact(16)
        .map(|c| {
            let mut a = Array::<u8, U16>::default();
            a.copy_from_slice(c);
            a
        })
        .collect();
    dec.decrypt_blocks(&mut blocks);
    blocks
        .iter()
        .flat_map(|b| b.as_slice().iter().copied())
        .collect()
}

/// AES-128 im CBC-Modus, verschlüsselt ganze Blöcke ohne Padding. Nur Tests.
#[cfg(test)]
pub fn aes128_cbc_encrypt(key: &[u8; 16], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    use cbc::cipher::BlockModeEncrypt;
    let mut enc =
        cbc::Encryptor::<Aes128>::new(&Array::<u8, U16>::from(*key), &Array::<u8, U16>::from(*iv));
    let mut blocks: Vec<Array<u8, U16>> = data
        .chunks_exact(16)
        .map(|c| {
            let mut a = Array::<u8, U16>::default();
            a.copy_from_slice(c);
            a
        })
        .collect();
    enc.encrypt_blocks(&mut blocks);
    blocks
        .iter()
        .flat_map(|b| b.as_slice().iter().copied())
        .collect()
}

/// Wandelt 7 Bytes in einen 8-Byte-DES-Schlüssel (7-Bit-Werte in die oberen
/// Bits, Paritätsbit bleibt 0; DES ignoriert die Parität ohnehin).
fn str_to_key(s: &[u8; 7]) -> [u8; 8] {
    let mut k = [0u8; 8];
    k[0] = s[0] >> 1;
    k[1] = ((s[0] & 0x01) << 6) | (s[1] >> 2);
    k[2] = ((s[1] & 0x03) << 5) | (s[2] >> 3);
    k[3] = ((s[2] & 0x07) << 4) | (s[3] >> 4);
    k[4] = ((s[3] & 0x0f) << 3) | (s[4] >> 5);
    k[5] = ((s[4] & 0x1f) << 2) | (s[5] >> 6);
    k[6] = ((s[5] & 0x3f) << 1) | (s[6] >> 7);
    k[7] = s[6] & 0x7f;
    for b in &mut k {
        *b = (*b << 1) & 0xfe;
    }
    k
}

/// Leitet aus der RID die beiden DES-Schlüssel ab, mit denen der NT-Hash
/// entschleiert wird.
pub fn sid_to_keys(rid: u32) -> ([u8; 8], [u8; 8]) {
    let r = rid.to_le_bytes();
    let s1 = [r[0], r[1], r[2], r[3], r[0], r[1], r[2]];
    let s2 = [r[3], r[0], r[1], r[2], r[3], r[0], r[1]];
    (str_to_key(&s1), str_to_key(&s2))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn md5_vektoren() {
        assert_eq!(
            md5(&[b""]),
            hex("d41d8cd98f00b204e9800998ecf8427e").as_slice()
        );
        assert_eq!(
            md5(&[b"a", b"bc"]),
            hex("900150983cd24fb0d6963f7d28e17f72").as_slice()
        );
    }

    #[test]
    fn rc4_vektor() {
        // Bekanntes Beispiel: Key "Key", Klartext "Plaintext".
        assert_eq!(rc4(b"Key", b"Plaintext"), hex("bbf316e8d940af0ad3"));
        // Symmetrie: zweimal RC4 ergibt wieder den Klartext.
        let c = rc4(b"schluessel", b"geheime daten");
        assert_eq!(rc4(b"schluessel", &c), b"geheime daten");
    }

    #[test]
    fn des_vektor_und_inverse() {
        // Klassischer DES-Testvektor.
        let key = hex("133457799bbcdff1");
        let pt = hex("0123456789abcdef");
        let ct = hex("85e813540f0ab405");
        let key8: [u8; 8] = key.try_into().unwrap();
        let pt8: [u8; 8] = pt.clone().try_into().unwrap();
        let ct8: [u8; 8] = ct.try_into().unwrap();
        assert_eq!(des_encrypt_block(&key8, &pt8), ct8);
        assert_eq!(des_decrypt_block(&key8, &ct8), pt8.as_slice());
    }

    #[test]
    fn aes_fips_vektor() {
        // FIPS-197: ein Block, IV = 0, damit CBC dem reinen AES entspricht.
        let key: [u8; 16] = hex("000102030405060708090a0b0c0d0e0f").try_into().unwrap();
        let ct = hex("69c4e0d86a7b0430d8cdb78070b4c55a");
        let pt = hex("00112233445566778899aabbccddeeff");
        assert_eq!(aes128_cbc_decrypt(&key, &[0u8; 16], &ct), pt);
        assert_eq!(aes128_cbc_encrypt(&key, &[0u8; 16], &pt), ct);
    }

    #[test]
    fn sid_to_keys_deterministisch_und_parität() {
        let (a, b) = sid_to_keys(500);
        assert_eq!((a, b), sid_to_keys(500));
        assert_ne!(sid_to_keys(500), sid_to_keys(501));
        // Alle Bytes haben ein gelöschtes Paritätsbit (LSB).
        for byte in a.iter().chain(b.iter()) {
            assert_eq!(byte & 0x01, 0);
        }
    }
}
