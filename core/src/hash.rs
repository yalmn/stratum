//! Integritäts-Hashes (SHA-256 und BLAKE3) über das gesamte Image.
//!
//! Beide Hashes laufen parallel in je einem Thread über das Mapping. Es wird
//! nichts in den Heap kopiert; der Kernel lädt die Seiten bei Bedarf und kann
//! sie danach wieder verwerfen. Die Gesamtdauer entspricht damit ungefähr der
//! des langsameren Hashes (in der Regel SHA-256).

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::image::ImageReader;

/// Blockgröße, in der die Hasher gefüttert werden.
const CHUNK: usize = 4 * 1024 * 1024;

/// Hashes eines Images, hex-kodiert (Kleinbuchstaben).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImageHashes {
    /// Anzahl der gehashten Bytes.
    pub bytes: u64,
    /// SHA-256, 64 Hex-Zeichen.
    pub sha256: String,
    /// BLAKE3, 64 Hex-Zeichen.
    pub blake3: String,
}

/// Rückmeldung über den Hash-Fortschritt: erhält die Gesamtzahl der bisher
/// verarbeiteten Bytes. Muss `Sync` sein, da sie aus dem Hash-Thread aufgerufen
/// wird.
pub type Progress<'a> = &'a (dyn Fn(u64) + Sync);

/// Berechnet SHA-256 und BLAKE3 über das komplette Image.
pub fn hash_image(img: &ImageReader) -> ImageHashes {
    hash_image_with_progress(img, None)
}

/// Wie [`hash_image`], meldet aber den Fortschritt über `progress`.
pub fn hash_image_with_progress(img: &ImageReader, progress: Option<Progress<'_>>) -> ImageHashes {
    img.advise_sequential();
    hash_bytes_with_progress(img.as_slice(), progress)
}

/// Berechnet SHA-256 und BLAKE3 über `data`, blockweise und parallel.
pub fn hash_bytes(data: &[u8]) -> ImageHashes {
    hash_bytes_with_progress(data, None)
}

/// Wie [`hash_bytes`], meldet aber den Fortschritt über `progress`. Der
/// Fortschritt wird vom SHA-256-Durchlauf gemeldet, der in aller Regel der
/// langsamere der beiden ist.
pub fn hash_bytes_with_progress(data: &[u8], progress: Option<Progress<'_>>) -> ImageHashes {
    let (sha, b3) = std::thread::scope(|s| {
        let sha = s.spawn(move || {
            let mut h = Sha256::new();
            let mut done = 0u64;
            for chunk in data.chunks(CHUNK) {
                h.update(chunk);
                if let Some(p) = progress {
                    done += chunk.len() as u64;
                    p(done);
                }
            }
            to_hex(&h.finalize())
        });
        let mut h = blake3::Hasher::new();
        for chunk in data.chunks(CHUNK) {
            h.update(chunk);
        }
        let b3 = h.finalize().to_hex().to_string();
        // Ein Panic im Hash-Thread ist nur bei einem Bug in sha2 denkbar und
        // wird unverändert weitergereicht.
        let sha = sha.join().unwrap_or_else(|e| std::panic::resume_unwind(e));
        (sha, b3)
    });

    ImageHashes {
        bytes: data.len() as u64,
        sha256: sha,
        blake3: b3,
    }
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    // Referenzwerte aus FIPS 180-2 bzw. der offiziellen BLAKE3-Implementierung.
    #[test]
    fn leere_eingabe() {
        let h = hash_bytes(b"");
        assert_eq!(
            h.sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            h.blake3,
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
        assert_eq!(h.bytes, 0);
    }

    #[test]
    fn abc() {
        let h = hash_bytes(b"abc");
        assert_eq!(
            h.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(h.blake3, blake3::hash(b"abc").to_hex().to_string());
    }

    #[test]
    fn blockgrenzen_ändern_nichts() {
        // Mehr als ein Block, damit die Aufteilung tatsächlich greift.
        let data: Vec<u8> = (0..CHUNK * 2 + 17).map(|i| (i % 251) as u8).collect();
        let h = hash_bytes(&data);
        assert_eq!(h.sha256, to_hex(&Sha256::digest(&data)));
        assert_eq!(h.blake3, blake3::hash(&data).to_hex().to_string());
        assert_eq!(h.bytes, data.len() as u64);
    }

    #[test]
    fn hex() {
        assert_eq!(to_hex(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
    }
}
