//! Integritäts-Hashes (SHA-256 und BLAKE3) über das gesamte Image.
//!
//! Beim Rohimage laufen beide Hashes parallel in je einem Thread über das
//! Mapping, ohne Kopie in den Heap. Bei E01 werden die Mediendaten blockweise
//! entpackt (die Chunks eines Blocks parallel) und dann gehasht; trägt das
//! Image bei der Akquise gespeicherte MD5- oder SHA-1-Werte, werden diese im
//! selben Durchlauf mitgebildet, damit sie sich vergleichen lassen.

use md5::Md5;
use rayon::prelude::*;
use serde::Serialize;
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::error::ImageError;
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
    /// MD5, nur bei E01 mit gespeichertem Akquise-MD5 (zum Vergleich).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub md5: Option<String>,
    /// SHA-1, nur bei E01 mit gespeichertem Akquise-SHA-1 (zum Vergleich).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha1: Option<String>,
}

/// Rückmeldung über den Hash-Fortschritt: erhält die Gesamtzahl der bisher
/// verarbeiteten Bytes. Muss `Sync` sein, da sie aus dem Hash-Thread aufgerufen
/// wird.
pub type Progress<'a> = &'a (dyn Fn(u64) + Sync);

/// Berechnet SHA-256 und BLAKE3 über das komplette Image. Fehler gibt es nur
/// bei E01, wenn ein Chunk nicht lesbar ist.
pub fn hash_image(img: &ImageReader) -> Result<ImageHashes, ImageError> {
    hash_image_with_progress(img, None)
}

/// Wie [`hash_image`], meldet aber den Fortschritt über `progress`.
pub fn hash_image_with_progress(
    img: &ImageReader,
    progress: Option<Progress<'_>>,
) -> Result<ImageHashes, ImageError> {
    if let Some(data) = img.raw_slice() {
        img.advise_sequential();
        let hashes = hash_bytes_with_progress(data, progress);
        img.advise_random();
        return Ok(hashes);
    }
    hash_stream(img, progress)
}

/// Blockgröße beim gestreamten Hashen (E01).
const BLOCK: usize = 16 * 1024 * 1024;
/// Teilstücke eines Blocks, die parallel gelesen (entpackt) werden.
const TEIL: usize = 1024 * 1024;

/// Hasht ein Image, das nicht als Slice vorliegt.
fn hash_stream(
    img: &ImageReader,
    progress: Option<Progress<'_>>,
) -> Result<ImageHashes, ImageError> {
    let gespeichert = img
        .ewf()
        .map(|e| e.stored_hashes().clone())
        .unwrap_or_default();
    let mut sha = Sha256::new();
    let mut b3 = blake3::Hasher::new();
    let mut md5 = gespeichert.md5.map(|_| Md5::new());
    let mut sha1 = gespeichert.sha1.map(|_| Sha1::new());
    let len = img.len();
    let mut buf = vec![0u8; BLOCK.min(len as usize)];
    let mut pos = 0u64;
    while pos < len {
        let n = (len - pos).min(BLOCK as u64) as usize;
        let block = &mut buf[..n];
        block
            .par_chunks_mut(TEIL)
            .enumerate()
            .try_for_each(|(i, teil)| img.read_into(pos + (i * TEIL) as u64, teil))?;
        let block = &buf[..n];
        std::thread::scope(|s| {
            s.spawn(|| sha.update(block));
            if let Some(h) = md5.as_mut() {
                s.spawn(move || h.update(block));
            }
            if let Some(h) = sha1.as_mut() {
                s.spawn(move || h.update(block));
            }
            b3.update(block);
        });
        pos += n as u64;
        if let Some(p) = progress {
            p(pos);
        }
    }
    Ok(ImageHashes {
        bytes: len,
        sha256: to_hex(&sha.finalize()),
        blake3: b3.finalize().to_hex().to_string(),
        md5: md5.map(|h| to_hex(&h.finalize())),
        sha1: sha1.map(|h| to_hex(&h.finalize())),
    })
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
        md5: None,
        sha1: None,
    }
}

/// Schreibt durch und berechnet dabei SHA-256 und BLAKE3 über alle geschriebenen
/// Bytes. So lässt sich eine erzeugte Datei hashen, ohne sie erneut zu lesen.
pub struct HashingWriter<W> {
    inner: W,
    sha: Sha256,
    b3: blake3::Hasher,
    bytes: u64,
}

impl<W: std::io::Write> HashingWriter<W> {
    /// Umhüllt `inner`.
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            sha: Sha256::new(),
            b3: blake3::Hasher::new(),
            bytes: 0,
        }
    }

    /// Leert den Puffer und liefert den inneren Writer mit den Hashes.
    pub fn finish(mut self) -> std::io::Result<(W, ImageHashes)> {
        self.inner.flush()?;
        let hashes = ImageHashes {
            bytes: self.bytes,
            sha256: to_hex(&self.sha.finalize()),
            blake3: self.b3.finalize().to_hex().to_string(),
            md5: None,
            sha1: None,
        };
        Ok((self.inner, hashes))
    }
}

impl<W: std::io::Write> std::io::Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.sha.update(&buf[..n]);
        self.b3.update(&buf[..n]);
        self.bytes += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
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

    #[test]
    fn hashing_writer_entspricht_hash_bytes() {
        use std::io::Write;
        let data = vec![7u8; CHUNK + 13];
        let mut w = HashingWriter::new(Vec::new());
        w.write_all(&data[..5]).unwrap();
        w.write_all(&data[5..]).unwrap();
        let (out, h) = w.finish().unwrap();
        assert_eq!(out, data);
        assert_eq!(h, hash_bytes(&data));
    }
}
