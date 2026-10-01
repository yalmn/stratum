//! Read-only Zugriff auf Images: Rohimages (`.dd`) und Expert-Witness-Images
//! (E01).
//!
//! Rohimages werden per Memory-Mapping eingebunden; Lesezugriffe liefern dort
//! Slices ohne Kopie. E01-Images werden blockweise entpackt (Crate
//! `stratum-ewf`). Beide werden an der Signatur erkannt, nicht an der Endung.

use std::borrow::Cow;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use stratum_ewf::EwfImage;
use stratum_mmap::ReadOnlyMap;

use crate::error::ImageError;

/// Format eines Images.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageFormat {
    /// Rohimage (dd).
    Raw,
    /// Expert Witness Format (E01, auch S01).
    Ewf,
}

#[derive(Debug)]
enum Source {
    Raw(ReadOnlyMap),
    Ewf(Box<EwfImage>),
}

/// Read-only Sicht auf ein Image.
///
/// Jeder Zugriff ist gegen die Imagegröße geprüft. Bei E01 bezeichnen alle
/// Offsets die Mediendaten, nicht die Segmentdateien.
#[derive(Debug)]
pub struct ImageReader {
    path: PathBuf,
    source: Source,
}

/// Signaturen der Expert-Witness-Formate (EWF-E01/S01, L01, EWF2).
fn ist_ewf(kopf: &[u8]) -> bool {
    kopf.starts_with(b"EVF\x09\x0d\x0a\xff\x00")
        || kopf.starts_with(b"LVF\x09\x0d\x0a\xff\x00")
        || kopf.starts_with(b"EVF2")
        || kopf.starts_with(b"LEF2")
}

impl ImageReader {
    /// Öffnet das Image unter `path` ausschließlich lesend. Bei E01 werden
    /// die weiteren Segmente (E02 ...) neben der ersten Datei gesucht.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ImageError> {
        let path = path.as_ref().to_path_buf();
        let map = ReadOnlyMap::open(&path).map_err(|source| ImageError::Open {
            path: path.clone(),
            source,
        })?;
        let source = if ist_ewf(map.as_slice()) {
            drop(map);
            Source::Ewf(Box::new(EwfImage::open(&path)?))
        } else {
            Source::Raw(map)
        };
        Ok(Self { path, source })
    }

    /// Pfad, unter dem das Image geöffnet wurde (bei E01 die erste Segmentdatei).
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Format des Images.
    pub fn format(&self) -> ImageFormat {
        match self.source {
            Source::Raw(_) => ImageFormat::Raw,
            Source::Ewf(_) => ImageFormat::Ewf,
        }
    }

    /// Das E01-Image, falls es eines ist (Akquisedaten, gespeicherte Hashes).
    pub fn ewf(&self) -> Option<&EwfImage> {
        match &self.source {
            Source::Ewf(e) => Some(e),
            Source::Raw(_) => None,
        }
    }

    /// Größe des Images in Bytes (bei E01 die Mediengröße).
    pub fn len(&self) -> u64 {
        match &self.source {
            Source::Raw(m) => m.len(),
            Source::Ewf(e) => e.media_size(),
        }
    }

    /// `true`, wenn das Image keine Bytes enthält. Da leere Dateien schon beim
    /// Öffnen abgelehnt werden, ist das in der Praxis nie der Fall.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Liefert `len` Bytes ab `offset`: beim Rohimage ohne Kopie, bei E01
    /// entpackt.
    ///
    /// Gibt [`ImageError::OutOfBounds`] zurück, wenn der Bereich ganz oder
    /// teilweise außerhalb des Images liegt. Es wird nie gepanict, auch nicht
    /// bei Überlauf von `offset + len`.
    pub fn read_at(&self, offset: u64, len: usize) -> Result<Cow<'_, [u8]>, ImageError> {
        let oob = || ImageError::OutOfBounds {
            offset,
            len: len as u64,
            size: self.len(),
        };
        match &self.source {
            Source::Raw(m) => slice_at(m.as_slice(), offset, len)
                .map(Cow::Borrowed)
                .ok_or_else(oob),
            Source::Ewf(e) => {
                offset
                    .checked_add(len as u64)
                    .filter(|&end| end <= e.media_size())
                    .ok_or_else(oob)?;
                let mut buf = vec![0u8; len];
                e.read_at(offset, &mut buf)?;
                Ok(Cow::Owned(buf))
            }
        }
    }

    /// Liest `buf.len()` Bytes ab `offset` in `buf`.
    pub fn read_into(&self, offset: u64, buf: &mut [u8]) -> Result<(), ImageError> {
        match &self.source {
            Source::Raw(m) => {
                let src =
                    slice_at(m.as_slice(), offset, buf.len()).ok_or(ImageError::OutOfBounds {
                        offset,
                        len: buf.len() as u64,
                        size: m.len(),
                    })?;
                buf.copy_from_slice(src);
                Ok(())
            }
            Source::Ewf(e) => e.read_at(offset, buf).map_err(|err| match err {
                stratum_ewf::EwfError::OutOfRange { offset, len, size } => {
                    ImageError::OutOfBounds { offset, len, size }
                }
                other => ImageError::Ewf(other),
            }),
        }
    }

    /// Das komplette Image als Slice, nur bei Rohimages. Für Code, der beide
    /// Formate lesen soll, [`read_at`](Self::read_at),
    /// [`read_into`](Self::read_into) oder [`cursor`](Self::cursor) nutzen.
    pub fn raw_slice(&self) -> Option<&[u8]> {
        match &self.source {
            Source::Raw(m) => Some(m.as_slice()),
            Source::Ewf(_) => None,
        }
    }

    /// Lesender, suchbarer Ausschnitt `offset .. offset + len` (Positionen
    /// relativ zu `offset`), z. B. für den NTFS-Parser.
    pub fn cursor(&self, offset: u64, len: u64) -> ImageCursor<'_> {
        ImageCursor {
            img: self,
            start: offset,
            len,
            pos: 0,
        }
    }

    /// Gibt dem Kernel den Hinweis, dass das Image jetzt sequentiell gelesen
    /// wird (nur Rohimages).
    pub(crate) fn advise_sequential(&self) {
        if let Source::Raw(m) = &self.source {
            m.advise_sequential();
        }
    }

    /// Setzt den Zugriffshinweis nach einem sequentiellen Durchlauf zurück.
    pub(crate) fn advise_random(&self) {
        if let Source::Raw(m) = &self.source {
            m.advise_random();
        }
    }

    /// Fordert `len` Bytes ab `offset` vorab vom Datenträger an. Reiner
    /// Leistungshinweis ohne Einfluss auf gelesene Inhalte (nur Rohimages).
    pub fn prefetch(&self, offset: u64, len: u64) {
        if let Source::Raw(m) = &self.source {
            m.prefetch(offset, len);
        }
    }
}

/// Lesender, suchbarer Ausschnitt eines Images.
#[derive(Debug, Clone)]
pub struct ImageCursor<'a> {
    img: &'a ImageReader,
    start: u64,
    len: u64,
    pos: u64,
}

impl<'a> ImageCursor<'a> {
    /// Das Image, aus dem gelesen wird.
    pub fn image(&self) -> &'a ImageReader {
        self.img
    }

    /// Beginn des Ausschnitts im Image.
    pub fn start(&self) -> u64 {
        self.start
    }
}

impl Read for ImageCursor<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.len || buf.is_empty() {
            return Ok(0);
        }
        let n = (buf.len() as u64).min(self.len - self.pos) as usize;
        self.img
            .read_into(self.start + self.pos, &mut buf[..n])
            .map_err(|e| io::Error::new(io::ErrorKind::UnexpectedEof, e))?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for ImageCursor<'_> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let neu = match pos {
            SeekFrom::Start(o) => Some(o),
            SeekFrom::End(d) => self.len.checked_add_signed(d),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d),
        }
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Position vor dem Anfang"))?;
        self.pos = neu;
        Ok(neu)
    }
}

/// Geprüfter Teilbereich `data[offset..offset + len]`.
pub(crate) fn slice_at(data: &[u8], offset: u64, len: usize) -> Option<&[u8]> {
    let start = usize::try_from(offset).ok()?;
    let end = start.checked_add(len)?;
    data.get(start..end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_image(content: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(content).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn liest_bereich() {
        let f = temp_image(b"0123456789");
        let img = ImageReader::open(f.path()).unwrap();
        assert_eq!(img.len(), 10);
        assert_eq!(&*img.read_at(2, 3).unwrap(), b"234");
        assert_eq!(&*img.read_at(0, 10).unwrap(), b"0123456789");
        assert_eq!(&*img.read_at(10, 0).unwrap(), b"");
        assert_eq!(img.format(), ImageFormat::Raw);
        let mut c = img.cursor(3, 4);
        let mut b = Vec::new();
        c.read_to_end(&mut b).unwrap();
        assert_eq!(b, b"3456");
        c.seek(SeekFrom::End(-1)).unwrap();
        assert_eq!(c.read(&mut [0u8; 8]).unwrap(), 1);
    }

    #[test]
    fn oob_liefert_fehler() {
        let f = temp_image(b"0123456789");
        let img = ImageReader::open(f.path()).unwrap();
        assert!(matches!(
            img.read_at(8, 3),
            Err(ImageError::OutOfBounds {
                offset: 8,
                len: 3,
                size: 10
            })
        ));
        assert!(img.read_at(11, 0).is_err());
        assert!(img.read_at(u64::MAX, 1).is_err());
        assert!(img.read_at(1, usize::MAX).is_err());
    }

    #[test]
    fn fehlende_datei() {
        assert!(matches!(
            ImageReader::open("/nicht/vorhanden.dd"),
            Err(ImageError::Open { .. })
        ));
    }

    #[test]
    fn leere_datei() {
        let f = temp_image(b"");
        assert!(ImageReader::open(f.path()).is_err());
    }
}
