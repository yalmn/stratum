//! Read-only Zugriff auf Roh-Images.

use std::path::{Path, PathBuf};

use stratum_mmap::ReadOnlyMap;

use crate::error::ImageError;

/// Read-only Sicht auf ein Roh-Image (`.dd`).
///
/// Das Image wird per Memory-Mapping eingebunden, Lesezugriffe liefern
/// Slices ohne Kopie. Jeder Zugriff ist gegen die Imagegröße geprüft.
#[derive(Debug)]
pub struct ImageReader {
    path: PathBuf,
    map: ReadOnlyMap,
}

impl ImageReader {
    /// Öffnet das Image unter `path` ausschließlich lesend.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ImageError> {
        let path = path.as_ref().to_path_buf();
        let map = ReadOnlyMap::open(&path).map_err(|source| ImageError::Open {
            path: path.clone(),
            source,
        })?;
        Ok(Self { path, map })
    }

    /// Pfad, unter dem das Image geöffnet wurde.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Größe des Images in Bytes.
    pub fn len(&self) -> u64 {
        self.map.len()
    }

    /// `true`, wenn das Image keine Bytes enthält. Da leere Dateien schon beim
    /// Öffnen abgelehnt werden, ist das in der Praxis nie der Fall.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Liefert `len` Bytes ab `offset`.
    ///
    /// Gibt [`ImageError::OutOfBounds`] zurück, wenn der Bereich ganz oder
    /// teilweise außerhalb des Images liegt. Es wird nie gepanict, auch nicht
    /// bei Überlauf von `offset + len`.
    pub fn read_at(&self, offset: u64, len: usize) -> Result<&[u8], ImageError> {
        slice_at(self.map.as_slice(), offset, len).ok_or(ImageError::OutOfBounds {
            offset,
            len: len as u64,
            size: self.len(),
        })
    }

    /// Das komplette Image als Slice, z. B. für Hashing oder Parser, die auf
    /// `&[u8]` arbeiten.
    pub fn as_slice(&self) -> &[u8] {
        self.map.as_slice()
    }

    /// Gibt dem Kernel den Hinweis, dass das Image jetzt sequentiell gelesen
    /// wird.
    pub(crate) fn advise_sequential(&self) {
        self.map.advise_sequential();
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
        assert_eq!(img.read_at(2, 3).unwrap(), b"234");
        assert_eq!(img.read_at(0, 10).unwrap(), b"0123456789");
        assert_eq!(img.read_at(10, 0).unwrap(), b"");
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
