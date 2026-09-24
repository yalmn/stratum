//! Read-only Memory-Mapping einer Image-Datei.
//!
//! Dieses Crate kapselt den einzigen `unsafe`-Aufruf des Projekts, damit alle
//! anderen Crates `#![forbid(unsafe_code)]` setzen können.

#![deny(unsafe_op_in_unsafe_fn)]

use std::fs::File;
use std::io;
use std::path::Path;

/// Read-only Mapping einer Datei. Der Inhalt ist über [`ReadOnlyMap::as_slice`]
/// als Byte-Slice erreichbar.
#[derive(Debug)]
pub struct ReadOnlyMap {
    map: memmap2::Mmap,
}

impl ReadOnlyMap {
    /// Öffnet `path` ausschließlich lesend und mappt die komplette Datei.
    ///
    /// Leere Dateien werden abgelehnt, da ein Mapping der Länge 0 nicht auf
    /// allen Plattformen erlaubt ist.
    pub fn open(path: &Path) -> io::Result<Self> {
        // File::open öffnet immer O_RDONLY, ein Schreibzugriff ist damit
        // schon auf Kernel-Ebene ausgeschlossen.
        let file = File::open(path)?;
        if file.metadata()?.len() == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Datei ist leer"));
        }

        // SAFETY: memmap2 markiert `map` als unsafe, weil ein anderer Prozess die
        // Datei während der Lebensdauer des Mappings verändern oder kürzen
        // könnte. Ersteres würde die Unveränderlichkeit von &[u8] verletzen,
        // Letzteres führt beim Zugriff zu SIGBUS.
        // Begründung für die Verwendung: Beweis-Images liegen auf einem
        // schreibgeschützten Asservaten-Speicher und werden während der Analyse
        // von niemandem verändert, wir selbst öffnen nur lesend. Eine Veränderung
        // von außen würde ohnehin die Hash-Prüfung invalidieren.
        let map = unsafe { memmap2::MmapOptions::new().map(&file)? };

        #[cfg(unix)]
        {
            // Rein ein Hinweis an den Kernel, Fehler sind unkritisch.
            let _ = map.advise(memmap2::Advice::Random);
        }

        Ok(Self { map })
    }

    /// Kompletter Dateiinhalt.
    pub fn as_slice(&self) -> &[u8] {
        &self.map
    }

    /// Länge in Bytes.
    pub fn len(&self) -> u64 {
        self.map.len() as u64
    }

    /// Immer `false`, da leere Dateien bereits in [`ReadOnlyMap::open`]
    /// abgelehnt werden.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Hinweis an den Kernel, dass jetzt sequentiell gelesen wird (z. B. beim
    /// Hashen). Auf Nicht-Unix-Systemen ohne Wirkung.
    pub fn advise_sequential(&self) {
        #[cfg(unix)]
        {
            let _ = self.map.advise(memmap2::Advice::Sequential);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn mappt_inhalt() {
        let mut path = std::env::temp_dir();
        path.push(format!("stratum-mmap-test-{}", std::process::id()));
        {
            let mut f = File::create(&path).unwrap();
            f.write_all(b"abc").unwrap();
        }
        let m = ReadOnlyMap::open(&path).unwrap();
        assert_eq!(m.as_slice(), b"abc");
        assert_eq!(m.len(), 3);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn leere_datei_wird_abgelehnt() {
        let mut path = std::env::temp_dir();
        path.push(format!("stratum-mmap-empty-{}", std::process::id()));
        File::create(&path).unwrap();
        assert!(ReadOnlyMap::open(&path).is_err());
        std::fs::remove_file(&path).unwrap();
    }
}
