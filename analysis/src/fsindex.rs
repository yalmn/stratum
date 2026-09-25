//! Pfad-Index eines NTFS-Bereichs.
//!
//! Der Index entsteht aus einem einmaligen Verzeichnis-Durchlauf (nur
//! Metadaten, keine Dateiinhalte). Analyzer fragen ihn nach den Dateien, die sie
//! brauchen (feste Pfade, Endungen, Verzeichnisse), und lesen anschliessend nur
//! diese gezielt über ihre MFT-Nummer. So läuft keine Domäne mehr blind über den
//! gesamten Rohdatenträger.

use stratum_core::ImageReader;
use stratum_ntfs::{NtfsVolume, NtfsVolumeError};

use crate::context::NtfsTarget;

/// Eine Datei im Index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    /// Vollständiger Pfad ab der Wurzel des Volumes (`\`-getrennt).
    pub path: String,
    /// MFT-Datensatznummer, zum gezielten Lesen ohne Pfadauflösung.
    pub mft_record: u64,
    /// Länge der Datei in Bytes.
    pub size: u64,
}

/// Der Pfad-Index eines NTFS-Bereichs (nur Dateien, keine Verzeichnisse).
#[derive(Debug, Clone)]
pub struct FsIndex {
    /// Der zugrunde liegende NTFS-Bereich.
    pub target: NtfsTarget,
    /// Alle Dateien des Bereichs.
    pub files: Vec<FileEntry>,
}

impl FsIndex {
    /// Baut den Index für einen NTFS-Bereich auf.
    pub fn build(img: &ImageReader, target: NtfsTarget) -> Result<Self, NtfsVolumeError> {
        let mut vol = NtfsVolume::open(img, target.offset, target.size)?;
        let files = vol
            .walk()?
            .into_iter()
            .filter(|e| !e.is_directory)
            .map(|e| FileEntry {
                path: e.path,
                mft_record: e.mft_record,
                size: e.size,
            })
            .collect();
        Ok(Self { target, files })
    }

    /// Dateien mit einer der angegebenen Endungen (ohne Punkt, klein).
    pub fn by_extension<'s>(
        &'s self,
        exts: &'s [&str],
    ) -> impl Iterator<Item = &'s FileEntry> + 's {
        self.files.iter().filter(move |f| {
            extension(&f.path)
                .map(|e| exts.iter().any(|x| x.eq_ignore_ascii_case(e)))
                .unwrap_or(false)
        })
    }

    /// Dateien, deren Pfad mit `prefix` beginnt (ohne Beachtung der
    /// Groß-/Kleinschreibung). `prefix` mit `\` getrennt, z. B. `"Users"`.
    pub fn under<'s>(&'s self, prefix: &'s str) -> impl Iterator<Item = &'s FileEntry> + 's {
        let prefix = prefix.trim_matches('\\');
        self.files.iter().filter(move |f| {
            let p = f.path.as_bytes();
            let n = prefix.len();
            p.len() > n && p[..n].eq_ignore_ascii_case(prefix.as_bytes()) && (p[n] == b'\\')
        })
    }

    /// Dateien, deren Dateiname (letzter Pfadteil) exakt `name` ist (ohne
    /// Beachtung der Groß-/Kleinschreibung). Nützlich für Dateien ohne Endung
    /// wie `torrc`, `hostname` oder `hs_ed25519_secret_key`.
    pub fn by_name<'s>(&'s self, name: &'s str) -> impl Iterator<Item = &'s FileEntry> + 's {
        self.files.iter().filter(move |f| {
            let base = f.path.rsplit('\\').next().unwrap_or(&f.path);
            base.eq_ignore_ascii_case(name)
        })
    }

    /// Die erste Datei, deren Pfad exakt passt (ohne Beachtung der
    /// Groß-/Kleinschreibung).
    pub fn get(&self, path: &str) -> Option<&FileEntry> {
        let path = path.replace('/', "\\");
        self.files
            .iter()
            .find(|f| f.path.eq_ignore_ascii_case(&path))
    }
}

/// Endung eines Pfads in Kleinbuchstaben, ohne Punkt.
fn extension(path: &str) -> Option<&str> {
    let name = path.rsplit('\\').next().unwrap_or(path);
    let dot = name.rfind('.')?;
    if dot + 1 >= name.len() {
        return None;
    }
    Some(&name[dot + 1..])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn idx(paths: &[(&str, u64)]) -> FsIndex {
        FsIndex {
            target: NtfsTarget {
                index: 0,
                offset: 0,
                size: 0,
            },
            files: paths
                .iter()
                .map(|(p, r)| FileEntry {
                    path: p.to_string(),
                    mft_record: *r,
                    size: 10,
                })
                .collect(),
        }
    }

    #[test]
    fn endung_und_verzeichnis() {
        let fs = idx(&[
            ("Users\\a\\notiz.txt", 1),
            ("Users\\a\\bild.PNG", 2),
            ("Windows\\System32\\x.dll", 3),
            ("brief.docx", 4),
        ]);
        let txt: Vec<_> = fs
            .by_extension(&["txt", "docx"])
            .map(|f| f.mft_record)
            .collect();
        assert_eq!(txt, vec![1, 4]);

        let users: Vec<_> = fs.under("users").map(|f| f.mft_record).collect();
        assert_eq!(users, vec![1, 2]);

        assert_eq!(
            fs.get("windows/system32/x.dll").map(|f| f.mft_record),
            Some(3)
        );
        assert!(fs.get("fehlt.txt").is_none());
    }
}
