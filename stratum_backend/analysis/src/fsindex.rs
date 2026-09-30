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
    /// Länge der Datei in Bytes (aus dem Verzeichniseintrag, bei Verzeichnissen 0).
    pub size: u64,
    /// MFT-Datensatznummer des Verzeichnisses, in dem der Eintrag steht.
    pub parent_record: u64,
}

/// Woher ein Pfad-Index stammt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Herkunft {
    /// Aktueller Stand des Volumes.
    #[default]
    Live,
    /// Schattenkopie; der Index enthält nur Dateien, die vom Live-Stand
    /// abweichen oder nur dort existieren.
    Snapshot {
        /// Store-Index (0 = älteste Schattenkopie).
        store: usize,
        /// Erstellungszeit (FILETIME, UTC).
        erstellt: u64,
    },
}

impl Herkunft {
    /// Bezeichnung im Report, z. B. `VSS#2`.
    pub fn label(&self) -> String {
        match self {
            Self::Live => "live".into(),
            Self::Snapshot { store, .. } => format!("VSS#{}", store + 1),
        }
    }
}

/// Der Pfad-Index eines NTFS-Bereichs.
#[derive(Debug, Clone)]
pub struct FsIndex {
    /// Der zugrunde liegende NTFS-Bereich.
    pub target: NtfsTarget,
    /// Live-Stand oder Schattenkopie.
    pub herkunft: Herkunft,
    /// Alle Dateien des Bereichs.
    pub files: Vec<FileEntry>,
    /// Alle Verzeichnisse des Bereichs (für den Dateikatalog).
    pub directories: Vec<FileEntry>,
    /// Was der Durchlauf nicht erfassen konnte (unlesbare Verzeichnisse, Grenzen).
    pub warnings: Vec<String>,
    /// Verzeichnisse, deren Inhalt fehlt: MFT-Nummer und Fehler, nach MFT sortiert.
    pub unreadable_dirs: Vec<(u64, String)>,
}

/// Höchstzahl einzeln gemeldeter unlesbarer Verzeichnisse je Volume.
const MAX_LISTED_SKIPS: usize = 50;

impl FsIndex {
    /// Baut den Index für einen NTFS-Bereich auf.
    pub fn build(img: &ImageReader, target: NtfsTarget) -> Result<Self, NtfsVolumeError> {
        let mut vol = NtfsVolume::open(img, target.offset, target.size)?;
        Self::from_volume(&mut vol, target, Herkunft::Live)
    }

    /// Leerer Index (etwa für einen nicht lesbaren Snapshot).
    pub fn leer(target: NtfsTarget, herkunft: Herkunft) -> Self {
        Self {
            target,
            herkunft,
            files: Vec::new(),
            directories: Vec::new(),
            warnings: Vec::new(),
            unreadable_dirs: Vec::new(),
        }
    }

    /// Baut den Index aus einem bereits geöffneten Volume.
    pub fn from_volume<R: std::io::Read + std::io::Seek>(
        vol: &mut NtfsVolume<R>,
        target: NtfsTarget,
        herkunft: Herkunft,
    ) -> Result<Self, NtfsVolumeError> {
        let mut files = Vec::new();
        let mut directories = Vec::new();
        let walk = vol.walk_report()?;
        let mut warnings = Vec::new();
        for d in walk.skipped.iter().take(MAX_LISTED_SKIPS) {
            let path = if d.path.is_empty() { "\\" } else { &d.path };
            warnings.push(format!(
                "Verzeichnis {path} (MFT {}) nicht lesbar, Inhalt fehlt im Index: {}",
                d.mft_record, d.error
            ));
        }
        if walk.skipped.len() > MAX_LISTED_SKIPS {
            warnings.push(format!(
                "weitere {} Verzeichnisse nicht lesbar",
                walk.skipped.len() - MAX_LISTED_SKIPS
            ));
        }
        if walk.depth_limited > 0 {
            warnings.push(format!(
                "{} Verzeichnisse wegen der Tiefengrenze nicht betreten",
                walk.depth_limited
            ));
        }
        if walk.truncated {
            warnings.push(format!(
                "Index nach {} Einträgen abgeschnitten",
                stratum_ntfs::MAX_WALK_ENTRIES
            ));
        }
        let mut unreadable_dirs: Vec<(u64, String)> = walk
            .skipped
            .into_iter()
            .map(|d| (d.mft_record, d.error))
            .collect();
        unreadable_dirs.sort_unstable_by_key(|(rec, _)| *rec);
        for e in walk.entries {
            let entry = FileEntry {
                path: e.path,
                mft_record: e.mft_record,
                size: e.size,
                parent_record: e.parent_record,
            };
            if e.is_directory {
                directories.push(entry);
            } else {
                files.push(entry);
            }
        }
        Ok(Self {
            target,
            herkunft,
            files,
            directories,
            warnings,
            unreadable_dirs,
        })
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
            herkunft: Herkunft::Live,
            files: paths
                .iter()
                .map(|(p, r)| FileEntry {
                    path: p.to_string(),
                    mft_record: *r,
                    size: 10,
                    parent_record: 5,
                })
                .collect(),
            directories: Vec::new(),
            warnings: Vec::new(),
            unreadable_dirs: Vec::new(),
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
