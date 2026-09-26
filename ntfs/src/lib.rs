//! NTFS-Zugriff für stratum: eine Datei oder ein Verzeichnis gezielt per Pfad
//! lesen, ohne das Dateisystem in den Host-Kernel einzuhängen.
//!
//! Aufbauend auf dem `ntfs`-Crate, das die eigentliche MFT-Auswertung
//! übernimmt. Diese Schicht bindet das Volume an einen read-only Ausschnitt
//! des Images (eine Partition) und liefert die Bytes einer Datei zusammen mit
//! ihrer Herkunft (Pfad, MFT-Nummer, Offset im Image), damit jeder spätere
//! Fund nachvollziehbar bleibt.
//!
//! Der Zugriff ist bewusst gezielt statt vollständig: die Analyzer holen sich
//! genau die Artefakte, die sie brauchen (Registry-Hives, NTUSER.DAT,
//! Prefetch-Dateien, Browser-Profile, Tor-Konfiguration), nicht den ganzen
//! Baum.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;

use std::io::{Cursor, Read, Seek, SeekFrom};

use ntfs::attribute_value::NtfsAttributeValue;
use ntfs::indexes::NtfsFileNameIndex;
use ntfs::structured_values::{NtfsFileNamespace, NtfsStandardInformation};
use ntfs::{Ntfs, NtfsFile};

use stratum_core::ImageReader;

pub use error::NtfsVolumeError;

/// Obergrenze für die Größe einer einzelnen gelesenen Datei (256 MiB).
///
/// Schützt vor einer manipulierten MFT, die eine absurde Dateigröße angibt.
/// Die forensisch relevanten Artefakte (Hives, Prefetch, kleine DB-Dateien)
/// liegen weit darunter.
pub const MAX_FILE_SIZE: u64 = 256 * 1024 * 1024;

/// Ein geöffnetes NTFS-Volume. Generisch über die darunterliegende Quelle
/// (`Read + Seek`): ein Ausschnitt des Images (`Cursor<&[u8]>`) oder der Reader
/// einer Volume Shadow Copy.
pub struct NtfsVolume<R: Read + Seek> {
    ntfs: Ntfs,
    fs: R,
    part_offset: u64,
    part_size: u64,
}

/// Herkunftsdaten einer Datei.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMeta {
    /// Angefragter Pfad.
    pub path: String,
    /// MFT-Datensatznummer, eindeutiger Anker der Datei im Volume.
    pub mft_record: u64,
    /// Größe der ungenannten Datenstroms in Bytes.
    pub size: u64,
    /// Absoluter Byte-Offset des MFT-Datensatzes im Image, falls bekannt.
    pub record_offset: Option<u64>,
    /// Erstellzeit als Windows-FILETIME (100-ns-Schritte seit 1601, UTC).
    pub created: u64,
    /// Letzte Änderung des Inhalts als FILETIME.
    pub modified: u64,
    /// Letzter Zugriff als FILETIME.
    pub accessed: u64,
    /// Letzte Änderung des MFT-Datensatzes als FILETIME.
    pub mft_modified: u64,
}

/// Inhalt einer gelesenen Datei mitsamt Herkunft.
#[derive(Debug, Clone)]
pub struct FileData {
    /// Herkunftsdaten.
    pub meta: FileMeta,
    /// Roher Inhalt des ungenannten Datenstroms.
    pub data: Vec<u8>,
}

/// Ein Eintrag eines Verzeichnisses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    /// Name des Eintrags.
    pub name: String,
    /// MFT-Datensatznummer.
    pub mft_record: u64,
    /// Länge der Datei in Bytes (aus dem Verzeichniseintrag).
    pub size: u64,
    /// Ob der Eintrag ein Verzeichnis ist.
    pub is_directory: bool,
}

/// Ein Eintrag aus dem rekursiven Verzeichnis-Durchlauf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalkEntry {
    /// Vollständiger Pfad ab der Wurzel, mit `\` getrennt.
    pub path: String,
    /// MFT-Datensatznummer, zum direkten Lesen ohne erneute Pfadauflösung.
    pub mft_record: u64,
    /// Länge der Datei in Bytes.
    pub size: u64,
    /// Ob der Eintrag ein Verzeichnis ist.
    pub is_directory: bool,
}

/// Obergrenze für die Zahl der Einträge eines Durchlaufs (Schutz vor
/// manipulierten Images mit absurd vielen Einträgen).
pub const MAX_WALK_ENTRIES: usize = 5_000_000;
/// Obergrenze für die Verzeichnistiefe.
const MAX_WALK_DEPTH: usize = 128;

impl<'a> NtfsVolume<Cursor<&'a [u8]>> {
    /// Öffnet ein NTFS-Volume, das bei `part_offset` beginnt und `part_size`
    /// Bytes umfasst.
    pub fn open(
        img: &'a ImageReader,
        part_offset: u64,
        part_size: u64,
    ) -> Result<Self, NtfsVolumeError> {
        let image_size = img.len();
        let end = part_offset
            .checked_add(part_size)
            .filter(|&e| e <= image_size)
            .ok_or(NtfsVolumeError::OutOfImage {
                offset: part_offset,
                size: part_size,
                image_size,
            })?;
        let start = usize::try_from(part_offset).map_err(|_| NtfsVolumeError::OutOfImage {
            offset: part_offset,
            size: part_size,
            image_size,
        })?;
        let slice = &img.as_slice()[start..end as usize];
        Self::from_reader(Cursor::new(slice), part_offset, part_size)
    }

    /// Öffnet ein NTFS-Volume, das bereits als blanker Byte-Slice vorliegt
    /// (das Volume beginnt bei Byte 0). Nützlich für Tests und Fuzzing.
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, NtfsVolumeError> {
        Self::from_reader(Cursor::new(data), 0, data.len() as u64)
    }
}

impl<R: Read + Seek> NtfsVolume<R> {
    /// Öffnet ein NTFS-Volume über eine beliebige `Read + Seek`-Quelle, z. B.
    /// den rekonstruierten Reader einer Volume Shadow Copy. `part_offset` dient
    /// nur der Herkunftsangabe (bei Snapshots ohne festen Image-Offset 0).
    pub fn from_reader(
        mut fs: R,
        part_offset: u64,
        part_size: u64,
    ) -> Result<Self, NtfsVolumeError> {
        let mut ntfs = Ntfs::new(&mut fs)?;
        // Für den namensbasierten Verzeichnis-Lookup muss die $UpCase-Tabelle
        // geladen sein.
        ntfs.read_upcase_table(&mut fs)?;

        Ok(Self {
            ntfs,
            fs,
            part_offset,
            part_size,
        })
    }

    /// Größe der Cluster in Bytes.
    pub fn cluster_size(&self) -> u32 {
        self.ntfs.cluster_size()
    }

    /// Seriennummer des Volumes.
    pub fn serial_number(&self) -> u64 {
        self.ntfs.serial_number()
    }

    /// Volume-Bezeichnung, falls gesetzt.
    pub fn label(&mut self) -> Option<String> {
        let name = self.ntfs.volume_name(&mut self.fs)?.ok()?;
        Some(name.name().to_string_lossy())
    }

    /// Liest die Datei unter `path` (z. B. `"Windows/System32/config/SYSTEM"`).
    ///
    /// Gibt `Ok(None)` zurück, wenn ein Teil des Pfads nicht existiert. Pfade
    /// werden ohne Beachtung der Groß-/Kleinschreibung aufgelöst, Trenner ist
    /// `/` oder `\`.
    pub fn read_file(&mut self, path: &str) -> Result<Option<FileData>, NtfsVolumeError> {
        let ntfs = &self.ntfs;
        let fs = &mut self.fs;

        let Some(rec) = resolve(ntfs, fs, path)? else {
            return Ok(None);
        };
        read_record(ntfs, fs, rec, path, self.part_offset, self.part_size)
    }

    /// Prüft, ob ein Pfad existiert.
    pub fn exists(&mut self, path: &str) -> Result<bool, NtfsVolumeError> {
        let ntfs = &self.ntfs;
        let fs = &mut self.fs;
        Ok(resolve(ntfs, fs, path)?.is_some())
    }

    /// Listet die Einträge des Verzeichnisses unter `path`. Der leere Pfad
    /// liefert das Wurzelverzeichnis. DOS-Kurznamen werden übersprungen, damit
    /// jeder Eintrag nur einmal erscheint.
    pub fn list_dir(&mut self, path: &str) -> Result<Option<Vec<DirEntry>>, NtfsVolumeError> {
        let ntfs = &self.ntfs;
        let fs = &mut self.fs;

        let Some(rec) = resolve(ntfs, fs, path)? else {
            return Ok(None);
        };
        list_children(ntfs, fs, rec).map(Some)
    }

    /// Liest eine Datei direkt über ihre MFT-Datensatznummer, ohne den Pfad
    /// erneut aufzulösen. `path` wird nur für die Herkunftsangabe übernommen.
    pub fn read_file_by_record(
        &mut self,
        record: u64,
        path: &str,
    ) -> Result<Option<FileData>, NtfsVolumeError> {
        let ntfs = &self.ntfs;
        let fs = &mut self.fs;
        read_record(ntfs, fs, record, path, self.part_offset, self.part_size)
    }

    /// Durchläuft das komplette Verzeichnis ab der Wurzel und liefert alle
    /// Dateien und Verzeichnisse mit vollständigem Pfad. Es werden nur Metadaten
    /// gelesen, keine Dateiinhalte; das ist die Grundlage des Pfad-Index.
    ///
    /// Der Durchlauf ist gegen manipulierte Images abgesichert: bereits besuchte
    /// Verzeichnisse werden nicht erneut betreten (Zyklenschutz), die Tiefe und
    /// die Gesamtzahl der Einträge sind begrenzt.
    pub fn walk(&mut self) -> Result<Vec<WalkEntry>, NtfsVolumeError> {
        let ntfs = &self.ntfs;
        let fs = &mut self.fs;
        let root = ntfs.root_directory(fs)?.file_record_number();

        let mut out = Vec::new();
        let mut visited = std::collections::HashSet::new();
        visited.insert(root);
        // Iterativer Durchlauf (Stack), damit die Rekursionstiefe nicht den
        // Programmstack sprengt.
        let mut stack: Vec<(u64, String, usize)> = vec![(root, String::new(), 0)];

        while let Some((dir_rec, prefix, depth)) = stack.pop() {
            if depth >= MAX_WALK_DEPTH || out.len() >= MAX_WALK_ENTRIES {
                continue;
            }
            let children = match list_children(ntfs, fs, dir_rec) {
                Ok(c) => c,
                Err(_) => continue, // beschädigtes Verzeichnis überspringen
            };
            for c in children {
                let path = if prefix.is_empty() {
                    c.name.clone()
                } else {
                    format!("{prefix}\\{}", c.name)
                };
                if c.is_directory && visited.insert(c.mft_record) {
                    stack.push((c.mft_record, path.clone(), depth + 1));
                }
                out.push(WalkEntry {
                    path,
                    mft_record: c.mft_record,
                    size: c.size,
                    is_directory: c.is_directory,
                });
                if out.len() >= MAX_WALK_ENTRIES {
                    break;
                }
            }
        }
        Ok(out)
    }
}

/// Listet die Einträge eines Verzeichnisses über dessen MFT-Nummer.
fn list_children<R: Read + Seek>(
    ntfs: &Ntfs,
    fs: &mut R,
    dir_rec: u64,
) -> Result<Vec<DirEntry>, NtfsVolumeError> {
    let dir = ntfs.file(fs, dir_rec)?;
    if !dir.is_directory() {
        return Err(NtfsVolumeError::NotADirectory {
            path: format!("MFT {dir_rec}"),
        });
    }
    let index = dir.directory_index(fs)?;
    let mut entries = index.entries();
    let mut out = Vec::new();
    while let Some(entry) = entries.next(fs) {
        let entry = entry?;
        let Some(key) = entry.key() else { continue };
        let key = key?;
        if key.namespace() == NtfsFileNamespace::Dos {
            continue;
        }
        out.push(DirEntry {
            name: key.name().to_string_lossy(),
            mft_record: entry.file_reference().file_record_number(),
            size: key.data_size(),
            is_directory: key.is_directory(),
        });
    }
    Ok(out)
}

/// Liest den Inhalt eines Datensatzes (ungenannter $DATA-Strom) mitsamt
/// Herkunft.
fn read_record<R: Read + Seek>(
    ntfs: &Ntfs,
    fs: &mut R,
    rec: u64,
    path: &str,
    part_offset: u64,
    part_size: u64,
) -> Result<Option<FileData>, NtfsVolumeError> {
    let file = ntfs.file(fs, rec)?;
    if file.is_directory() {
        return Err(NtfsVolumeError::NotAFile {
            path: path.to_string(),
        });
    }

    let meta = file_meta(&file, path, part_offset)?;
    let data = read_data(&file, fs, part_size)?;
    Ok(Some(FileData { meta, data }))
}

/// Beschreibung eines Datenlaufs (Nutzdaten oder spärlich).
enum RunPlan {
    /// Nicht-residente Läufe: (physischer Offset im Volume, belegte Länge).
    /// `None` als Offset bedeutet einen spärlichen Lauf (mit Nullen zu füllen).
    Runs(Vec<(Option<u64>, u64)>),
    /// Residente Daten: (physischer Offset, Länge).
    Resident(u64, u64),
    /// Sonderfall (Attributliste): über den eingebauten Leser holen.
    Fallback,
}

/// Liest den ungenannten `$DATA`-Strom, indem die Datenläufe selbst
/// zusammengesetzt werden. Spärliche Läufe werden mit Nullen gefüllt, damit die
/// Byte-Ausrichtung erhalten bleibt (der eingebaute Leser des ntfs-Crates
/// lieferte hier fragmentierte/spärliche Dateien falsch zusammengesetzt).
fn read_data<R: Read + Seek>(
    file: &NtfsFile<'_>,
    fs: &mut R,
    part_size: u64,
) -> Result<Vec<u8>, NtfsVolumeError> {
    let Some(item) = file.data(fs, "") else {
        return Ok(Vec::new());
    };
    let item = item?;
    let attribute = item.to_attribute()?;
    let file_size = attribute.value_length().min(part_size).min(MAX_FILE_SIZE);
    if file_size == 0 {
        return Ok(Vec::new());
    }

    // Läufe ohne fs-Zugriff einsammeln, damit fs danach frei zum Lesen ist.
    let plan = {
        let value = attribute.value(fs)?;
        match value {
            NtfsAttributeValue::NonResident(nr) => {
                let mut runs = Vec::new();
                for run in nr.data_runs() {
                    let run = run?;
                    runs.push((
                        run.data_position().value().map(|p| p.get()),
                        run.allocated_size(),
                    ));
                }
                RunPlan::Runs(runs)
            }
            NtfsAttributeValue::Resident(ref res) => match res.data_position().value() {
                Some(p) => RunPlan::Resident(p.get(), file_size),
                None => RunPlan::Fallback,
            },
            NtfsAttributeValue::AttributeListNonResident(_) => RunPlan::Fallback,
        }
    };

    let cap = usize::try_from(file_size).unwrap_or(0);
    let mut buf = Vec::with_capacity(cap);
    match plan {
        RunPlan::Runs(runs) => {
            let mut done: u64 = 0;
            for (pos, alloc) in runs {
                if done >= file_size {
                    break;
                }
                let take = alloc.min(file_size - done);
                let take_usize = usize::try_from(take).unwrap_or(0);
                match pos {
                    Some(p) => {
                        // Bei Lesefehlern (z. B. gekürztes Image) den Lauf
                        // mit Nullen füllen, damit die Ausrichtung erhalten bleibt.
                        if fs.seek(SeekFrom::Start(p)).is_ok() {
                            let start = buf.len();
                            buf.resize(start + take_usize, 0);
                            if fs.read_exact(&mut buf[start..]).is_err() {
                                // teilweise gelesen ist ok; Rest bleibt 0
                            }
                        } else {
                            buf.resize(buf.len() + take_usize, 0);
                        }
                    }
                    None => buf.resize(buf.len() + take_usize, 0),
                }
                done += alloc;
            }
            buf.truncate(cap);
        }
        RunPlan::Resident(p, len) => {
            let len = usize::try_from(len).unwrap_or(0);
            buf.resize(len, 0);
            if fs.seek(SeekFrom::Start(p)).is_ok() {
                let _ = fs.read_exact(&mut buf);
            }
        }
        RunPlan::Fallback => {
            let value = attribute.value(fs)?;
            value.attach(fs).take(MAX_FILE_SIZE).read_to_end(&mut buf)?;
        }
    }
    Ok(buf)
}

/// Löst einen Pfad in eine MFT-Datensatznummer auf.
fn resolve<R: Read + Seek>(
    ntfs: &Ntfs,
    fs: &mut R,
    path: &str,
) -> Result<Option<u64>, NtfsVolumeError> {
    let mut rec = ntfs.root_directory(fs)?.file_record_number();

    for component in path.split(['/', '\\']).filter(|c| !c.is_empty()) {
        let dir = ntfs.file(fs, rec)?;
        if !dir.is_directory() {
            return Ok(None);
        }
        let index = dir.directory_index(fs)?;
        let mut finder = index.finder();
        match NtfsFileNameIndex::find(&mut finder, ntfs, fs, component) {
            Some(entry) => {
                rec = entry?.file_reference().file_record_number();
            }
            None => return Ok(None),
        }
    }

    Ok(Some(rec))
}

fn file_meta(
    file: &NtfsFile<'_>,
    path: &str,
    part_offset: u64,
) -> Result<FileMeta, NtfsVolumeError> {
    let info: NtfsStandardInformation = file.info()?;
    let record_offset = file
        .position()
        .value()
        .map(|p| part_offset.saturating_add(p.get()));
    Ok(FileMeta {
        path: path.to_string(),
        mft_record: file.file_record_number(),
        size: u64::from(file.data_size()),
        record_offset,
        created: info.creation_time().nt_timestamp(),
        modified: info.modification_time().nt_timestamp(),
        accessed: info.access_time().nt_timestamp(),
        mft_modified: info.mft_record_modification_time().nt_timestamp(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pfadauflösung und Fehlerpfade ohne echtes Image testet der
    // Integrationstest gegen ein mit mkntfs erzeugtes Volume. Hier bleibt Platz
    // für reine Logik, die ohne Dateisystem auskommt.

    #[test]
    fn max_file_size_ist_gesetzt() {
        assert_eq!(MAX_FILE_SIZE, 256 * 1024 * 1024);
    }
}
