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
pub mod lznt1;
pub mod wof;

use std::io::{Cursor, Read, Seek, SeekFrom};

use ntfs::attribute_value::NtfsAttributeValue;
use ntfs::indexes::NtfsFileNameIndex;
use ntfs::structured_values::{
    NtfsAttributeList, NtfsFileName, NtfsFileNamespace, NtfsStandardInformation,
};
use ntfs::{Ntfs, NtfsAttributeFlags, NtfsAttributeType, NtfsFile};

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
    /// WOF-Kompressionsverfahren, falls der Inhalt aus `WofCompressedData` entpackt wurde.
    pub wof: Option<&'static str>,
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
    /// MFT-Datensatznummer des Verzeichnisses, in dem der Eintrag gefunden wurde.
    pub parent_record: u64,
    /// Länge der Datei in Bytes.
    pub size: u64,
    /// Ob der Eintrag ein Verzeichnis ist.
    pub is_directory: bool,
}

/// Ein Verzeichnis, dessen Einträge der Durchlauf nicht lesen konnte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedDir {
    /// Pfad des Verzeichnisses (leer für die Wurzel).
    pub path: String,
    /// MFT-Datensatznummer.
    pub mft_record: u64,
    /// Fehlermeldung.
    pub error: String,
}

/// Ergebnis eines Durchlaufs mit allem, was dabei nicht erfasst werden konnte.
#[derive(Debug, Clone, Default)]
pub struct WalkResult {
    /// Alle erreichten Dateien und Verzeichnisse.
    pub entries: Vec<WalkEntry>,
    /// Verzeichnisse, deren Inhalt fehlt, weil ihr Index nicht lesbar war.
    pub skipped: Vec<SkippedDir>,
    /// Verzeichnisse, die wegen der Tiefengrenze nicht betreten wurden.
    pub depth_limited: u64,
    /// Ob die Obergrenze der Einträge erreicht wurde.
    pub truncated: bool,
}

/// Die vier NTFS-Zeitstempel als FILETIME (100-ns-Schritte seit 1601, UTC).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NtfsTimes {
    /// Erstellung.
    pub created: u64,
    /// Letzte Änderung des Inhalts.
    pub modified: u64,
    /// Letzte Änderung des MFT-Datensatzes.
    pub mft_modified: u64,
    /// Letzter Zugriff.
    pub accessed: u64,
}

/// Benannter Datenstrom (Alternate Data Stream) mit logischer Länge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedStream {
    /// Name des Stroms, z. B. `Zone.Identifier`.
    pub name: String,
    /// Logische Länge in Bytes.
    pub size: u64,
}

/// Metadaten eines MFT-Datensatzes, ohne Dateiinhalt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordInfo {
    /// MFT-Datensatznummer.
    pub mft_record: u64,
    /// Sequenznummer des Datensatzes (steigt bei Wiederverwendung).
    pub sequence: u16,
    /// Absoluter Byte-Offset des Datensatzes im Image, falls bekannt.
    pub record_offset: Option<u64>,
    /// Ob der Datensatz ein Verzeichnis beschreibt.
    pub is_directory: bool,
    /// Zahl der Hardlinks laut Datensatzkopf.
    pub hard_links: u16,
    /// Zeiten aus `$STANDARD_INFORMATION`.
    pub si_times: Option<NtfsTimes>,
    /// Dateiattribute aus `$STANDARD_INFORMATION` (Windows-Bitmaske).
    pub file_attributes: u32,
    /// Zeiten aus dem passenden `$FILE_NAME`-Attribut.
    pub fn_times: Option<NtfsTimes>,
    /// Logische Länge des unbenannten `$DATA`-Stroms.
    pub data_size: Option<u64>,
    /// Benannte `$DATA`-Ströme.
    pub streams: Vec<NamedStream>,
    /// Reparse-Tag, falls ein `$REPARSE_POINT` vorhanden ist.
    pub reparse_tag: Option<u32>,
    /// WOF-Kompressionsverfahren bei vom System komprimierten Dateien.
    pub wof: Option<&'static str>,
}

/// Obergrenze für benannte Datenströme je Datensatz (Schutz vor Manipulation).
const MAX_STREAMS: usize = 64;

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

    /// Schreibt den vollständigen logischen Inhalt einer Datei direkt über ihre
    /// MFT-Datensatznummer nach `out`. Normale und spärliche Datenströme werden
    /// blockweise verarbeitet, ohne die ganze Datei im Speicher zu halten.
    ///
    /// NTFS- und WOF-komprimierte Dateien müssen für die Dekompression derzeit
    /// vollständig im Speicher liegen und unterliegen daher [`MAX_FILE_SIZE`].
    /// Bei einem Lesefehler werden keine Ersatzbytes erzeugt: Der Aufrufer darf
    /// einen bis dahin berechneten Hash nicht als vollständigen Dateihash nutzen.
    pub fn write_file_by_record<W: std::io::Write>(
        &mut self,
        record: u64,
        path: &str,
        out: &mut W,
    ) -> Result<Option<FileMeta>, NtfsVolumeError> {
        let ntfs = &self.ntfs;
        let fs = &mut self.fs;
        write_record(
            ntfs,
            fs,
            record,
            path,
            self.part_offset,
            self.part_size,
            out,
        )
    }

    /// Liest die Metadaten eines Datensatzes in einem Durchlauf über seine
    /// Attribute: `$STANDARD_INFORMATION`, das zum Eintrag passende
    /// `$FILE_NAME` (gleiches Elternverzeichnis, bevorzugt nicht der DOS-Kurzname)
    /// und die Längen aller `$DATA`-Ströme. Dateiinhalte werden nicht gelesen.
    pub fn record_info(
        &mut self,
        record: u64,
        parent_record: Option<u64>,
    ) -> Result<RecordInfo, NtfsVolumeError> {
        let ntfs = &self.ntfs;
        let fs = &mut self.fs;
        let file = ntfs.file(fs, record)?;
        let mut info = RecordInfo {
            mft_record: record,
            sequence: file.sequence_number(),
            record_offset: file
                .position()
                .value()
                .map(|p| self.part_offset.saturating_add(p.get())),
            is_directory: file.is_directory(),
            hard_links: file.hard_link_count(),
            si_times: None,
            file_attributes: 0,
            fn_times: None,
            data_size: None,
            streams: Vec::new(),
            reparse_tag: None,
            wof: None,
        };
        let mut fn_is_dos = true;
        let mut attrs = file.attributes();
        while let Some(item) = attrs.next(fs) {
            let item = item?;
            let attribute = item.to_attribute()?;
            match attribute.ty()? {
                NtfsAttributeType::StandardInformation if info.si_times.is_none() => {
                    let si: NtfsStandardInformation = attribute.structured_value(fs)?;
                    info.si_times = Some(NtfsTimes {
                        created: si.creation_time().nt_timestamp(),
                        modified: si.modification_time().nt_timestamp(),
                        mft_modified: si.mft_record_modification_time().nt_timestamp(),
                        accessed: si.access_time().nt_timestamp(),
                    });
                    info.file_attributes = si.file_attributes().bits();
                }
                NtfsAttributeType::FileName if fn_is_dos => {
                    let name: NtfsFileName = attribute.structured_value(fs)?;
                    let parent_ok = parent_record.is_none_or(|p| {
                        name.parent_directory_reference().file_record_number() == p
                    });
                    if !parent_ok {
                        continue;
                    }
                    fn_is_dos = name.namespace() == NtfsFileNamespace::Dos;
                    info.fn_times = Some(NtfsTimes {
                        created: name.creation_time().nt_timestamp(),
                        modified: name.modification_time().nt_timestamp(),
                        mft_modified: name.mft_record_modification_time().nt_timestamp(),
                        accessed: name.access_time().nt_timestamp(),
                    });
                }
                NtfsAttributeType::ReparsePoint if info.reparse_tag.is_none() => {
                    let data = small_value(&attribute, fs)?;
                    info.reparse_tag = data
                        .get(..4)
                        .map(|t| u32::from_le_bytes([t[0], t[1], t[2], t[3]]));
                    // Unbekannte WOF-Varianten nur kennzeichnen, der Katalog bricht nicht ab.
                    info.wof = match wof::parse_reparse(&data) {
                        Ok(format) => format.map(wof::WofFormat::name),
                        Err(_) => Some("unbekannt"),
                    };
                }
                NtfsAttributeType::Data => {
                    let stream = attribute.name()?.to_string_lossy();
                    // Bei Attributlisten erscheint ein Strom in mehreren Teilen;
                    // nur der erste trägt die gültige Länge.
                    if stream.is_empty() {
                        info.data_size.get_or_insert(attribute.value_length());
                    } else if info.streams.len() < MAX_STREAMS
                        && !info.streams.iter().any(|s| s.name == stream)
                    {
                        info.streams.push(NamedStream {
                            name: stream,
                            size: attribute.value_length(),
                        });
                    }
                }
                _ => {}
            }
        }
        Ok(info)
    }

    /// Durchläuft das komplette Verzeichnis ab der Wurzel und liefert alle
    /// Dateien und Verzeichnisse mit vollständigem Pfad. Es werden nur Metadaten
    /// gelesen, keine Dateiinhalte; das ist die Grundlage des Pfad-Index.
    ///
    /// Der Durchlauf ist gegen manipulierte Images abgesichert: bereits besuchte
    /// Verzeichnisse werden nicht erneut betreten (Zyklenschutz), die Tiefe und
    /// die Gesamtzahl der Einträge sind begrenzt.
    pub fn walk(&mut self) -> Result<Vec<WalkEntry>, NtfsVolumeError> {
        Ok(self.walk_report()?.entries)
    }

    /// Wie [`walk`](Self::walk), meldet aber zusätzlich unlesbare Verzeichnisse
    /// und erreichte Grenzen, statt sie stillschweigend zu übergehen.
    pub fn walk_report(&mut self) -> Result<WalkResult, NtfsVolumeError> {
        let ntfs = &self.ntfs;
        let fs = &mut self.fs;
        let root = ntfs.root_directory(fs)?.file_record_number();

        let mut result = WalkResult::default();
        let out = &mut result.entries;
        let mut visited = std::collections::HashSet::new();
        visited.insert(root);
        // Iterativer Durchlauf (Stack), damit die Rekursionstiefe nicht den
        // Programmstack sprengt.
        let mut stack: Vec<(u64, String, usize)> = vec![(root, String::new(), 0)];

        while let Some((dir_rec, prefix, depth)) = stack.pop() {
            if out.len() >= MAX_WALK_ENTRIES {
                result.truncated = true;
                break;
            }
            if depth >= MAX_WALK_DEPTH {
                result.depth_limited += 1;
                continue;
            }
            let children = match list_children(ntfs, fs, dir_rec) {
                Ok(c) => c,
                Err(e) => {
                    result.skipped.push(SkippedDir {
                        path: prefix,
                        mft_record: dir_rec,
                        error: e.to_string(),
                    });
                    continue;
                }
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
                    parent_record: dir_rec,
                    size: c.size,
                    is_directory: c.is_directory,
                });
                if out.len() >= MAX_WALK_ENTRIES {
                    result.truncated = true;
                    break;
                }
            }
        }
        Ok(result)
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

    // Vom System komprimierte Dateien (WOF): der Inhalt steht in WofCompressedData,
    // der unbenannte Strom trägt nur die Größe. Unbekannte Varianten ergeben einen
    // Fehler, nie einen leeren oder falschen Inhalt.
    let (data, stream_size, wof) = match wof_format(&file, fs)? {
        Some(format) => {
            let size = file
                .data(fs, "")
                .transpose()?
                .map(|item| item.to_attribute().map(|a| a.value_length()))
                .transpose()?
                .unwrap_or(0);
            let (stream, _) = read_data(ntfs, &file, fs, part_size, wof::WOF_STREAM)?;
            let limit = usize::try_from(MAX_FILE_SIZE.min(part_size)).unwrap_or(usize::MAX);
            let data = wof::decompress(&stream, format, size, limit)?;
            (data, size, Some(format.name()))
        }
        None => {
            let (data, size) = read_data(ntfs, &file, fs, part_size, "")?;
            (data, size, None)
        }
    };
    let mut meta = file_meta(&file, path, part_offset, stream_size)?;
    meta.wof = wof;
    Ok(Some(FileData { meta, data }))
}

/// Schreibt den unbenannten `$DATA`-Strom eines Datensatzes vollständig.
fn write_record<R: Read + Seek, W: std::io::Write>(
    ntfs: &Ntfs,
    fs: &mut R,
    rec: u64,
    path: &str,
    part_offset: u64,
    part_size: u64,
    out: &mut W,
) -> Result<Option<FileMeta>, NtfsVolumeError> {
    let file = ntfs.file(fs, rec)?;
    if file.is_directory() {
        return Err(NtfsVolumeError::NotAFile {
            path: path.to_string(),
        });
    }

    let (stream_size, wof) = match wof_format(&file, fs)? {
        Some(format) => {
            let size = file
                .data(fs, "")
                .transpose()?
                .map(|item| item.to_attribute().map(|a| a.value_length()))
                .transpose()?
                .unwrap_or(0);
            if size > MAX_FILE_SIZE {
                return Err(NtfsVolumeError::CompressedFileTooLarge {
                    path: path.to_string(),
                    size,
                    limit: MAX_FILE_SIZE,
                });
            }
            let (stream, _) = read_data(ntfs, &file, fs, part_size, wof::WOF_STREAM)?;
            let data = wof::decompress(&stream, format, size, size as usize)?;
            out.write_all(&data)?;
            (size, Some(format.name()))
        }
        None => {
            let size = write_data(ntfs, &file, fs, part_size, path, out)?;
            (size, None)
        }
    };
    let mut meta = file_meta(&file, path, part_offset, stream_size)?;
    meta.wof = wof;
    Ok(Some(meta))
}

/// Liest den (kleinen) Wert eines Attributs, höchstens 64 KiB.
fn small_value<R: Read + Seek>(
    attribute: &ntfs::NtfsAttribute<'_, '_>,
    fs: &mut R,
) -> Result<Vec<u8>, NtfsVolumeError> {
    let mut buf = Vec::new();
    match attribute.value(fs)? {
        NtfsAttributeValue::Resident(r) => {
            buf.extend_from_slice(&r.data()[..r.data().len().min(65536)])
        }
        value => {
            value.attach(fs).take(65536).read_to_end(&mut buf)?;
        }
    }
    Ok(buf)
}

/// WOF-Verfahren einer Datei aus ihrem `$REPARSE_POINT`, sonst `None`.
fn wof_format<R: Read + Seek>(
    file: &NtfsFile<'_>,
    fs: &mut R,
) -> Result<Option<wof::WofFormat>, NtfsVolumeError> {
    let mut attrs = file.attributes();
    while let Some(item) = attrs.next(fs) {
        let item = item?;
        let attribute = item.to_attribute()?;
        if attribute.ty()? == NtfsAttributeType::ReparsePoint {
            let data = small_value(&attribute, fs)?;
            return Ok(wof::parse_reparse(&data)?);
        }
    }
    Ok(None)
}

/// Beschreibung eines Datenlaufs (Nutzdaten oder spärlich).
enum RunPlan {
    /// Nicht-residente Läufe: (physischer Offset im Volume, belegte Länge).
    /// `None` als Offset bedeutet einen spärlichen Lauf (mit Nullen zu füllen).
    Runs(Vec<(Option<u64>, u64)>),
    /// Nicht-residente Läufe eines NTFS-komprimierten Stroms (LZNT1). Werden
    /// einheitenweise entpackt statt roh zusammengesetzt.
    CompressedRuns(Vec<(Option<u64>, u64)>),
    /// Residente Daten, bereits aus dem fixup-korrigierten Dateidatensatz kopiert.
    Resident(Vec<u8>),
}

/// Schreibt einen unbenannten Strom blockweise. Nur komprimierte Datenläufe
/// verwenden noch den vorhandenen, begrenzten Dekompressionspfad.
fn write_data<R: Read + Seek, W: std::io::Write>(
    ntfs: &Ntfs,
    file: &NtfsFile<'_>,
    fs: &mut R,
    part_size: u64,
    path: &str,
    out: &mut W,
) -> Result<u64, NtfsVolumeError> {
    let Some(item) = file.data(fs, "") else {
        return Ok(0);
    };
    let item = item?;
    let attribute = item.to_attribute()?;
    let stream_size = attribute.value_length();
    if stream_size > part_size {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("logische Dateigröße {stream_size} überschreitet Volumegröße {part_size}"),
        )
        .into());
    }
    if stream_size == 0 {
        return Ok(0);
    }

    let compressed = attribute.flags().contains(NtfsAttributeFlags::COMPRESSED);
    if compressed {
        if stream_size > MAX_FILE_SIZE {
            return Err(NtfsVolumeError::CompressedFileTooLarge {
                path: path.to_string(),
                size: stream_size,
                limit: MAX_FILE_SIZE,
            });
        }
        let (data, size) = read_data(ntfs, file, fs, part_size, "")?;
        if data.len() as u64 != size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "NTFS-komprimierter Inhalt ist unvollständig",
            )
            .into());
        }
        out.write_all(&data)?;
        return Ok(size);
    }

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
            NtfsAttributeValue::Resident(ref resident) => {
                let len = usize::try_from(stream_size)
                    .unwrap_or(usize::MAX)
                    .min(resident.data().len());
                RunPlan::Resident(resident.data()[..len].to_vec())
            }
            NtfsAttributeValue::AttributeListNonResident(_) => {
                RunPlan::Runs(collect_attribute_list_runs(ntfs, fs, file, "")?)
            }
        }
    };

    match plan {
        RunPlan::Resident(data) => {
            if data.len() as u64 != stream_size {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "residenter Dateiinhalt ist unvollständig",
                )
                .into());
            }
            out.write_all(&data)?;
        }
        RunPlan::Runs(runs) => write_runs(fs, &runs, stream_size, out)?,
        RunPlan::CompressedRuns(_) => unreachable!("Kompression wurde vorab behandelt"),
    }
    Ok(stream_size)
}

fn write_runs<R: Read + Seek, W: std::io::Write>(
    fs: &mut R,
    runs: &[(Option<u64>, u64)],
    stream_size: u64,
    out: &mut W,
) -> Result<(), NtfsVolumeError> {
    const BLOCK: usize = 1024 * 1024;
    let mut buf = vec![0u8; BLOCK];
    let mut done = 0u64;
    for &(position, allocated) in runs {
        if done >= stream_size {
            break;
        }
        let mut remaining = allocated.min(stream_size - done);
        if let Some(position) = position {
            fs.seek(SeekFrom::Start(position))?;
            while remaining > 0 {
                let n = usize::try_from(remaining.min(BLOCK as u64)).unwrap_or(BLOCK);
                fs.read_exact(&mut buf[..n])?;
                out.write_all(&buf[..n])?;
                remaining -= n as u64;
                done += n as u64;
            }
        } else {
            buf.fill(0);
            while remaining > 0 {
                let n = usize::try_from(remaining.min(BLOCK as u64)).unwrap_or(BLOCK);
                out.write_all(&buf[..n])?;
                remaining -= n as u64;
                done += n as u64;
            }
        }
    }
    if done != stream_size {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            format!("Datenläufe liefern {done} statt {stream_size} Bytes"),
        )
        .into());
    }
    Ok(())
}

/// Liest den ungenannten `$DATA`-Strom, indem die Datenläufe selbst
/// zusammengesetzt werden. Spärliche Läufe werden mit Nullen gefüllt, damit die
/// Byte-Ausrichtung erhalten bleibt (der eingebaute Leser des ntfs-Crates
/// lieferte hier fragmentierte/spärliche Dateien falsch zusammengesetzt).
///
/// Ist der Strom über eine Attributliste auf mehrere MFT-Datensätze verteilt
/// (`AttributeListNonResident`), werden die Läufe aller verbundenen
/// `$DATA`-Fragmente selbst eingesammelt (`collect_attribute_list_runs`) statt
/// dem eingebauten Leser zu vertrauen, der beim ersten nicht passenden
/// Listeneintrag abbricht und die Datei so verschoben zusammensetzt.
///
/// Mit gesetzter Umgebungsvariable `STRATUM_DEBUG` wird die erkannte Ablage
/// (resident, nicht-resident, Attributliste) samt Lauf-Anzahl auf `stderr`
/// gemeldet; hilfreich, um die Herkunft eines Fundes nachzuvollziehen.
fn read_data<R: Read + Seek>(
    ntfs: &Ntfs,
    file: &NtfsFile<'_>,
    fs: &mut R,
    part_size: u64,
    stream: &str,
) -> Result<(Vec<u8>, u64), NtfsVolumeError> {
    let Some(item) = file.data(fs, stream) else {
        return Ok((Vec::new(), 0));
    };
    let item = item?;
    let attribute = item.to_attribute()?;
    let stream_size = attribute.value_length();
    let limit = part_size.min(MAX_FILE_SIZE);
    if stream_size > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Datenstrom mit {stream_size} Bytes überschreitet Lesegrenze {limit}"),
        )
        .into());
    }
    let file_size = stream_size;
    if file_size == 0 {
        return Ok((Vec::new(), stream_size));
    }

    let debug = std::env::var_os("STRATUM_DEBUG").is_some();
    let flags = attribute.flags();
    let compressed = flags.contains(NtfsAttributeFlags::COMPRESSED);
    if debug {
        eprintln!(
            "[stratum] $DATA Flags: {flags:?}{}",
            if compressed {
                " (NTFS-komprimiert, LZNT1)"
            } else {
                ""
            }
        );
    }

    // Läufe ohne dauerhaften fs-Zugriff einsammeln, damit fs danach frei zum
    // Lesen ist.
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
                if debug {
                    let sparse = runs.iter().filter(|(p, _)| p.is_none()).count();
                    eprintln!(
                        "[stratum] $DATA nicht-resident{}: {} Lauf/Laeufe ({sparse} spaerlich), {file_size} Bytes",
                        if compressed { " (LZNT1)" } else { "" },
                        runs.len()
                    );
                    for (i, (pos, len)) in runs.iter().enumerate() {
                        eprintln!("[stratum]   Lauf {i}: pos={pos:?} len={len}");
                    }
                }
                if compressed {
                    RunPlan::CompressedRuns(runs)
                } else {
                    RunPlan::Runs(runs)
                }
            }
            NtfsAttributeValue::Resident(ref res) => {
                // Nicht über `data_position()` vom Datenträger lesen: ntfs 0.4.0
                // liefert dort die Position des Attributkopfs, nicht des Werts,
                // und die Rohbytes wären nicht um die Update Sequence korrigiert.
                let data = res.data();
                let len = usize::try_from(file_size).unwrap_or(0).min(data.len());
                if debug {
                    eprintln!("[stratum] $DATA resident: {len} Bytes");
                }
                RunPlan::Resident(data[..len].to_vec())
            }
            NtfsAttributeValue::AttributeListNonResident(_) => {
                // `value` haelt hier keinen fs-Borrow; der Sammler darf fs nutzen.
                let runs = collect_attribute_list_runs(ntfs, fs, file, stream)?;
                if debug {
                    eprintln!(
                        "[stratum] $DATA ueber Attributliste{}: {} Lauf/Laeufe, {file_size} Bytes",
                        if compressed { " (LZNT1)" } else { "" },
                        runs.len()
                    );
                }
                if compressed {
                    RunPlan::CompressedRuns(runs)
                } else {
                    RunPlan::Runs(runs)
                }
            }
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
                        fs.seek(SeekFrom::Start(p))?;
                        let start = buf.len();
                        buf.resize(start + take_usize, 0);
                        fs.read_exact(&mut buf[start..])?;
                    }
                    None => buf.resize(buf.len() + take_usize, 0),
                }
                done += alloc;
            }
            buf.truncate(cap);
        }
        RunPlan::CompressedRuns(runs) => {
            buf = assemble_compressed(&runs, fs, u64::from(ntfs.cluster_size()), file_size)?;
        }
        RunPlan::Resident(data) => buf = data,
    }
    Ok((buf, stream_size))
}

/// Setzt einen NTFS-komprimierten (LZNT1) `$DATA`-Strom aus seinen Datenläufen
/// zusammen und entpackt ihn.
///
/// NTFS komprimiert in Einheiten zu 16 Clustern. Innerhalb einer Einheit liegen
/// die belegten (komprimierten) Cluster vorn, die durch die Kompression
/// eingesparten Cluster als spärlicher Lauf dahinter. Eine vollständig belegte
/// Einheit ist unkomprimiert abgelegt (roh übernehmen), eine vollständig
/// spärliche Einheit ist eine reine Nullfolge, sonst wird sie mit LZNT1
/// entpackt. Die Zuordnung der Läufe zu Einheiten erfolgt über die logische
/// Position (VCN), da ein Lauf Einheitengrenzen überspannen kann.
fn assemble_compressed<R: Read + Seek>(
    runs: &[(Option<u64>, u64)],
    fs: &mut R,
    cluster_size: u64,
    file_size: u64,
) -> Result<Vec<u8>, NtfsVolumeError> {
    // NTFS-Kompressionseinheit = 16 Cluster (einziger von NTFS genutzte Wert;
    // Kompression ist nur bei Clustergröße bis 4 KiB zulässig).
    let cu_size = cluster_size.saturating_mul(16);
    if cu_size == 0 {
        return Ok(Vec::new());
    }

    let allocated: u64 = runs.iter().map(|(_, len)| *len).sum();
    let alloc_usize = usize::try_from(allocated).unwrap_or(0);
    let mut raw = vec![0u8; alloc_usize];
    let num_units = allocated.div_ceil(cu_size) as usize;
    let mut real_per_unit = vec![0u64; num_units];

    // Rohpuffer der allozierten Daten füllen und je Einheit die Zahl belegter
    // (nicht spärlicher) Bytes zählen.
    let mut off: u64 = 0;
    for (pos, len) in runs {
        let len = *len;
        if let Some(p) = pos {
            let start = usize::try_from(off).unwrap_or(0);
            let n = usize::try_from(len).unwrap_or(0);
            if start.saturating_add(n) > raw.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Datenlauf überschreitet den Dekompressionspuffer",
                )
                .into());
            }
            fs.seek(SeekFrom::Start(*p))?;
            fs.read_exact(&mut raw[start..start + n])?;
            let mut b = off;
            let e = off + len;
            while b < e {
                let u = (b / cu_size) as usize;
                let unit_end = (b / cu_size + 1) * cu_size;
                let take = e.min(unit_end) - b;
                if let Some(slot) = real_per_unit.get_mut(u) {
                    *slot += take;
                }
                b += take;
            }
        }
        off += len;
    }

    let cap = usize::try_from(file_size).unwrap_or(0);
    let mut out = Vec::with_capacity(cap);
    // Ausgabe entlang der LOGISCHEN (entpackten) Groesse aufbauen. Die letzte
    // Einheit kann weniger als eine volle Einheitenlaenge tragen.
    let logical_units = file_size.div_ceil(cu_size) as usize;
    for u in 0..logical_units {
        let start = u as u64 * cu_size;
        let logical = cu_size.min(file_size - start);
        let logical_usize = usize::try_from(logical).unwrap_or(0);
        let real = real_per_unit.get(u).copied().unwrap_or(0);

        // Eine Einheit ist komprimiert abgelegt, wenn die Kompression mindestens
        // einen Cluster gespart hat, also weniger belegte Cluster als logische
        // vorliegen. Sonst liegt sie unkomprimiert (roh) vor. Die letzte,
        // teilweise gefuellte Einheit (z. B. ein einzelner Cluster) ist damit
        // korrekt als unkomprimiert erkannt.
        let logical_clusters = logical.div_ceil(cluster_size);
        let real_clusters = real / cluster_size;
        let s = usize::try_from(start).unwrap_or(0);

        if real == 0 {
            // Vollständig spärliche Einheit: reine Nullfolge.
            out.resize(out.len() + logical_usize, 0);
        } else if real_clusters >= logical_clusters {
            // Unkomprimiert: die logischen Bytes roh übernehmen.
            let e = s.saturating_add(logical_usize);
            if e > raw.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "unkomprimierte NTFS-Einheit ist unvollständig",
                )
                .into());
            }
            out.extend_from_slice(&raw[s..e]);
        } else {
            // Komprimierte Einheit: nur die belegten Bytes entpacken.
            let r = usize::try_from(real).unwrap_or(0);
            let e = (s + r).min(raw.len());
            let before = out.len();
            lznt1::decompress(&raw[s..e], &mut out)?;
            // Jede Einheit muss ihre logische Länge liefern; bei Abweichung
            // (defensiv gegen fehlerhafte Daten) angleichen.
            if out.len() - before != logical_usize {
                out.resize(before + logical_usize, 0);
            }
        }
    }
    out.truncate(cap);
    Ok(out)
}

/// Sammelt die Datenläufe eines über eine Attributliste verteilten
/// (`AttributeListNonResident`) ungenannten `$DATA`-Stroms ein.
///
/// Statt dem eingebauten Leser zu vertrauen, wird die `$ATTRIBUTE_LIST` selbst
/// durchlaufen: für jeden Eintrag vom Typ `$DATA` ohne Namen wird der zugehörige
/// MFT-Datensatz geladen und dessen nicht-residente Läufe (physischer Offset,
/// belegte Länge) angehängt. Die Einträge liegen nach aufsteigender VCN vor, die
/// Läufe ergeben also aneinandergereiht den Datenstrom in Byte-Reihenfolge.
/// Spärliche Läufe (Offset `None`) bleiben erhalten und werden vom Aufrufer mit
/// Nullen gefüllt.
fn collect_attribute_list_runs<R: Read + Seek>(
    ntfs: &Ntfs,
    fs: &mut R,
    file: &NtfsFile<'_>,
    stream: &str,
) -> Result<Vec<(Option<u64>, u64)>, NtfsVolumeError> {
    // Die $ATTRIBUTE_LIST unter den rohen Attributen des Basis-Datensatzes
    // suchen (sie wird nicht über die Liste selbst referenziert).
    let mut list: Option<NtfsAttributeList<'_, '_>> = None;
    for attr in file.attributes_raw() {
        let attr = attr?;
        if matches!(attr.ty(), Ok(NtfsAttributeType::AttributeList)) {
            list = Some(attr.structured_value::<_, NtfsAttributeList>(fs)?);
            break;
        }
    }
    let Some(list) = list else {
        return Ok(Vec::new());
    };

    let mut runs: Vec<(Option<u64>, u64)> = Vec::new();
    let mut entries = list.entries();
    while let Some(entry) = entries.next(fs) {
        let entry = entry?;
        if !matches!(entry.ty(), Ok(NtfsAttributeType::Data)) {
            continue;
        }
        // Nur der angefragte Datenstrom (leer = unbenannter Strom).
        let matches = if stream.is_empty() {
            entry.name_length() == 0
        } else {
            entry.name().to_string_lossy() == stream
        };
        if !matches {
            continue;
        }
        let entry_file = entry.to_file(ntfs, fs)?;
        let entry_attr = entry.to_attribute(&entry_file)?;
        if entry_attr.is_resident() {
            // Verbundene Fragmente sind stets nicht-resident; resident wäre der
            // ungeteilte Fall, den read_data nicht über diesen Pfad erreicht.
            continue;
        }
        if let NtfsAttributeValue::NonResident(nr) = entry_attr.value(fs)? {
            for run in nr.data_runs() {
                let run = run?;
                runs.push((
                    run.data_position().value().map(|p| p.get()),
                    run.allocated_size(),
                ));
            }
        }
    }
    Ok(runs)
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
    stream_size: u64,
) -> Result<FileMeta, NtfsVolumeError> {
    let info: NtfsStandardInformation = file.info()?;
    let record_offset = file
        .position()
        .value()
        .map(|p| part_offset.saturating_add(p.get()));
    Ok(FileMeta {
        path: path.to_string(),
        mft_record: file.file_record_number(),
        size: stream_size,
        record_offset,
        created: info.creation_time().nt_timestamp(),
        modified: info.modification_time().nt_timestamp(),
        accessed: info.access_time().nt_timestamp(),
        mft_modified: info.mft_record_modification_time().nt_timestamp(),
        wof: None,
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

    #[test]
    fn datenlaeufe_werden_blockweise_und_sparse_korrekt_geschrieben() {
        let mut source = Cursor::new(vec![1u8, 2, 3, 4]);
        let runs = vec![(Some(0), 4), (None, 3)];
        let mut out = Vec::new();
        write_runs(&mut source, &runs, 7, &mut out).unwrap();
        assert_eq!(out, [1, 2, 3, 4, 0, 0, 0]);
    }

    #[test]
    fn gekuerzter_datenlauf_ist_ein_fehler() {
        let mut source = Cursor::new(vec![1u8, 2]);
        let mut out = Vec::new();
        let error = write_runs(&mut source, &[(Some(0), 4)], 4, &mut out).unwrap_err();
        assert!(matches!(error, NtfsVolumeError::Io(_)));
    }
}
