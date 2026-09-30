//! Dateibasierte Auswertung von Schattenkopien.
//!
//! Je Snapshot wird der Verzeichnisbaum durchlaufen und mit dem Live-Volume
//! verglichen. Eine Datei gilt nur dann als unverändert, wenn ihr Inhalt
//! nachweislich gleich ist: gleiche Datenläufe, und kein Block dieser Läufe
//! wurde seit dem Snapshot in einen Store kopiert (sonst werden die Bytes
//! dieses Blocks verglichen). Residente Inhalte werden direkt verglichen.
//! Alles andere landet im Differenz-Index des Snapshots: Dateien, die es nur
//! dort gibt, und Dateien mit abweichendem Inhalt. Auf diesem Index laufen
//! die dateibasierten Analyzer ein zweites Mal, sodass nur geänderte oder
//! gelöschte Dateien erneut ausgewertet werden.
//!
//! Verglichen wird der unbenannte Datenstrom; benannte Ströme nicht.

use std::collections::HashMap;
use std::io::{Cursor, Read, Seek, SeekFrom};

use rayon::prelude::*;
use stratum_core::ImageReader;
use stratum_ntfs::{DataStreamLayout, NtfsVolume, NtfsVolumeError, RecordInfo};
use stratum_vss::{Location, StoreReader, Volume};

use crate::fsindex::{FileEntry, FsIndex, Herkunft};
use crate::NtfsTarget;

/// Obergrenze für den vollständigen Inhaltsvergleich einer Datei, wenn die
/// Datenläufe verschieden sind oder der Strom komprimiert ist.
const MAX_VERGLEICH: u64 = 256 * 1024 * 1024;

/// Schattenkopien eines NTFS-Bereichs.
#[derive(Debug)]
pub struct Schatten<'a> {
    /// NTFS-Bereich, auf dem die Schattenkopien liegen.
    pub target: NtfsTarget,
    /// Eingelesene Schattenkopien.
    pub vss: Volume<'a>,
}

/// Lesequelle eines NTFS-Volumes: Live-Bereich im Image oder Snapshot.
pub enum VolumeReader<'c> {
    /// Bereich des Images.
    Live(Cursor<&'c [u8]>),
    /// Rekonstruierter Snapshot.
    Snapshot(StoreReader<'c, 'c>),
}

impl Read for VolumeReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Live(c) => c.read(buf),
            Self::Snapshot(s) => s.read(buf),
        }
    }
}

impl Seek for VolumeReader<'_> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        match self {
            Self::Live(c) => c.seek(pos),
            Self::Snapshot(s) => s.seek(pos),
        }
    }
}

/// Umrechnung von Offsets, die der NTFS-Parser liefert, in Image-Offsets.
/// Live-Volumes liefern bereits Image-Offsets. In Snapshots sind es Offsets
/// im Snapshot; sie werden über die Schattenkopie einer physischen Stelle
/// zugeordnet (oder keiner, wenn der Block laut Bitmap nicht belegt war).
#[derive(Clone, Copy)]
pub struct Abbildung<'c> {
    snapshot: Option<(&'c Volume<'c>, usize, u64)>,
}

impl Abbildung<'_> {
    /// Abbildung für ein Live-Volume.
    pub fn live() -> Self {
        Self { snapshot: None }
    }

    /// Image-Offset zu einem vom NTFS-Parser gelieferten Offset.
    pub fn image(&self, offset: u64) -> Option<u64> {
        let Some((vss, store, target)) = self.snapshot else {
            return Some(offset);
        };
        match vss.locate(store, offset).ok()?.0 {
            Location::Volume { offset, .. } => target.checked_add(offset),
            Location::Zero => None,
        }
    }

    /// `true` bei einem Snapshot.
    pub fn ist_snapshot(&self) -> bool {
        self.snapshot.is_some()
    }
}

/// Öffnet das Volume eines Index, live oder als Snapshot.
pub(crate) fn open<'c>(
    img: &'c ImageReader,
    schatten: &'c [Schatten<'c>],
    v: &FsIndex,
) -> Result<(NtfsVolume<VolumeReader<'c>>, Abbildung<'c>), NtfsVolumeError> {
    let t = v.target;
    match v.herkunft {
        Herkunft::Live => {
            let slice = image_slice(img, t)?;
            let vol =
                NtfsVolume::from_reader(VolumeReader::Live(Cursor::new(slice)), t.offset, t.size)?;
            Ok((vol, Abbildung::live()))
        }
        Herkunft::Snapshot { store, .. } => {
            let s = schatten
                .iter()
                .find(|s| s.target.offset == t.offset)
                .ok_or(NtfsVolumeError::OutOfImage {
                    offset: t.offset,
                    size: t.size,
                    image_size: img.len(),
                })?;
            let reader = s.vss.reader(store).map_err(|e| {
                NtfsVolumeError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
            })?;
            let size = reader.size();
            let vol = NtfsVolume::from_reader(VolumeReader::Snapshot(reader), 0, size)?;
            Ok((
                vol,
                Abbildung {
                    snapshot: Some((&s.vss, store, t.offset)),
                },
            ))
        }
    }
}

fn image_slice(img: &ImageReader, t: NtfsTarget) -> Result<&[u8], NtfsVolumeError> {
    let fehler = || NtfsVolumeError::OutOfImage {
        offset: t.offset,
        size: t.size,
        image_size: img.len(),
    };
    let start = usize::try_from(t.offset).map_err(|_| fehler())?;
    let end = start
        .checked_add(usize::try_from(t.size).map_err(|_| fehler())?)
        .filter(|&e| e <= img.as_slice().len())
        .ok_or_else(fehler)?;
    Ok(&img.as_slice()[start..end])
}

/// Stand einer Snapshot-Datei gegenüber dem Live-Volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Unter diesem Pfad gibt es live keine Datei.
    NurImSnapshot,
    /// Der Inhalt unterscheidet sich.
    InhaltAbweichend,
    /// Der Vergleich war nicht möglich (Grund in `hinweis`).
    NichtPruefbar,
}

impl Status {
    /// Bezeichnung im Report.
    pub fn name(self) -> &'static str {
        match self {
            Self::NurImSnapshot => "nur_im_snapshot",
            Self::InhaltAbweichend => "inhalt_abweichend",
            Self::NichtPruefbar => "nicht_pruefbar",
        }
    }
}

/// Eine Datei des Snapshots, die sich vom Live-Stand unterscheidet.
#[derive(Debug, Clone)]
pub struct Abweichung {
    /// Volume-Offset des NTFS-Bereichs.
    pub volume_offset: u64,
    /// Store-Index (0 = älteste Schattenkopie).
    pub store: usize,
    /// Eintrag im Snapshot.
    pub eintrag: FileEntry,
    /// Stand.
    pub status: Status,
    /// Metadaten im Snapshot.
    pub snapshot: Option<RecordInfo>,
    /// Metadaten der Live-Datei unter demselben Pfad.
    pub live: Option<RecordInfo>,
    /// Grund bei `NichtPruefbar`.
    pub hinweis: Option<String>,
}

/// Ergebnis für einen Snapshot.
pub struct SnapshotVergleich {
    /// Differenz-Index (nur abweichende Dateien) mit Herkunft Snapshot.
    pub index: FsIndex,
    /// Abweichende Dateien.
    pub abweichungen: Vec<Abweichung>,
    /// Dateien im Snapshot insgesamt.
    pub dateien: usize,
    /// Hinweise.
    pub warnungen: Vec<String>,
}

/// Vergleicht alle Snapshots eines Bereichs mit dem Live-Index, parallel je
/// Snapshot.
pub(crate) fn vergleichen(
    img: &ImageReader,
    schatten: &Schatten<'_>,
    live: &FsIndex,
) -> Vec<SnapshotVergleich> {
    let nach_pfad: HashMap<String, &FileEntry> = live
        .files
        .iter()
        .map(|e| (e.path.to_lowercase(), e))
        .collect();
    let stores: Vec<_> = schatten.vss.stores().into_iter().cloned().collect();
    stores
        .par_iter()
        .map(|info| {
            let herkunft = Herkunft::Snapshot {
                store: info.index,
                erstellt: info.creation_time,
            };
            match snapshot_vergleichen(img, schatten, &nach_pfad, info.index) {
                Ok((index, abweichungen, dateien, warnungen)) => SnapshotVergleich {
                    index: FsIndex { herkunft, ..index },
                    abweichungen,
                    dateien,
                    warnungen,
                },
                Err(e) => SnapshotVergleich {
                    index: FsIndex::leer(schatten.target, herkunft),
                    abweichungen: Vec::new(),
                    dateien: 0,
                    warnungen: vec![format!("VSS#{}: nicht lesbar: {e}", info.index + 1)],
                },
            }
        })
        .collect()
}

type Ergebnis = (FsIndex, Vec<Abweichung>, usize, Vec<String>);

fn snapshot_vergleichen(
    img: &ImageReader,
    schatten: &Schatten<'_>,
    nach_pfad: &HashMap<String, &FileEntry>,
    store: usize,
) -> Result<Ergebnis, NtfsVolumeError> {
    let t = schatten.target;
    let reader = schatten.vss.reader(store).map_err(|e| {
        NtfsVolumeError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    })?;
    let size = reader.size();
    let mut snap = NtfsVolume::from_reader(reader, 0, size)?;
    let index = FsIndex::from_volume(&mut snap, t, Herkunft::Live)?;
    let slice = image_slice(img, t)?;
    let mut lv = NtfsVolume::from_reader(Cursor::new(slice), t.offset, t.size)?;
    let mut abweichungen = Vec::new();
    let mut behalten = Vec::new();
    let warnungen: Vec<String> = index
        .warnings
        .iter()
        .map(|w| format!("VSS#{}: {w}", store + 1))
        .collect();
    for e in &index.files {
        let live_eintrag = nach_pfad.get(&e.path.to_lowercase()).copied();
        let (status, hinweis) = match live_eintrag {
            None => (Status::NurImSnapshot, None),
            Some(l) => {
                match inhalt_gleich(&schatten.vss, store, t, slice, &mut snap, e, &mut lv, l) {
                    Ok(true) => continue,
                    Ok(false) => (Status::InhaltAbweichend, None),
                    Err(h) => (Status::NichtPruefbar, Some(h)),
                }
            }
        };
        // Metadaten nur für abweichende Dateien lesen.
        let snap_info = snap.record_info(e.mft_record, Some(e.parent_record)).ok();
        let live_info =
            live_eintrag.and_then(|l| lv.record_info(l.mft_record, Some(l.parent_record)).ok());
        behalten.push(e.clone());
        abweichungen.push(Abweichung {
            volume_offset: t.offset,
            store,
            eintrag: e.clone(),
            status,
            snapshot: snap_info,
            live: live_info,
            hinweis,
        });
    }
    let dateien = index.files.len();
    let diff = FsIndex {
        files: behalten,
        ..index
    };
    Ok((diff, abweichungen, dateien, warnungen))
}

/// `Ok(true)`, wenn der unbenannte Datenstrom nachweislich gleich ist.
#[allow(clippy::too_many_arguments)]
fn inhalt_gleich<R: Read + Seek, L: Read + Seek>(
    vss: &Volume<'_>,
    store: usize,
    t: NtfsTarget,
    live_slice: &[u8],
    snap: &mut NtfsVolume<R>,
    e: &FileEntry,
    lv: &mut NtfsVolume<L>,
    l: &FileEntry,
) -> Result<bool, String> {
    let s = snap.data_stream_layout_by_record(e.mft_record, "");
    let v = lv.data_stream_layout_by_record(l.mft_record, "");
    match (s, v) {
        (Ok(Some(s)), Ok(Some(v))) => {
            if s.logical_size != v.logical_size || s.valid_size != v.valid_size {
                return Ok(false);
            }
            if let (Some(a), Some(b)) = (&s.resident, &v.resident) {
                return Ok(a == b);
            }
            if gleiche_laeufe(&s, &v, t.offset) {
                return laeufe_unveraendert(vss, store, live_slice, &s);
            }
            voll_vergleichen(snap, e, lv, l, s.logical_size)
        }
        (Ok(None), Ok(None)) => Ok(true),
        (Ok(_), Ok(_)) => Ok(false),
        // Komprimierte Ströme haben keine direkte Ablage: Inhalt lesen.
        (Err(NtfsVolumeError::CompressedDataStream { .. }), _)
        | (_, Err(NtfsVolumeError::CompressedDataStream { .. })) => {
            let groesse = lv
                .record_info(l.mft_record, None)
                .ok()
                .and_then(|i| i.data_size)
                .unwrap_or(0);
            voll_vergleichen(snap, e, lv, l, groesse)
        }
        (Err(err), _) | (_, Err(err)) => Err(format!("Ablage nicht lesbar: {err}")),
    }
}

/// Gleiche Läufe: Snapshot-Offsets entsprechen Live-Offsets ohne den
/// Bereichs-Offset.
fn gleiche_laeufe(s: &DataStreamLayout, v: &DataStreamLayout, bereich: u64) -> bool {
    s.runs.len() == v.runs.len()
        && s.runs.iter().zip(&v.runs).all(|(a, b)| {
            a.logical_offset == b.logical_offset
                && a.length == b.length
                && a.image_offset == b.image_offset.and_then(|o| o.checked_sub(bereich))
        })
}

/// Prüft die Läufe blockweise: Stammen die Snapshot-Bytes aus dem aktuellen
/// Volume an derselben Stelle, sind sie gleich. Sonst werden die Bytes
/// verglichen.
fn laeufe_unveraendert(
    vss: &Volume<'_>,
    store: usize,
    live: &[u8],
    s: &DataStreamLayout,
) -> Result<bool, String> {
    let mut puffer = Vec::new();
    for run in &s.runs {
        let Some(start) = run.image_offset else {
            continue;
        };
        let ende = start + run.length;
        let mut pos = start;
        while pos < ende {
            let (loc, len) = vss.locate(store, pos).map_err(|e| e.to_string())?;
            let n = len.min(ende - pos);
            let gleich_ohne_lesen =
                matches!(loc, Location::Volume { offset, from_store: false } if offset == pos);
            if !gleich_ohne_lesen {
                let a = usize::try_from(pos).map_err(|e| e.to_string())?;
                let live_teil = live
                    .get(a..a + n as usize)
                    .ok_or("Lauf außerhalb des Volumes")?;
                puffer.resize(n as usize, 0);
                vss.read_at(store, pos, &mut puffer)
                    .map_err(|e| e.to_string())?;
                if puffer != live_teil {
                    return Ok(false);
                }
            }
            pos += n;
        }
    }
    Ok(true)
}

fn voll_vergleichen<R: Read + Seek, L: Read + Seek>(
    snap: &mut NtfsVolume<R>,
    e: &FileEntry,
    lv: &mut NtfsVolume<L>,
    l: &FileEntry,
    groesse: u64,
) -> Result<bool, String> {
    if groesse > MAX_VERGLEICH {
        return Err(format!(
            "Datenläufe verschieden, Datei mit {groesse} Byte zu groß für den Vollvergleich"
        ));
    }
    let a = snap
        .read_file_by_record(e.mft_record, &e.path)
        .map_err(|x| x.to_string())?;
    let b = lv
        .read_file_by_record(l.mft_record, &l.path)
        .map_err(|x| x.to_string())?;
    Ok(a.map(|f| f.data) == b.map(|f| f.data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use stratum_ntfs::DataStreamRun;

    fn layout(runs: &[(u64, Option<u64>, u64)]) -> DataStreamLayout {
        DataStreamLayout {
            logical_size: runs.iter().map(|r| r.2).sum(),
            valid_size: runs.iter().map(|r| r.2).sum(),
            allocated_size: 0,
            runs: runs
                .iter()
                .map(|&(logical_offset, image_offset, length)| DataStreamRun {
                    logical_offset,
                    image_offset,
                    length,
                })
                .collect(),
            resident: None,
            resident_image_offset: None,
        }
    }

    #[test]
    fn laeufe_ohne_bereichsoffset_vergleichen() {
        // Snapshot liefert Volume-Offsets, live Image-Offsets (+ Bereich 1 MiB).
        let s = layout(&[(0, Some(0x4000), 0x1000), (0x1000, None, 0x1000)]);
        let v = layout(&[(0, Some(0x104000), 0x1000), (0x1000, None, 0x1000)]);
        assert!(gleiche_laeufe(&s, &v, 0x100000));
        assert!(!gleiche_laeufe(&s, &v, 0));
        let anders = layout(&[(0, Some(0x108000), 0x1000), (0x1000, None, 0x1000)]);
        assert!(!gleiche_laeufe(&s, &anders, 0x100000));
        assert!(!gleiche_laeufe(&s, &layout(&[]), 0x100000));
    }

    #[test]
    fn bezeichnungen() {
        assert_eq!(Status::NurImSnapshot.name(), "nur_im_snapshot");
        assert_eq!(
            Herkunft::Snapshot {
                store: 0,
                erstellt: 0
            }
            .label(),
            "VSS#1"
        );
        assert_eq!(Herkunft::Live.label(), "live");
        assert_eq!(Abbildung::live().image(42), Some(42));
        assert!(!Abbildung::live().ist_snapshot());
    }
}
