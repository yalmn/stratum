//! Nur lesender Parser für Volume Shadow Copies (VSS) auf NTFS-Volumes.
//!
//! Formatgrundlage ist die Beschreibung von libyal/libvshadow („Volume Shadow
//! Snapshot (VSS) format“). Wo die Beschreibung selbst als unvollständig
//! gekennzeichnet ist (aufeinanderfolgende Blockdeskriptoren, Overlays,
//! Forwarder), folgt die Umsetzung dem Verhalten von libvshadow und ist
//! blockweise gegen libvshadow geprüft.
//!
//! Ein Snapshot wird gelesen, indem die Stores vom jüngsten bis zum
//! gewünschten über das aktuelle Volume gelegt werden: Blöcke, die sich nach
//! dem Snapshot geändert haben, liegen als alte Kopie in einem Store, alle
//! anderen werden aus dem aktuellen Volume gelesen. [`Volume::locate`] nennt
//! für jede Stelle des Snapshots, woher die Bytes stammen; damit lässt sich
//! jeder Fund in einer Schattenkopie einer physischen Stelle zuordnen.
//!
//! Der Parser arbeitet auf dem Byte-Slice des Volumes, prüft alle Längen und
//! schützt Blockketten gegen Schleifen. Beschädigte Strukturen führen zu
//! Fehlern oder Hinweisen, nie zu einer Panik.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod blocks;
mod error;
mod reader;

use std::collections::HashSet;

pub use error::VssError;
pub use reader::StoreReader;

use blocks::{BlockList, Descriptor, FLAG_FORWARDER};

/// Blockgröße aller VSS-Strukturen und Datenblöcke.
pub const BLOCK_SIZE: u64 = 0x4000;
/// Lage des VSS-Kopfs im Volume.
pub const HEADER_OFFSET: u64 = 0x1e00;
/// Kennung von VSS-Strukturen (`3808876b-c176-4e48-b7ae-04046e6cc752`).
const VSS_ID: [u8; 16] = [
    0x6b, 0x87, 0x08, 0x38, 0x76, 0xc1, 0x48, 0x4e, 0xb7, 0xae, 0x04, 0x04, 0x6e, 0x6c, 0xc7, 0x52,
];
/// Kopf eines Katalog- oder Store-Blocks.
const BLOCK_HEADER: usize = 128;
/// Obergrenze für Blöcke einer Kette (Katalog, Blockliste, Bitmap).
const MAX_CHAIN: usize = 1 << 20;
/// Obergrenze für Stores; Windows hält höchstens 512.
const MAX_STORES: usize = 512;

const RECORD_CATALOG: u32 = 2;
const RECORD_BLOCK_LIST: u32 = 3;
const RECORD_STORE_HEADER: u32 = 4;
const RECORD_BITMAP: u32 = 6;

pub(crate) fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

pub(crate) fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

/// GUID in der üblichen Schreibweise (erste drei Felder little-endian).
pub fn guid(b: &[u8; 16]) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{}",
        u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        u16::from_le_bytes([b[4], b[5]]),
        u16::from_le_bytes([b[6], b[7]]),
        b[8],
        b[9],
        b[10..]
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect::<String>()
    )
}

/// Angaben zu einem Store (einer Schattenkopie).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreInfo {
    /// Position nach Erstellungszeit, 0 ist die älteste.
    pub index: usize,
    /// Store-Kennung (Teil des Dateinamens in `System Volume Information`).
    pub id: [u8; 16],
    /// Größe des Volumes zum Zeitpunkt des Snapshots.
    pub volume_size: u64,
    /// Erstellungszeit (FILETIME, UTC).
    pub creation_time: u64,
    /// Laufende Nummer laut Katalog.
    pub sequence: u64,
    /// Kennung der Schattenkopie aus dem Store-Kopf.
    pub copy_id: Option<[u8; 16]>,
    /// Kennung des Schattenkopie-Satzes aus dem Store-Kopf.
    pub copy_set_id: Option<[u8; 16]>,
    /// Attribut-Flags (`_VSS_VOLUME_SNAPSHOT_ATTRIBUTES`).
    pub attribute_flags: Option<u32>,
    /// Anzahl der Blockdeskriptoren nach dem Einlesen der Blockliste.
    pub block_descriptors: usize,
}

/// Woher die Bytes einer Stelle im Snapshot stammen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Location {
    /// Aus dem Volume an diesem Offset (aktueller Inhalt oder Store-Kopie).
    Volume {
        /// Offset im Volume.
        offset: u64,
        /// `true`, wenn der Block aus einem Store stammt (alte Kopie).
        from_store: bool,
    },
    /// Nicht belegter Block, wird mit Nullen gefüllt (wie libvshadow).
    Zero,
}

/// Ein Store mit seinen eingelesenen Strukturen.
#[derive(Debug)]
struct Store {
    info: StoreInfo,
    has_data: bool,
    blocks: BlockList,
    /// Aktuelle Bitmap: gesetztes Bit = Block vom Store nicht belegt.
    bitmap: Vec<u8>,
    /// Vorherige Bitmap, falls vorhanden.
    previous: Option<Vec<u8>>,
}

/// Rohangaben eines Stores aus dem Katalog.
#[derive(Debug, Default, Clone)]
struct CatalogStore {
    id: [u8; 16],
    volume_size: u64,
    sequence: u64,
    creation_time: u64,
    block_list: u64,
    header: u64,
    bitmap: u64,
    previous_bitmap: u64,
    has_data: bool,
}

/// Ein Volume mit Schattenkopien.
#[derive(Debug)]
pub struct Volume<'a> {
    data: &'a [u8],
    version: u32,
    stores: Vec<Store>,
    warnings: Vec<String>,
}

impl<'a> Volume<'a> {
    /// Liest VSS-Kopf, Katalog und alle Stores. `Ok(None)`, wenn das Volume
    /// keinen VSS-Kopf oder keinen Katalog hat (keine Schattenkopien).
    pub fn open(data: &'a [u8]) -> Result<Option<Self>, VssError> {
        let at = HEADER_OFFSET as usize;
        let Some(head) = data.get(at..at + 128) else {
            return Ok(None);
        };
        if head[..16] != VSS_ID || u32_at(head, 20) != Some(1) {
            return Ok(None);
        }
        let version = u32_at(head, 16).unwrap_or(0);
        let catalog = u64_at(head, 48).unwrap_or(0);
        if catalog == 0 {
            return Ok(None);
        }
        let mut warnings = Vec::new();
        if !(1..=2).contains(&version) {
            warnings.push(format!("unbekannte VSS-Version {version}"));
        }
        let mut entries = read_catalog(data, catalog)?;
        // Nach Erstellungszeit ordnen, der nächste Store ist der jüngere.
        entries.sort_by_key(|e| e.creation_time);
        entries.truncate(MAX_STORES);
        let mut stores = Vec::with_capacity(entries.len());
        for (index, e) in entries.into_iter().enumerate() {
            stores.push(read_store(data, index, e, &mut warnings)?);
        }
        Ok(Some(Self {
            data,
            version,
            stores,
            warnings,
        }))
    }

    /// VSS-Version aus dem Kopf (1 Vista/7, 2 ab Windows 8).
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Angaben zu allen Stores, älteste zuerst.
    pub fn stores(&self) -> Vec<&StoreInfo> {
        self.stores.iter().map(|s| &s.info).collect()
    }

    /// Anzahl der Stores.
    pub fn store_count(&self) -> usize {
        self.stores.len()
    }

    /// Hinweise beim Einlesen.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Herkunft der Bytes ab `offset` im Snapshot `store` und die Länge, für
    /// die sie gilt (nie über eine Blockgrenze hinaus).
    pub fn locate(&self, store: usize, offset: u64) -> Result<(Location, u64), VssError> {
        let active = self.stores.get(store).ok_or(VssError::NoStore(store))?;
        if !active.has_data {
            return Err(VssError::NoStoreData(store));
        }
        if offset >= active.info.volume_size {
            return Err(VssError::OutOfRange(offset));
        }
        let mut s = store;
        let mut off = offset;
        let mut len = BLOCK_SIZE - offset % BLOCK_SIZE;
        // Jede Runde wechselt zu einem jüngeren Store; mehr Runden als Stores
        // gibt es nicht.
        for _ in 0..=self.stores.len() {
            let st = &self.stores[s];
            let next = (s + 1 < self.stores.len()).then_some(s + 1);
            let hit = st.blocks.range_at(off, s == store);
            len = len.min(hit.size).max(1);
            match hit.descriptor {
                Some(d) => {
                    if d.flags & FLAG_FORWARDER != 0 {
                        if let Some(n) = next {
                            s = n;
                            off = hit.offset;
                            continue;
                        }
                    }
                    // Ein Forwarder ohne jüngeren Store verweist auf das
                    // aktuelle Volume, alle anderen Deskriptoren auf eine
                    // Store-Kopie.
                    return Ok((
                        Location::Volume {
                            offset: hit.offset,
                            from_store: d.flags & FLAG_FORWARDER == 0,
                        },
                        len,
                    ));
                }
                None => {
                    if let Some(n) = next {
                        s = n;
                        continue;
                    }
                    if s == store && !st.blocks.in_reverse(off) && st.unused(off) {
                        return Ok((Location::Zero, len));
                    }
                    return Ok((
                        Location::Volume {
                            offset: off,
                            from_store: false,
                        },
                        len,
                    ));
                }
            }
        }
        Err(VssError::Loop(offset))
    }

    /// Liest `buf.len()` Bytes ab `offset` aus dem Snapshot `store`.
    pub fn read_at(&self, store: usize, offset: u64, buf: &mut [u8]) -> Result<(), VssError> {
        let mut done = 0usize;
        while done < buf.len() {
            let pos = offset + done as u64;
            let (loc, len) = self.locate(store, pos)?;
            let n = (len as usize).min(buf.len() - done);
            let ziel = &mut buf[done..done + n];
            match loc {
                Location::Zero => ziel.fill(0),
                Location::Volume { offset, .. } => {
                    let start =
                        usize::try_from(offset).map_err(|_| VssError::OutOfRange(offset))?;
                    let src = self
                        .data
                        .get(start..start + n)
                        .ok_or(VssError::Truncated(offset))?;
                    ziel.copy_from_slice(src);
                }
            }
            done += n;
        }
        Ok(())
    }

    /// Lesbare, suchbare Sicht auf einen Snapshot.
    pub fn reader(&self, store: usize) -> Result<StoreReader<'_, 'a>, VssError> {
        let st = self.stores.get(store).ok_or(VssError::NoStore(store))?;
        if !st.has_data {
            return Err(VssError::NoStoreData(store));
        }
        Ok(StoreReader::new(self, store, st.info.volume_size))
    }
}

impl Store {
    /// Block laut aktueller (und ggf. vorheriger) Bitmap nicht belegt.
    fn unused(&self, offset: u64) -> bool {
        let bit = |map: &[u8]| {
            let n = (offset / BLOCK_SIZE) as usize;
            map.get(n / 8).is_some_and(|b| b & (1 << (n % 8)) != 0)
        };
        bit(&self.bitmap) && self.previous.as_deref().is_none_or(bit)
    }
}

/// Liest einen 16-KiB-Block mit Kopf und prüft Kennung und Satztyp.
fn block(data: &[u8], offset: u64, record: u32) -> Result<&[u8], VssError> {
    let start = usize::try_from(offset).map_err(|_| VssError::OutOfRange(offset))?;
    let b = data
        .get(start..start + BLOCK_SIZE as usize)
        .ok_or(VssError::Truncated(offset))?;
    if b[..8] != VSS_ID[..8] {
        return Err(VssError::BadBlock {
            offset,
            reason: "Kennung fehlt",
        });
    }
    if u32_at(b, 20) != Some(record) {
        return Err(VssError::BadBlock {
            offset,
            reason: "unerwarteter Satztyp",
        });
    }
    Ok(b)
}

/// Folgt einer Blockkette über das Feld „nächster Block“ (Offset 40).
fn chain(
    data: &[u8],
    first: u64,
    record: u32,
    mut each: impl FnMut(&[u8]) -> Result<(), VssError>,
) -> Result<(), VssError> {
    let mut seen = HashSet::new();
    let mut off = first;
    while off != 0 {
        if !seen.insert(off) || seen.len() > MAX_CHAIN {
            return Err(VssError::Loop(off));
        }
        let b = block(data, off, record)?;
        each(b)?;
        off = u64_at(b, 40).unwrap_or(0);
    }
    Ok(())
}

fn read_catalog(data: &[u8], first: u64) -> Result<Vec<CatalogStore>, VssError> {
    let mut stores: Vec<CatalogStore> = Vec::new();
    chain(data, first, RECORD_CATALOG, |b| {
        for e in b[BLOCK_HEADER..].chunks_exact(128) {
            let id: [u8; 16] = e[16..32].try_into().unwrap_or_default();
            match u64_at(e, 0) {
                Some(2) => {
                    if stores.iter().any(|s| s.id == id) {
                        continue;
                    }
                    stores.push(CatalogStore {
                        id,
                        volume_size: u64_at(e, 8).unwrap_or(0),
                        sequence: u64_at(e, 32).unwrap_or(0),
                        creation_time: u64_at(e, 48).unwrap_or(0),
                        ..Default::default()
                    });
                }
                Some(3) => {
                    // Typ 3 gehört zum Typ-2-Eintrag mit derselben Kennung.
                    if let Some(s) = stores.iter_mut().find(|s| s.id == id) {
                        s.block_list = u64_at(e, 8).unwrap_or(0);
                        s.header = u64_at(e, 32).unwrap_or(0);
                        s.bitmap = u64_at(e, 48).unwrap_or(0);
                        s.previous_bitmap = u64_at(e, 72).unwrap_or(0);
                        s.has_data = true;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    })?;
    Ok(stores)
}

/// Bitmap-Daten einer Kette hintereinander (ohne Blockköpfe).
fn read_bitmap(data: &[u8], first: u64) -> Result<Vec<u8>, VssError> {
    let mut out = Vec::new();
    chain(data, first, RECORD_BITMAP, |b| {
        out.extend_from_slice(&b[BLOCK_HEADER..]);
        Ok(())
    })?;
    Ok(out)
}

fn read_store(
    data: &[u8],
    index: usize,
    e: CatalogStore,
    warnings: &mut Vec<String>,
) -> Result<Store, VssError> {
    let mut info = StoreInfo {
        index,
        id: e.id,
        volume_size: e.volume_size,
        creation_time: e.creation_time,
        sequence: e.sequence,
        copy_id: None,
        copy_set_id: None,
        attribute_flags: None,
        block_descriptors: 0,
    };
    let mut blocks = BlockList::default();
    let mut bitmap = Vec::new();
    let mut previous = None;
    if e.has_data {
        match block(data, e.header, RECORD_STORE_HEADER) {
            Ok(h) => {
                let i = &h[BLOCK_HEADER..];
                info.copy_id = i.get(16..32).and_then(|b| b.try_into().ok());
                info.copy_set_id = i.get(32..48).and_then(|b| b.try_into().ok());
                info.attribute_flags = u32_at(i, 56);
            }
            Err(err) => warnings.push(format!("Store {index}: Kopf nicht lesbar: {err}")),
        }
        chain(data, e.block_list, RECORD_BLOCK_LIST, |b| {
            for entry in b[BLOCK_HEADER..].chunks_exact(32) {
                if let Some(d) = Descriptor::parse(entry) {
                    blocks.insert(d, warnings, index);
                }
            }
            Ok(())
        })?;
        bitmap = read_bitmap(data, e.bitmap)?;
        if e.previous_bitmap != 0 {
            previous = Some(read_bitmap(data, e.previous_bitmap)?);
        }
        info.block_descriptors = blocks.len();
    } else {
        warnings.push(format!(
            "Store {index}: keine Daten im Volume (kein Katalogeintrag Typ 3)"
        ));
    }
    Ok(Store {
        info,
        has_data: e.has_data,
        blocks,
        bitmap,
        previous,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const B: usize = BLOCK_SIZE as usize;

    fn kopf(buf: &mut [u8], at: usize, record: u32, next: u64) {
        buf[at..at + 16].copy_from_slice(&VSS_ID);
        buf[at + 16..at + 20].copy_from_slice(&1u32.to_le_bytes());
        buf[at + 20..at + 24].copy_from_slice(&record.to_le_bytes());
        buf[at + 32..at + 40].copy_from_slice(&(at as u64).to_le_bytes());
        buf[at + 40..at + 48].copy_from_slice(&next.to_le_bytes());
    }

    fn put(buf: &mut [u8], at: usize, v: u64) {
        buf[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }

    fn deskriptor(buf: &mut [u8], at: usize, orig: usize, rel: usize, off: usize, flags: u32) {
        put(buf, at, (orig * B) as u64);
        put(buf, at + 8, (rel * B) as u64);
        put(buf, at + 16, (off * B) as u64);
        buf[at + 24..at + 28].copy_from_slice(&flags.to_le_bytes());
    }

    /// 32 Blöcke. Aktuelles Volume: Block n voller Bytes n. Store A (alt)
    /// und B (jung) mit Kopf, Blockliste und Bitmap; Datenblöcke ab 10.
    fn volume() -> Vec<u8> {
        let mut v = vec![0u8; 32 * B];
        for n in 16..32 {
            v[n * B..(n + 1) * B].fill(n as u8);
        }
        v[HEADER_OFFSET as usize..HEADER_OFFSET as usize + 16].copy_from_slice(&VSS_ID);
        v[0x1e10..0x1e14].copy_from_slice(&1u32.to_le_bytes());
        v[0x1e14..0x1e18].copy_from_slice(&1u32.to_le_bytes());
        put(&mut v, 0x1e30, B as u64);
        // Katalog in Block 1: B vor A, um die Sortierung zu prüfen.
        kopf(&mut v, B, RECORD_CATALOG, 0);
        for (i, (id, zeit, h, l, bm)) in [(0xbb, 200u64, 5, 6, 7), (0xaa, 100, 2, 3, 4)]
            .into_iter()
            .enumerate()
        {
            let e2 = B + 128 + i * 256;
            put(&mut v, e2, 2);
            put(&mut v, e2 + 8, (32 * B) as u64);
            v[e2 + 16..e2 + 32].fill(id);
            put(&mut v, e2 + 48, zeit);
            let e3 = e2 + 128;
            put(&mut v, e3, 3);
            put(&mut v, e3 + 8, (l * B) as u64);
            v[e3 + 16..e3 + 32].fill(id);
            put(&mut v, e3 + 32, (h * B) as u64);
            put(&mut v, e3 + 48, (bm * B) as u64);
        }
        for (h, l, bm) in [(2, 3, 4), (5, 6, 7)] {
            kopf(&mut v, h * B, RECORD_STORE_HEADER, 0);
            kopf(&mut v, l * B, RECORD_BLOCK_LIST, 0);
            kopf(&mut v, bm * B, RECORD_BITMAP, 0);
        }
        // Store A: Block 20 -> Daten 10, Block 24 weitergeleitet auf 25.
        deskriptor(&mut v, 3 * B + 128, 20, 0, 10, 0);
        deskriptor(&mut v, 3 * B + 160, 24, 25, 0, blocks::FLAG_FORWARDER);
        // Store B: Block 20 -> 11, Block 21 -> 12, Block 25 -> 13.
        deskriptor(&mut v, 6 * B + 128, 20, 0, 11, 0);
        deskriptor(&mut v, 6 * B + 160, 21, 0, 12, 0);
        deskriptor(&mut v, 6 * B + 192, 25, 0, 13, 0);
        // Bitmap von B: Block 23 nicht belegt.
        v[7 * B + 128 + 2] = 1 << 7;
        for (n, wert) in [(10, 0xa0u8), (11, 0xb0), (12, 0xb1), (13, 0xb5)] {
            v[n * B..(n + 1) * B].fill(wert);
        }
        v
    }

    fn block_von(vol: &Volume<'_>, store: usize, n: usize) -> u8 {
        let mut b = vec![0u8; B];
        vol.read_at(store, (n * B) as u64, &mut b).unwrap();
        assert!(b.iter().all(|x| *x == b[0]), "Block {n} nicht einheitlich");
        b[0]
    }

    #[test]
    fn zwei_stores_verkettet() {
        let data = volume();
        let vol = Volume::open(&data).unwrap().unwrap();
        assert!(vol.warnings().is_empty(), "{:?}", vol.warnings());
        let s = vol.stores();
        assert_eq!((s[0].id[0], s[1].id[0]), (0xaa, 0xbb));
        assert_eq!((s[0].block_descriptors, s[1].block_descriptors), (2, 3));
        // Jüngster Snapshot (B).
        assert_eq!(block_von(&vol, 1, 20), 0xb0);
        assert_eq!(block_von(&vol, 1, 21), 0xb1);
        assert_eq!(block_von(&vol, 1, 22), 22);
        assert_eq!(block_von(&vol, 1, 23), 0, "laut Bitmap nicht belegt");
        // Älterer Snapshot (A): eigene Kopie, sonst über B.
        assert_eq!(block_von(&vol, 0, 20), 0xa0);
        assert_eq!(block_von(&vol, 0, 21), 0xb1, "aus dem jüngeren Store");
        assert_eq!(block_von(&vol, 0, 22), 22);
        assert_eq!(block_von(&vol, 0, 23), 23, "Bitmap gilt nur im jüngsten");
        assert_eq!(block_von(&vol, 0, 24), 0xb5, "Forwarder über B");
        assert_eq!(
            vol.locate(0, (21 * B) as u64 + 7).unwrap(),
            (
                Location::Volume {
                    offset: (12 * B) as u64 + 7,
                    from_store: true
                },
                (B - 7) as u64
            )
        );
        assert_eq!(
            vol.locate(1, (22 * B) as u64).unwrap().0,
            Location::Volume {
                offset: (22 * B) as u64,
                from_store: false
            }
        );
        // Lesen über eine Blockgrenze hinweg.
        let mut b = vec![0u8; 20];
        vol.read_at(0, (21 * B) as u64 - 10, &mut b).unwrap();
        assert_eq!(&b[..10], &[0xa0; 10]);
        assert_eq!(&b[10..], &[0xb1; 10]);
    }

    #[test]
    fn ohne_vss_oder_kaputt() {
        assert!(Volume::open(&[0u8; 100]).unwrap().is_none());
        assert!(Volume::open(&vec![0u8; 8 * B]).unwrap().is_none());
        let data = volume();
        // Verkürzt: Katalog fehlt.
        assert!(Volume::open(&data[..B + 100]).is_err());
        // Blockliste verweist auf sich selbst.
        let mut schleife = data.clone();
        put(&mut schleife, 3 * B + 40, (3 * B) as u64);
        assert_eq!(
            Volume::open(&schleife).unwrap_err(),
            VssError::Loop((3 * B) as u64)
        );
        // Außerhalb des Snapshots und unbekannter Store.
        let vol = Volume::open(&data).unwrap().unwrap();
        assert!(vol.read_at(0, (32 * B) as u64, &mut [0u8; 1]).is_err());
        assert_eq!(vol.locate(9, 0).unwrap_err(), VssError::NoStore(9));
        // Zufällig verfälschte Bytes: nur Fehler, keine Panik.
        for i in (0..data.len()).step_by(61) {
            let mut k = data.clone();
            k[i] ^= 0xff;
            if let Ok(Some(v)) = Volume::open(&k) {
                for s in 0..v.store_count() {
                    let _ = v.read_at(s, 0, &mut vec![0u8; 3 * B]);
                }
            }
        }
    }
}
