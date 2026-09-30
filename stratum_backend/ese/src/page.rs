//! Seiten, Seiten-Tags und Knoten.

use crate::{u16_at, u32_at, EseError};

/// Kopf kleiner Seiten; große Seiten (16 und 32 KiB) haben 40 Byte mehr.
const HEADER_SMALL: usize = 40;
const HEADER_LARGE: usize = 80;

/// Seiten-Flags (Auswahl).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PageFlags(pub u32);

impl PageFlags {
    /// Wurzel eines B+-Baums.
    pub const ROOT: u32 = 0x01;
    /// Blattseite.
    pub const LEAF: u32 = 0x02;
    /// Leere Seite.
    pub const EMPTY: u32 = 0x08;
    /// Seite eines Speicherbaums.
    pub const SPACE_TREE: u32 = 0x20;
    /// Indexseite.
    pub const INDEX: u32 = 0x40;
    /// Long-Value-Seite.
    pub const LONG_VALUE: u32 = 0x80;
    /// Neues Datensatzformat.
    pub const NEW_RECORD_FORMAT: u32 = 0x2000;

    /// Prüft ein Flag.
    pub fn contains(self, flag: u32) -> bool {
        self.0 & flag != 0
    }
}

/// Eine gelesene Seite.
#[derive(Debug, Clone)]
pub struct Page<'a> {
    /// Seitennummer.
    pub number: u32,
    /// Offset der Seite in der Datei.
    pub file_offset: u64,
    /// Flags.
    pub flags: PageFlags,
    /// Vorherige Seite auf derselben Ebene.
    pub previous: u32,
    /// Nächste Seite auf derselben Ebene.
    pub next: u32,
    /// Objekt-ID des Baums (Father Data Page).
    pub fdp_object: u32,
    buf: &'a [u8],
    data_start: usize,
    small: bool,
    tag_count: usize,
    reserved: usize,
}

/// Ein Knoten (logischer Eintrag) einer Seite.
#[derive(Debug, Clone)]
pub struct Node<'a> {
    /// Seite des Knotens.
    pub page: u32,
    /// Offset der Knotendaten in der Datei (nach dem Schlüssel).
    pub file_offset: u64,
    /// Tag-Flags (0x02 gelöscht, 0x04 gemeinsamer Schlüsselanfang).
    pub flags: u16,
    /// Vollständiger Schlüssel.
    pub key: Vec<u8>,
    /// Daten nach dem Schlüssel.
    pub data: &'a [u8],
    /// Datensätze dieser Seite nutzen das neue Format.
    pub new_record_format: bool,
}

impl Node<'_> {
    /// Der Knoten ist als gelöscht markiert, aber noch nicht bereinigt.
    pub fn is_deleted(&self) -> bool {
        self.flags & 0x02 != 0
    }
}

impl<'a> Page<'a> {
    pub(crate) fn parse(
        number: u32,
        file_offset: u64,
        buf: &'a [u8],
        small: bool,
    ) -> Result<Self, EseError> {
        let data_start = if small { HEADER_SMALL } else { HEADER_LARGE };
        let bad = |reason| EseError::BadPage {
            page: number,
            reason,
        };
        if buf.len() < data_start + 4 {
            return Err(bad("zu klein"));
        }
        let flags = PageFlags(u32_at(buf, 36).ok_or(bad("Kopf"))?);
        // Ab Revision 0x122 stehen in den oberen 4 Bit reservierte Tags.
        let state = u16_at(buf, 34).ok_or(bad("Kopf"))?;
        let tag_count = usize::from(state & 0x0fff);
        let reserved = usize::from(state >> 12).max(1);
        if tag_count * 4 > buf.len() - data_start {
            return Err(bad("zu viele Seiten-Tags"));
        }
        Ok(Self {
            number,
            file_offset,
            flags,
            previous: u32_at(buf, 16).unwrap_or(0),
            next: u32_at(buf, 20).unwrap_or(0),
            fdp_object: u32_at(buf, 24).unwrap_or(0),
            buf,
            data_start,
            small,
            tag_count,
            reserved,
        })
    }

    /// Daten eines Tags: Offset relativ zum Seitenkopf, Größe und bei kleinen
    /// Seiten die Tag-Flags.
    fn tag(&self, index: usize) -> Option<(&'a [u8], usize, u16)> {
        let at = self.buf.len().checked_sub((index + 1) * 4)?;
        let size_raw = u16_at(self.buf, at)?;
        let off_raw = u16_at(self.buf, at + 2)?;
        let mask = if self.small { 0x1fff } else { 0x7fff };
        let (size, off) = (usize::from(size_raw & mask), usize::from(off_raw & mask));
        let start = self.data_start + off;
        let data = self.buf.get(start..start.checked_add(size)?)?;
        let flags = if self.small {
            off_raw >> 13
        } else {
            // Große Seiten: Flags in den oberen 3 Bit des ersten Worts.
            data.get(1).map_or(0, |b| u16::from(b >> 5))
        };
        Some((data, start, flags))
    }

    /// Gemeinsamer Schlüsselanfang (Tag 0), außer bei Wurzelseiten.
    fn key_prefix(&self) -> &'a [u8] {
        if self.flags.contains(PageFlags::ROOT) {
            return &[];
        }
        self.tag(0).map_or(&[][..], |(d, _, _)| d)
    }

    /// Knoten der Seite (Tags 1 bis zur Zahl der Knoten). Unstimmige Tags
    /// werden übersprungen.
    pub fn nodes(&self) -> Vec<Node<'a>> {
        let count = self.tag_count.saturating_sub(self.reserved);
        let prefix = self.key_prefix();
        let mut out = Vec::with_capacity(count);
        for index in 1..=count {
            let Some((data, start, flags)) = self.tag(index) else {
                continue;
            };
            let mut pos = 0usize;
            let mut key = Vec::new();
            if flags & 0x04 != 0 {
                let Some(n) = u16_at(data, 0) else { continue };
                let n = usize::from(n & 0x1fff).min(prefix.len());
                key.extend_from_slice(&prefix[..n]);
                pos = 2;
            }
            let Some(n) = u16_at(data, pos) else { continue };
            let n = usize::from(n & 0x1fff);
            pos += 2;
            let Some(suffix) = data.get(pos..pos + n) else {
                continue;
            };
            key.extend_from_slice(suffix);
            pos += n;
            out.push(Node {
                page: self.number,
                file_offset: self.file_offset + (start + pos) as u64,
                flags,
                key,
                data: &data[pos..],
                new_record_format: self.flags.contains(PageFlags::NEW_RECORD_FORMAT),
            });
        }
        out
    }
}
