//! Blockdeskriptoren eines Stores: Vorwärtsliste (nach Originaloffset),
//! Rückwärtsliste der Forwarder (nach relativem Offset) und Overlays.
//!
//! Das Einfügen folgt libvshadow (`libvshadow_block_tree_insert`), weil die
//! Formatbeschreibung diesen Teil selbst als unvollständig kennzeichnet.

use std::collections::HashMap;

use crate::{u32_at, u64_at, BLOCK_SIZE};

/// Der Block wird aus dem nächsten Store bzw. über den relativen Offset gelesen.
pub(crate) const FLAG_FORWARDER: u32 = 0x01;
/// Overlay: die Bitmap nennt die belegten 512-Byte-Abschnitte.
pub(crate) const FLAG_OVERLAY: u32 = 0x02;
/// Nicht benutzt, wird übergangen.
pub(crate) const FLAG_NOT_USED: u32 = 0x04;

/// Ein Blockdeskriptor (32 Byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Descriptor {
    pub original_offset: u64,
    pub relative_offset: u64,
    pub offset: u64,
    pub flags: u32,
    pub bitmap: u32,
    /// Overlay zu diesem Deskriptor (Index in der Liste).
    overlay: Option<usize>,
}

impl Descriptor {
    /// `None` für leere Einträge (nur Nullbytes).
    pub fn parse(e: &[u8]) -> Option<Self> {
        if e.len() < 32 || e[..32].iter().all(|b| *b == 0) {
            return None;
        }
        Some(Self {
            original_offset: u64_at(e, 0)?,
            relative_offset: u64_at(e, 8)?,
            offset: u64_at(e, 16)?,
            flags: u32_at(e, 24)?,
            bitmap: u32_at(e, 28)?,
            overlay: None,
        })
    }
}

/// Ergebnis einer Abfrage: Deskriptor, Leseoffset im Volume und Länge des
/// gleichartigen Bereichs ab dem gefragten Offset.
pub(crate) struct Hit {
    pub descriptor: Option<Descriptor>,
    pub offset: u64,
    pub size: u64,
}

#[derive(Debug, Default)]
pub(crate) struct BlockList {
    arena: Vec<Descriptor>,
    forward: HashMap<u64, usize>,
    reverse: HashMap<u64, usize>,
    /// Eingelesene, nicht leere Deskriptoren.
    count: usize,
}

fn key(offset: u64) -> u64 {
    offset / BLOCK_SIZE
}

impl BlockList {
    pub fn len(&self) -> usize {
        self.count
    }

    pub fn insert(&mut self, d: Descriptor, warnings: &mut Vec<String>, store: usize) {
        self.count += 1;
        if d.flags & FLAG_NOT_USED != 0 {
            return;
        }
        if d.flags & FLAG_FORWARDER != 0 && d.offset != 0 {
            // libvshadow bricht hier ab; stratum übergeht nur diesen Eintrag.
            warnings.push(format!(
                "Store {store}: Forwarder bei {:#x} mit Store-Offset ungleich 0 übergangen",
                d.original_offset
            ));
            return;
        }
        let mut original = d.original_offset;
        if d.flags & FLAG_OVERLAY == 0 {
            // Forwarder, die aufeinander verweisen, zusammenfassen.
            if let Some(ri) = self.reverse.get(&key(d.original_offset)).copied() {
                original = self.arena[ri].original_offset;
                self.reverse.remove(&key(self.arena[ri].relative_offset));
            }
        }
        if d.flags & FLAG_FORWARDER != 0 && original == d.relative_offset {
            return;
        }
        let ni = self.arena.len();
        self.arena.push(Descriptor {
            original_offset: original,
            overlay: None,
            ..d
        });
        match self.forward.get(&key(original)).copied() {
            None => {
                self.forward.insert(key(original), ni);
            }
            Some(ei) => {
                if d.flags & FLAG_OVERLAY != 0 {
                    // Weiteres Overlay: Bitmap des bestehenden erweitern.
                    let existing = self.arena[ei];
                    let ov = if existing.flags & FLAG_OVERLAY != 0 {
                        Some(ei)
                    } else {
                        existing.overlay
                    };
                    match ov {
                        Some(o) => self.arena[o].bitmap |= d.bitmap,
                        None => self.arena[ei].overlay = Some(ni),
                    }
                    return;
                }
                self.forward.insert(key(original), ni);
                if self.arena[ei].flags & FLAG_OVERLAY != 0 {
                    if self.arena[ei].overlay.is_some() {
                        warnings.push(format!(
                            "Store {store}: Overlay bei {original:#x} hat selbst ein Overlay"
                        ));
                    }
                    self.arena[ni].overlay = Some(ei);
                } else {
                    self.arena[ni].overlay = self.arena[ei].overlay.take();
                }
            }
        }
        if d.flags & FLAG_FORWARDER != 0 {
            self.reverse.insert(key(d.relative_offset), ni);
        }
    }

    /// Liegt für diesen Block ein Forwarder in der Rückwärtsliste?
    pub fn in_reverse(&self, offset: u64) -> bool {
        self.reverse.contains_key(&key(offset))
    }

    /// Deskriptor und Leseoffset für `offset`. Overlays gelten nur im
    /// aktiven Store (dem, dessen Snapshot gelesen wird).
    pub fn range_at(&self, offset: u64, active: bool) -> Hit {
        let rel = offset % BLOCK_SIZE;
        let mut size = BLOCK_SIZE - rel;
        let Some(&di) = self.forward.get(&key(offset)) else {
            return Hit {
                descriptor: None,
                offset: 0,
                size,
            };
        };
        let d = self.arena[di];
        let mut desc = Some(di);
        let mut read_at = if d.flags & FLAG_FORWARDER != 0 {
            d.relative_offset
        } else {
            d.offset
        };
        let ov = if d.flags & FLAG_OVERLAY != 0 {
            Some(di)
        } else {
            d.overlay
        };
        if let Some(o) = ov {
            if !active {
                if desc == Some(o) {
                    desc = None;
                }
            } else {
                let od = self.arena[o];
                // Abschnitt (512 Byte) des gefragten Offsets im Overlay-Block.
                let im_block = offset.saturating_sub(od.original_offset);
                let k = (im_block / 512).min(32) as u32;
                let bits = od.bitmap.checked_shr(k).unwrap_or(0);
                let belegt = bits & 1 != 0;
                let mut lauf = 0u64;
                for i in 0..(32 - k) {
                    if ((bits >> i) & 1 != 0) != belegt {
                        break;
                    }
                    lauf += 1;
                }
                size = (lauf * 512).saturating_sub(im_block % 512).min(size);
                if belegt {
                    read_at = od.offset;
                    desc = Some(o);
                } else if desc == Some(o) {
                    desc = None;
                }
            }
        }
        Hit {
            descriptor: desc.map(|i| self.arena[i]),
            offset: read_at + rel,
            size,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(original: u64, relative: u64, offset: u64, flags: u32, bitmap: u32) -> Descriptor {
        Descriptor {
            original_offset: original,
            relative_offset: relative,
            offset,
            flags,
            bitmap,
            overlay: None,
        }
    }

    #[test]
    fn leere_und_nicht_benutzte_eintraege() {
        assert!(Descriptor::parse(&[0; 32]).is_none());
        let mut l = BlockList::default();
        l.insert(d(0x4000, 0, 0x8000, FLAG_NOT_USED, 0), &mut Vec::new(), 0);
        assert_eq!(l.len(), 1);
        assert!(l.range_at(0x4000, true).descriptor.is_none());
    }

    #[test]
    fn overlay_nur_im_aktiven_store() {
        let mut l = BlockList::default();
        let mut w = Vec::new();
        // Normaler Block, dann Overlay für die ersten zwei Abschnitte.
        l.insert(d(0x4000, 0, 0x10000, 0, 0), &mut w, 0);
        l.insert(d(0x4000, 1, 0x20000, FLAG_OVERLAY, 0b11), &mut w, 0);
        let h = l.range_at(0x4000, true);
        assert_eq!((h.offset, h.size), (0x20000, 1024));
        let h = l.range_at(0x4000 + 1024, true);
        assert_eq!((h.offset, h.size), (0x10000 + 1024, 0x4000 - 1024));
        // Nicht aktiv: Overlay wird übergangen.
        let h = l.range_at(0x4000, false);
        assert_eq!((h.offset, h.size), (0x10000, 0x4000));
    }

    #[test]
    fn overlays_werden_zusammengefasst() {
        let mut l = BlockList::default();
        let mut w = Vec::new();
        l.insert(d(0x4000, 1, 0x20000, FLAG_OVERLAY, 0b01), &mut w, 0);
        l.insert(d(0x4000, 1, 0x20000, FLAG_OVERLAY, 0b10), &mut w, 0);
        let h = l.range_at(0x4000, true);
        assert_eq!((h.offset, h.size), (0x20000, 1024));
        // Nicht belegter Rest eines reinen Overlays: kein Deskriptor.
        assert!(l.range_at(0x4000 + 1024, true).descriptor.is_none());
    }

    #[test]
    fn forwarder_ketten() {
        let mut l = BlockList::default();
        let mut w = Vec::new();
        // Block 0x8000 wird weitergeleitet nach 0xc000.
        l.insert(d(0x8000, 0xc000, 0, FLAG_FORWARDER, 0), &mut w, 0);
        let h = l.range_at(0x8000, true);
        assert_eq!(h.offset, 0xc000);
        assert!(l.in_reverse(0xc000));
        // Ein Deskriptor für 0xc000 übernimmt den Originaloffset 0x8000.
        l.insert(d(0xc000, 0, 0x30000, 0, 0), &mut w, 0);
        assert!(!l.in_reverse(0xc000));
        let h = l.range_at(0x8000, true);
        assert_eq!(h.offset, 0x30000);
        // Forwarder auf sich selbst wird übergangen.
        l.insert(d(0x10000, 0x10000, 0, FLAG_FORWARDER, 0), &mut w, 0);
        assert!(l.range_at(0x10000, true).descriptor.is_none());
        // Forwarder mit Store-Offset: Hinweis statt Abbruch.
        l.insert(d(0x14000, 0x18000, 0x4000, FLAG_FORWARDER, 0), &mut w, 3);
        assert_eq!(w.len(), 1);
    }
}
