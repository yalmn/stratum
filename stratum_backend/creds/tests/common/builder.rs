//! Baut synthetische Hives für Tests.
//!
//! Alle Zellen landen in einem einzigen Hive Bin. Rückgabewerte sind
//! Zell-Offsets (relativ zum Ende des Base Blocks), `patch_*` erwartet Offsets
//! relativ zum Zellbeginn, also inklusive des 4-Byte-Größenfelds.

#![allow(dead_code)]

const HBIN_HEADER: usize = 32;
const BIG_SEGMENT: usize = 16344;

pub struct HiveBuilder {
    bin: Vec<u8>,
    minor: u32,
}

impl Default for HiveBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl HiveBuilder {
    pub fn new() -> Self {
        let mut bin = vec![0u8; HBIN_HEADER];
        bin[..4].copy_from_slice(b"hbin");
        Self { bin, minor: 5 }
    }

    pub fn minor(&mut self, minor: u32) -> &mut Self {
        self.minor = minor;
        self
    }

    /// Legt eine belegte Zelle an und liefert ihren Offset.
    pub fn alloc(&mut self, payload: &[u8]) -> u32 {
        let off = self.bin.len() as u32;
        let size = (4 + payload.len()).next_multiple_of(8);
        self.bin.extend_from_slice(&(-(size as i32)).to_le_bytes());
        self.bin.extend_from_slice(payload);
        self.bin.resize(off as usize + size, 0);
        off
    }

    pub fn patch_u16(&mut self, cell: u32, at: usize, v: u16) {
        let o = cell as usize + at;
        self.bin[o..o + 2].copy_from_slice(&v.to_le_bytes());
    }

    pub fn patch_u32(&mut self, cell: u32, at: usize, v: u32) {
        let o = cell as usize + at;
        self.bin[o..o + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn nk(&mut self, name: &[u8], flags: u16, list: Option<(u32, u32)>, values: &[u32]) -> u32 {
        let value_list = if values.is_empty() {
            u32::MAX
        } else {
            let raw: Vec<u8> = values.iter().flat_map(|v| v.to_le_bytes()).collect();
            self.alloc(&raw)
        };
        let (list_cell, count) = list.unwrap_or((u32::MAX, 0));

        let mut p = vec![0u8; 76];
        p[..2].copy_from_slice(b"nk");
        p[2..4].copy_from_slice(&flags.to_le_bytes());
        // 2021-01-01T00:00:00Z
        p[4..12].copy_from_slice(&132_539_328_000_000_000u64.to_le_bytes());
        p[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        p[20..24].copy_from_slice(&count.to_le_bytes());
        p[28..32].copy_from_slice(&list_cell.to_le_bytes());
        p[32..36].copy_from_slice(&u32::MAX.to_le_bytes());
        p[36..40].copy_from_slice(&(values.len() as u32).to_le_bytes());
        p[40..44].copy_from_slice(&value_list.to_le_bytes());
        p[44..48].copy_from_slice(&u32::MAX.to_le_bytes());
        p[48..52].copy_from_slice(&u32::MAX.to_le_bytes());
        p[72..74].copy_from_slice(&(name.len() as u16).to_le_bytes());
        p.extend_from_slice(name);
        self.alloc(&p)
    }

    /// Schlüssel mit ASCII-Namen. `list` ist (Listen-Zelle, Anzahl).
    pub fn key(&mut self, name: &str, list: Option<(u32, u32)>, values: &[u32]) -> u32 {
        self.nk(name.as_bytes(), 0x0020, list, values)
    }

    pub fn key_with_list(&mut self, name: &str, list: u32, count: u32, values: &[u32]) -> u32 {
        self.key(name, Some((list, count)), values)
    }

    /// Schlüssel mit UTF-16LE-Namen, ohne Unterschlüssel und Werte.
    pub fn key_utf16(&mut self, name: &str) -> u32 {
        let raw: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        self.nk(&raw, 0, None, &[])
    }

    /// Schlüssel mit ASCII-Namen und einem Class-Wert (UTF-16LE abgelegt).
    pub fn key_with_class(
        &mut self,
        name: &str,
        class: &str,
        list: Option<(u32, u32)>,
        values: &[u32],
    ) -> u32 {
        let raw: Vec<u8> = class.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let class_cell = self.alloc(&raw);
        let nk = self.nk(name.as_bytes(), 0x0020, list, values);
        // patch_* ist zellrelativ (inklusive 4-Byte-Größenpräfix), daher +4
        // auf die Payload-Offsets 48 (Class-Zelle) und 74 (Class-Länge).
        self.patch_u32(nk, 4 + 48, class_cell);
        self.patch_u16(nk, 4 + 74, raw.len() as u16);
        nk
    }

    fn list(&mut self, sig: &[u8; 2], entries: &[u32], with_hash: bool) -> u32 {
        let mut p = Vec::new();
        p.extend_from_slice(sig);
        p.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        for e in entries {
            p.extend_from_slice(&e.to_le_bytes());
            if with_hash {
                p.extend_from_slice(&0u32.to_le_bytes());
            }
        }
        self.alloc(&p)
    }

    pub fn lf(&mut self, entries: &[u32]) -> u32 {
        self.list(b"lf", entries, true)
    }

    pub fn lh(&mut self, entries: &[u32]) -> u32 {
        self.list(b"lh", entries, true)
    }

    pub fn li(&mut self, entries: &[u32]) -> u32 {
        self.list(b"li", entries, false)
    }

    pub fn ri(&mut self, entries: &[u32]) -> u32 {
        self.list(b"ri", entries, false)
    }

    fn vk_raw(&mut self, name: &str, typ: u32, len: u32, data_field: u32) -> u32 {
        let mut p = vec![0u8; 20];
        p[..2].copy_from_slice(b"vk");
        p[2..4].copy_from_slice(&(name.len() as u16).to_le_bytes());
        p[4..8].copy_from_slice(&len.to_le_bytes());
        p[8..12].copy_from_slice(&data_field.to_le_bytes());
        p[12..16].copy_from_slice(&typ.to_le_bytes());
        p[16..18].copy_from_slice(&1u16.to_le_bytes());
        p.extend_from_slice(name.as_bytes());
        self.alloc(&p)
    }

    /// Wert mit ASCII-Namen. Daten bis 4 Bytes werden inline abgelegt.
    pub fn vk(&mut self, name: &str, typ: u32, data: &[u8]) -> u32 {
        if data.len() <= 4 {
            let mut inline = [0u8; 4];
            inline[..data.len()].copy_from_slice(data);
            self.vk_raw(
                name,
                typ,
                0x8000_0000 | data.len() as u32,
                u32::from_le_bytes(inline),
            )
        } else {
            let cell = self.alloc(data);
            self.vk_raw(name, typ, data.len() as u32, cell)
        }
    }

    /// Wert, dessen Daten als Big Data (db) in Segmenten abgelegt werden.
    pub fn vk_big(&mut self, name: &str, typ: u32, data: &[u8]) -> u32 {
        let segs: Vec<u32> = data.chunks(BIG_SEGMENT).map(|c| self.alloc(c)).collect();
        let list: Vec<u8> = segs.iter().flat_map(|s| s.to_le_bytes()).collect();
        let list_cell = self.alloc(&list);
        let mut db = Vec::new();
        db.extend_from_slice(b"db");
        db.extend_from_slice(&(segs.len() as u16).to_le_bytes());
        db.extend_from_slice(&list_cell.to_le_bytes());
        let db_cell = self.alloc(&db);
        self.vk_raw(name, typ, data.len() as u32, db_cell)
    }

    /// Schreibt Base Block und Hive Bin.
    pub fn finish(mut self, root: u32) -> Vec<u8> {
        let size = self.bin.len().next_multiple_of(4096);
        self.bin.resize(size, 0);
        self.bin[8..12].copy_from_slice(&(size as u32).to_le_bytes());

        let mut base = vec![0u8; 4096];
        base[..4].copy_from_slice(b"regf");
        base[4..8].copy_from_slice(&1u32.to_le_bytes());
        base[8..12].copy_from_slice(&1u32.to_le_bytes());
        base[12..20].copy_from_slice(&132_539_328_000_000_000u64.to_le_bytes());
        base[20..24].copy_from_slice(&1u32.to_le_bytes());
        base[24..28].copy_from_slice(&self.minor.to_le_bytes());
        base[32..36].copy_from_slice(&1u32.to_le_bytes());
        base[36..40].copy_from_slice(&root.to_le_bytes());
        base[40..44].copy_from_slice(&(size as u32).to_le_bytes());
        base[44..48].copy_from_slice(&1u32.to_le_bytes());
        for (i, u) in "SYSTEM".encode_utf16().enumerate() {
            base[48 + 2 * i..50 + 2 * i].copy_from_slice(&u.to_le_bytes());
        }
        let sum = base[..508].chunks_exact(4).fold(0u32, |a, c| {
            a ^ u32::from_le_bytes([c[0], c[1], c[2], c[3]])
        });
        base[508..512].copy_from_slice(&sum.to_le_bytes());

        base.extend_from_slice(&self.bin);
        base
    }

    /// Hive mit einem leeren Wurzelschlüssel.
    pub fn finish_empty_root(mut self) -> Vec<u8> {
        let root = self.key("ROOT", None, &[]);
        self.finish(root)
    }
}
