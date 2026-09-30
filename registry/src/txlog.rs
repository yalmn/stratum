//! Transaktionslogs (`.LOG1`, `.LOG2`) im neuen Format (ab Windows 8.1) und
//! die Wiederherstellung eines unsauber geschriebenen Hives daraus.
//!
//! Formatgrundlage: Maxim Suhanov, "Windows registry file format
//! specification", Abschnitte "Format of transaction log files / New format",
//! "Dirty state of a hive" und "Multiple transaction log files". Marvin32 nach
//! dem Referenzcode von Microsoft (.NET, `System.Marvin`). Die Deutung des
//! Startwerts als Zahl `0x82EF4D887A4E55C5` und die Ablage des 64-Bit-Ergebnisses
//! (untere Hälfte zuerst) sind gegen die Prüfsummen echter Logs geprüft.
//!
//! Das alte Format (Windows XP bis 8, Kennung `DIRT`) wird erkannt, aber nicht
//! eingespielt; dafür liegen keine Testdaten vor.
//!
//! Die Wiederherstellung arbeitet auf einer Kopie im Speicher. Die Dateien im
//! Image bleiben unverändert.

use crate::hive::{checksum, le_u32, BASE_BLOCK_SIZE};

/// Obergrenze für die Größe eines wiederhergestellten Hive-Bin-Bereichs.
/// Entspricht der Lesegrenze für Dateien und schützt vor manipulierten Logs.
pub const MAX_HBINS_SIZE: u32 = 256 * 1024 * 1024;

const SECTOR: usize = 512;
const ENTRY_HEADER: usize = 40;
const SEED: u64 = 0x82EF_4D88_7A4E_55C5;

/// Marvin32 mit 64-Bit-Ergebnis (untere Hälfte: erster Zustandswert).
pub fn marvin64(data: &[u8], seed: u64) -> u64 {
    fn block(p0: &mut u32, p1: &mut u32) {
        *p1 ^= *p0;
        *p0 = p0.rotate_left(20);
        *p0 = p0.wrapping_add(*p1);
        *p1 = p1.rotate_left(9);
        *p1 ^= *p0;
        *p0 = p0.rotate_left(27);
        *p0 = p0.wrapping_add(*p1);
        *p1 = p1.rotate_left(19);
    }
    let (mut p0, mut p1) = (seed as u32, (seed >> 32) as u32);
    let mut chunks = data.chunks_exact(4);
    for c in &mut chunks {
        p0 = p0.wrapping_add(u32::from_le_bytes([c[0], c[1], c[2], c[3]]));
        block(&mut p0, &mut p1);
    }
    // Rest von 0 bis 3 Byte, dahinter das Abschlussbyte 0x80.
    let mut last = [0u8; 4];
    let rest = chunks.remainder();
    last[..rest.len()].copy_from_slice(rest);
    last[rest.len()] = 0x80;
    p0 = p0.wrapping_add(u32::from_le_bytes(last));
    block(&mut p0, &mut p1);
    block(&mut p0, &mut p1);
    u64::from(p0) | (u64::from(p1) << 32)
}

/// Format einer Logdatei.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    /// Neues Format mit `HvLE`-Einträgen (Dateityp 6).
    Neu,
    /// Altes Format mit Dirty Vector (Dateityp 1 oder 2), wird nicht eingespielt.
    Alt,
    /// Datei ohne Inhalt.
    Leer,
    /// Kein gültiger Kopf.
    Ungueltig,
}

impl LogFormat {
    /// Bezeichnung im Report.
    pub fn name(self) -> &'static str {
        match self {
            Self::Neu => "neu",
            Self::Alt => "alt_nicht_unterstuetzt",
            Self::Leer => "leer",
            Self::Ungueltig => "ungueltig",
        }
    }
}

/// Ein Logeintrag (`HvLE`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    /// Offset des Eintrags in der Logdatei.
    pub offset: usize,
    /// Größe in Byte.
    pub size: usize,
    /// Flags (nur Bit 0 wird übernommen).
    pub flags: u32,
    /// Sequenznummer des Hives nach dem Einspielen.
    pub sequence: u32,
    /// Größe des Hive-Bin-Bereichs nach dem Einspielen.
    pub hbins_size: u32,
    /// Seiten: Offset im Hive-Bin-Bereich und Lage der Daten in der Logdatei.
    pub pages: Vec<(u32, std::ops::Range<usize>)>,
    /// Beide Marvin-Prüfsummen stimmen.
    pub hashes_ok: bool,
}

/// Eine gelesene Logdatei.
#[derive(Debug, Clone)]
pub struct TransactionLog<'a> {
    data: &'a [u8],
    /// Erkanntes Format.
    pub format: LogFormat,
    /// Primäre Sequenznummer im Kopf der Logdatei.
    pub primary_seq: u32,
    /// Sekundäre Sequenznummer im Kopf der Logdatei.
    pub secondary_seq: u32,
    /// Prüfsumme des Kopfs stimmt.
    pub checksum_ok: bool,
    /// Lesbare Einträge in Dateireihenfolge, einschließlich alter Reste.
    pub entries: Vec<LogEntry>,
}

impl<'a> TransactionLog<'a> {
    /// Liest den Kopf und alle aufeinanderfolgenden Einträge. Die Suche endet
    /// am ersten Sektor ohne gültigen Eintrag; dahinter liegen Reste.
    pub fn parse(data: &'a [u8]) -> Self {
        let mut log = Self {
            data,
            format: LogFormat::Ungueltig,
            primary_seq: 0,
            secondary_seq: 0,
            checksum_ok: false,
            entries: Vec::new(),
        };
        if data.is_empty() {
            log.format = LogFormat::Leer;
            return log;
        }
        if data.len() < SECTOR || &data[..4] != b"regf" {
            return log;
        }
        log.primary_seq = le_u32(data, 4);
        log.secondary_seq = le_u32(data, 8);
        log.checksum_ok = checksum(&data[..508]) == le_u32(data, 508);
        log.format = match le_u32(data, 28) {
            6 => LogFormat::Neu,
            1 | 2 => LogFormat::Alt,
            _ => LogFormat::Ungueltig,
        };
        if log.format == LogFormat::Neu {
            let mut pos = SECTOR;
            while let Some(entry) = parse_entry(data, pos) {
                pos += entry.size;
                log.entries.push(entry);
            }
        }
        log
    }

    /// Kopf gültig: neues Format, Prüfsumme stimmt, Sequenznummern gleich.
    pub fn header_ok(&self) -> bool {
        self.format == LogFormat::Neu && self.checksum_ok && self.primary_seq == self.secondary_seq
    }

    /// Die Kette einspielbarer Einträge ab dem ersten Eintrag: Sie beginnt mit
    /// der Sequenznummer aus dem Kopf der Logdatei, die nicht kleiner als
    /// `min_seq` sein darf, und endet vor der ersten Lücke, einem falschen
    /// Hash oder einer unplausiblen Größe.
    fn chain(&self, min_seq: Option<u32>) -> &[LogEntry] {
        let mut len = 0;
        for (i, e) in self.entries.iter().enumerate() {
            let expected = if i == 0 {
                self.primary_seq
            } else {
                self.entries[i - 1].sequence.wrapping_add(1)
            };
            let ok = e.sequence == expected
                && e.hashes_ok
                && e.hbins_size.is_multiple_of(4096)
                && e.hbins_size <= MAX_HBINS_SIZE
                && (i > 0 || min_seq.is_none_or(|m| e.sequence >= m));
            if !ok {
                break;
            }
            len += 1;
        }
        &self.entries[..len]
    }
}

fn parse_entry(data: &[u8], pos: usize) -> Option<LogEntry> {
    let head = data.get(pos..pos.checked_add(ENTRY_HEADER)?)?;
    if &head[..4] != b"HvLE" {
        return None;
    }
    let size = le_u32(head, 4) as usize;
    if size < ENTRY_HEADER || !size.is_multiple_of(SECTOR) {
        return None;
    }
    let raw = data.get(pos..pos.checked_add(size)?)?;
    let count = le_u32(head, 20) as usize;
    let refs_end = count.checked_mul(8)?.checked_add(ENTRY_HEADER)?;
    if refs_end > size {
        return None;
    }
    let hbins_size = le_u32(head, 16);
    let mut pages = Vec::with_capacity(count);
    let mut at = refs_end;
    for i in 0..count {
        let r = ENTRY_HEADER + i * 8;
        let offset = le_u32(raw, r);
        let len = le_u32(raw, r + 4) as usize;
        let end = at.checked_add(len)?;
        if len == 0 || end > size || u64::from(offset) + len as u64 > u64::from(hbins_size) {
            return None;
        }
        pages.push((offset, pos + at..pos + end));
        at = end;
    }
    let hash1 = u64::from_le_bytes(head[24..32].try_into().ok()?);
    let hash2 = u64::from_le_bytes(head[32..40].try_into().ok()?);
    let hashes_ok =
        marvin64(&raw[ENTRY_HEADER..], SEED) == hash1 && marvin64(&raw[..32], SEED) == hash2;
    Some(LogEntry {
        offset: pos,
        size,
        flags: le_u32(head, 8),
        sequence: le_u32(head, 12),
        hbins_size,
        pages,
        hashes_ok,
    })
}

/// Ein eingespielter Abschnitt: Index der Logdatei und Sequenzbereich.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    /// Index der Logdatei in der übergebenen Liste.
    pub log: usize,
    /// Erste eingespielte Sequenznummer.
    pub from: u32,
    /// Letzte eingespielte Sequenznummer.
    pub to: u32,
}

/// Ergebnis der Prüfung eines Hives gegen seine Logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recovery {
    /// Hive ist sauber, nichts einzuspielen. `ignored` zählt Einträge mit
    /// Sequenznummer ab der des Hives; Windows ignoriert sie bei einem
    /// sauberen Hive ebenfalls.
    Clean {
        /// Neuere, von Windows nicht eingespielte Einträge.
        ignored: usize,
    },
    /// Aus den Logs wiederhergestellt.
    Recovered {
        /// Wiederhergestellter Hive.
        data: Vec<u8>,
        /// Eingespielte Abschnitte in Reihenfolge.
        applied: Vec<Applied>,
        /// Der Kopf des Hives stammt aus einer Logdatei (Prüfsumme war falsch).
        base_from_log: bool,
    },
    /// Unsauber, aber nicht wiederherstellbar.
    Failed(&'static str),
}

/// Prüft einen Hive gegen seine Logs und spielt sie bei Bedarf ein, wie es der
/// Windows-Kern beim Laden tut: nur wenn die Prüfsumme des Kopfs falsch ist
/// oder die Sequenznummern abweichen.
pub fn recover(primary: &[u8], logs: &[TransactionLog<'_>]) -> Recovery {
    if primary.len() < BASE_BLOCK_SIZE || &primary[..4] != b"regf" {
        return Recovery::Failed("kein gültiger Hive-Kopf");
    }
    let prim_seq = le_u32(primary, 4);
    let sec_seq = le_u32(primary, 8);
    let checksum_ok = checksum(&primary[..508]) == le_u32(primary, 508);
    if checksum_ok && prim_seq == sec_seq {
        let ignored = logs
            .iter()
            .flat_map(|l| &l.entries)
            .filter(|e| e.sequence >= prim_seq && e.hashes_ok)
            .count();
        return Recovery::Clean { ignored };
    }

    let usable: Vec<(usize, &TransactionLog<'_>)> = logs
        .iter()
        .enumerate()
        .filter(|(_, l)| l.header_ok())
        .collect();
    if usable.is_empty() {
        return Recovery::Failed("keine gültige Logdatei im neuen Format");
    }

    let mut data = primary.to_vec();
    let mut applied = Vec::new();
    if checksum_ok {
        // Beide Logs, das mit den früheren Einträgen zuerst; das zweite schließt
        // nur mit genau der nächsten Sequenznummer an.
        let mut chains: Vec<(usize, &[LogEntry])> = usable
            .iter()
            .map(|(i, l)| (*i, l.chain(Some(sec_seq))))
            .filter(|(_, c)| !c.is_empty())
            .collect();
        chains.sort_by_key(|(_, c)| c[0].sequence);
        let mut last: Option<u32> = None;
        for (index, chain) in chains {
            if last.is_some_and(|n| chain[0].sequence != n.wrapping_add(1)) {
                continue;
            }
            if let Err(reason) = apply(&mut data, logs[index].data, chain) {
                return Recovery::Failed(reason);
            }
            applied.push(Applied {
                log: index,
                from: chain[0].sequence,
                to: chain[chain.len() - 1].sequence,
            });
            last = Some(chain[chain.len() - 1].sequence);
        }
    } else {
        // Kopf defekt: nur das Log mit den jüngsten Einträgen, sein Kopf ersetzt
        // den des Hives.
        let Some((index, chain)) = usable
            .iter()
            .map(|(i, l)| (*i, l.chain(None)))
            .filter(|(_, c)| !c.is_empty())
            .max_by_key(|(_, c)| c[c.len() - 1].sequence)
        else {
            return Recovery::Failed("keine einspielbaren Logeinträge");
        };
        data[..SECTOR].copy_from_slice(&logs[index].data[..SECTOR]);
        data[28..32].copy_from_slice(&0u32.to_le_bytes());
        if let Err(reason) = apply(&mut data, logs[index].data, chain) {
            return Recovery::Failed(reason);
        }
        applied.push(Applied {
            log: index,
            from: chain[0].sequence,
            to: chain[chain.len() - 1].sequence,
        });
    }
    if applied.is_empty() {
        return Recovery::Failed("keine einspielbaren Logeinträge");
    }
    Recovery::Recovered {
        data,
        applied,
        base_from_log: !checksum_ok,
    }
}

/// Schreibt die Seiten der Einträge in den Hive und setzt den Kopf auf den
/// Stand nach dem letzten Eintrag.
fn apply(data: &mut Vec<u8>, log: &[u8], entries: &[LogEntry]) -> Result<(), &'static str> {
    for e in entries {
        let needed = BASE_BLOCK_SIZE + e.hbins_size as usize;
        if data.len() < needed {
            data.resize(needed, 0);
        }
        for (offset, range) in &e.pages {
            let at = BASE_BLOCK_SIZE + *offset as usize;
            let page = log
                .get(range.clone())
                .ok_or("Seite außerhalb der Logdatei")?;
            data.get_mut(at..at + page.len())
                .ok_or("Seite außerhalb des Hives")?
                .copy_from_slice(page);
        }
        data[4..8].copy_from_slice(&e.sequence.to_le_bytes());
        data[8..12].copy_from_slice(&e.sequence.to_le_bytes());
        data[40..44].copy_from_slice(&e.hbins_size.to_le_bytes());
        let flags = (le_u32(data, 144) & !1) | (e.flags & 1);
        data[144..148].copy_from_slice(&flags.to_le_bytes());
    }
    let sum = checksum(&data[..508]);
    data[508..512].copy_from_slice(&sum.to_le_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::HiveBuilder;
    use crate::Hive;

    #[test]
    fn marvin_referenzwerte() {
        // Werte aus einer unabhängigen Umsetzung, die gegen die Prüfsummen
        // echter Windows-11-Logs bestätigt ist.
        let lang: Vec<u8> = (0..16).flat_map(|_| 0u8..=255).collect();
        let kurz: Vec<u8> = (0u8..40).collect();
        for (data, erwartet) in [
            (&b""[..], 0xb39e_fca4_0396_6e08u64),
            (b"a", 0x21a0_13c7_26f2_92f4),
            (b"ab", 0x7911_da00_3172_85f8),
            (b"abc", 0xb9cf_3dfc_a419_14f7),
            (b"abcd", 0x2009_4fb1_1a6c_d086),
            (b"abcdefg", 0x0c00_597a_c6bf_45f2),
            (&kurz[..], 0x2366_e1ba_b67b_6ea3),
            (&lang[..], 0x9db6_3191_813e_594e),
        ] {
            assert_eq!(marvin64(data, SEED), erwartet, "Länge {}", data.len());
        }
    }

    /// Hive mit gegebenen Sequenznummern und gültiger Prüfsumme.
    fn hive(primary: u32, secondary: u32) -> Vec<u8> {
        let mut b = HiveBuilder::new();
        let root = b.key("ROOT", None, &[]);
        let mut data = b.finish(root);
        data[4..8].copy_from_slice(&primary.to_le_bytes());
        data[8..12].copy_from_slice(&secondary.to_le_bytes());
        let sum = checksum(&data[..508]);
        data[508..512].copy_from_slice(&sum.to_le_bytes());
        data
    }

    fn eintrag(seq: u32, hbins: u32, seiten: &[(u32, Vec<u8>)]) -> Vec<u8> {
        let daten: usize = seiten.iter().map(|(_, p)| p.len()).sum();
        let roh = ENTRY_HEADER + 8 * seiten.len() + daten;
        let size = roh.div_ceil(SECTOR) * SECTOR;
        let mut e = vec![0u8; size];
        e[..4].copy_from_slice(b"HvLE");
        e[4..8].copy_from_slice(&(size as u32).to_le_bytes());
        e[12..16].copy_from_slice(&seq.to_le_bytes());
        e[16..20].copy_from_slice(&hbins.to_le_bytes());
        e[20..24].copy_from_slice(&(seiten.len() as u32).to_le_bytes());
        let mut at = ENTRY_HEADER + 8 * seiten.len();
        for (i, (offset, page)) in seiten.iter().enumerate() {
            let r = ENTRY_HEADER + 8 * i;
            e[r..r + 4].copy_from_slice(&offset.to_le_bytes());
            e[r + 4..r + 8].copy_from_slice(&(page.len() as u32).to_le_bytes());
            e[at..at + page.len()].copy_from_slice(page);
            at += page.len();
        }
        let h1 = marvin64(&e[ENTRY_HEADER..], SEED);
        e[24..32].copy_from_slice(&h1.to_le_bytes());
        let h2 = marvin64(&e[..32], SEED);
        e[32..40].copy_from_slice(&h2.to_le_bytes());
        e
    }

    fn logdatei(primary: &[u8], seq: u32, eintraege: &[Vec<u8>]) -> Vec<u8> {
        let mut log = primary[..SECTOR].to_vec();
        log[4..8].copy_from_slice(&seq.to_le_bytes());
        log[8..12].copy_from_slice(&seq.to_le_bytes());
        log[28..32].copy_from_slice(&6u32.to_le_bytes());
        let sum = checksum(&log[..508]);
        log[508..512].copy_from_slice(&sum.to_le_bytes());
        for e in eintraege {
            log.extend_from_slice(e);
        }
        log
    }

    fn seite(fuell: u8) -> Vec<u8> {
        let mut p = vec![fuell; 4096];
        p[..4].copy_from_slice(b"hbin");
        p
    }

    #[test]
    fn sauberer_hive_bleibt_unberuehrt() {
        let h = hive(10, 10);
        let log = logdatei(&h, 9, &[eintrag(9, 4096, &[]), eintrag(10, 4096, &[])]);
        let logs = [TransactionLog::parse(&log)];
        assert_eq!(logs[0].entries.len(), 2);
        assert!(logs[0].entries.iter().all(|e| e.hashes_ok));
        // Eintrag 10 ist neuer als der Hive, Windows ignoriert ihn trotzdem.
        assert_eq!(recover(&h, &logs), Recovery::Clean { ignored: 1 });
    }

    #[test]
    fn unsauberer_hive_wird_eingespielt_und_waechst() {
        let h = hive(10, 9);
        let log = logdatei(
            &h,
            9,
            &[
                eintrag(9, 4096, &[(0, seite(0x11))]),
                eintrag(10, 8192, &[(4096, seite(0x22))]),
            ],
        );
        let logs = [TransactionLog::parse(&log)];
        let Recovery::Recovered {
            data,
            applied,
            base_from_log,
        } = recover(&h, &logs)
        else {
            panic!("nicht wiederhergestellt");
        };
        assert!(!base_from_log);
        assert_eq!(
            applied,
            [Applied {
                log: 0,
                from: 9,
                to: 10
            }]
        );
        assert_eq!(data.len(), 4096 + 8192);
        assert_eq!(data[4096 + 8], 0x11);
        assert_eq!(data[8192 + 8], 0x22);
        let base = Hive::parse(&data).unwrap().base_block().clone();
        assert_eq!(
            (base.primary_seq, base.secondary_seq, base.hbins_size),
            (10, 10, 8192)
        );
        assert!(base.checksum_ok());
        // Die Eingabe bleibt unverändert.
        assert_eq!(h, hive(10, 9));
    }

    #[test]
    fn luecke_und_falscher_hash_beenden_die_kette() {
        let h = hive(12, 9);
        let mut kaputt = eintrag(10, 4096, &[(0, seite(0x33))]);
        kaputt[100] ^= 1;
        let log = logdatei(&h, 9, &[eintrag(9, 4096, &[(0, seite(0x11))]), kaputt]);
        let logs = [TransactionLog::parse(&log)];
        assert!(!logs[0].entries[1].hashes_ok);
        let Recovery::Recovered { data, applied, .. } = recover(&h, &logs) else {
            panic!("nicht wiederhergestellt");
        };
        assert_eq!(
            applied,
            [Applied {
                log: 0,
                from: 9,
                to: 9
            }]
        );
        assert_eq!(data[4096 + 8], 0x11);

        let log = logdatei(&h, 9, &[eintrag(9, 4096, &[]), eintrag(11, 4096, &[])]);
        let logs = [TransactionLog::parse(&log)];
        let Recovery::Recovered { applied, .. } = recover(&h, &logs) else {
            panic!("nicht wiederhergestellt");
        };
        assert_eq!(applied[0].to, 9);
    }

    #[test]
    fn zwei_logs_in_sequenzreihenfolge() {
        let h = hive(12, 9);
        let log1 = logdatei(&h, 11, &[eintrag(11, 4096, &[(0, seite(0x55))])]);
        let log2 = logdatei(
            &h,
            9,
            &[
                eintrag(9, 4096, &[(0, seite(0x44))]),
                eintrag(10, 4096, &[]),
            ],
        );
        let logs = [TransactionLog::parse(&log1), TransactionLog::parse(&log2)];
        let Recovery::Recovered { data, applied, .. } = recover(&h, &logs) else {
            panic!("nicht wiederhergestellt");
        };
        assert_eq!(
            applied,
            [
                Applied {
                    log: 1,
                    from: 9,
                    to: 10
                },
                Applied {
                    log: 0,
                    from: 11,
                    to: 11
                }
            ]
        );
        // Die jüngere Seite gewinnt.
        assert_eq!(data[4096 + 8], 0x55);
    }

    #[test]
    fn alte_eintraege_vor_dem_hive_werden_nicht_eingespielt() {
        // Sekundäre Sequenz 20: ein Log, das bei 9 beginnt, ist veraltet.
        let h = hive(21, 20);
        let log = logdatei(&h, 9, &[eintrag(9, 4096, &[(0, seite(0x66))])]);
        let logs = [TransactionLog::parse(&log)];
        assert_eq!(
            recover(&h, &logs),
            Recovery::Failed("keine einspielbaren Logeinträge")
        );
    }

    #[test]
    fn defekter_kopf_kommt_aus_dem_juengsten_log() {
        let mut h = hive(10, 10);
        h[508] ^= 0xff;
        let log1 = logdatei(&h, 9, &[eintrag(9, 4096, &[(0, seite(0x11))])]);
        let log2 = logdatei(&h, 12, &[eintrag(12, 4096, &[(0, seite(0x22))])]);
        let logs = [TransactionLog::parse(&log1), TransactionLog::parse(&log2)];
        let Recovery::Recovered {
            data,
            applied,
            base_from_log,
        } = recover(&h, &logs)
        else {
            panic!("nicht wiederhergestellt");
        };
        assert!(base_from_log);
        assert_eq!(
            applied,
            [Applied {
                log: 1,
                from: 12,
                to: 12
            }]
        );
        assert_eq!(data[4096 + 8], 0x22);
        let base = Hive::parse(&data).unwrap().base_block().clone();
        assert!(base.checksum_ok());
        assert_eq!(le_u32(&data, 28), 0);
    }

    #[test]
    fn ohne_gueltiges_log_und_mit_unsinn() {
        let h = hive(10, 9);
        let logs = [
            TransactionLog::parse(&[]),
            TransactionLog::parse(&[0xff; 4096]),
        ];
        assert_eq!(logs[0].format, LogFormat::Leer);
        assert_eq!(logs[1].format, LogFormat::Ungueltig);
        assert!(matches!(recover(&h, &logs), Recovery::Failed(_)));
        // Beliebige Bytes nach einem gültigen Kopf: keine Panik.
        let mut log = logdatei(&h, 9, &[]);
        log.extend((0..20_000u32).map(|i| (i * 7 + 3) as u8));
        log[512..516].copy_from_slice(b"HvLE");
        let parsed = TransactionLog::parse(&log);
        let _ = recover(&h, &[parsed]);
    }

    /// Gegen echte Hives und Logs: alle Prüfsummen stimmen, und das Einspielen
    /// des jüngsten, bereits übernommenen Eintrags ändert keine Hive-Daten.
    #[test]
    #[ignore = "benötigt STRATUM_HIVELOG_REFERENCE mit Hives und ihren Logs"]
    fn hivelog_referenz() {
        let dir = std::path::PathBuf::from(std::env::var_os("STRATUM_HIVELOG_REFERENCE").unwrap());
        let mut eintraege = 0;
        for name in [
            "SYSTEM",
            "SOFTWARE",
            "SAM",
            "DEFAULT",
            "UsrClass.dat",
            "ntuser.dat",
        ] {
            let primary = std::fs::read(dir.join(name)).unwrap();
            let rohe: Vec<Vec<u8>> = [".LOG1", ".LOG2"]
                .iter()
                .filter_map(|s| std::fs::read(dir.join(format!("{name}{s}"))).ok())
                .collect();
            let logs: Vec<TransactionLog<'_>> =
                rohe.iter().map(|d| TransactionLog::parse(d)).collect();
            for log in &logs {
                assert!(log.header_ok(), "{name}");
                assert!(log.entries.iter().all(|e| e.hashes_ok), "{name}");
                eintraege += log.entries.len();
            }
            assert_eq!(recover(&primary, &logs), Recovery::Clean { ignored: 0 });
            if name == "ntuser.dat" {
                // Eintrag 150 fehlt (LOG1 im Image leer), kein Vergleich möglich.
                continue;
            }
            // Unsauberen Zustand vor dem jüngsten Eintrag nachstellen.
            let juengster = logs
                .iter()
                .flat_map(|l| &l.entries)
                .map(|e| e.sequence)
                .max()
                .unwrap();
            let mut dirty = primary.clone();
            dirty[8..12].copy_from_slice(&juengster.to_le_bytes());
            let sum = checksum(&dirty[..508]);
            dirty[508..512].copy_from_slice(&sum.to_le_bytes());
            let Recovery::Recovered { data, applied, .. } = recover(&dirty, &logs) else {
                panic!("{name}: nicht wiederhergestellt");
            };
            assert_eq!(applied.last().unwrap().to, juengster, "{name}");
            assert_eq!(
                data[BASE_BLOCK_SIZE..],
                primary[BASE_BLOCK_SIZE..],
                "{name}"
            );
        }
        assert_eq!(eintraege, 18);
    }
}
