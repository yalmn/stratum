//! Baut kleine ESE-Datenbanken für Tests: Seitengröße 4096, eine Blattseite
//! je Tabelle, Datensätze im neuen Format mit festen, variablen und
//! getaggten Spalten. Keine Long Values, keine Kompression.
#![allow(dead_code)]

const SEITE: usize = 4096;
const KOPF: usize = 40;
const KATALOG: u32 = 4;

/// Spaltendefinition. `groesse` gilt nur für Typen ohne feste Größe.
#[derive(Clone, Copy)]
pub struct Spalte {
    pub id: u16,
    pub name: &'static str,
    pub typ: u32,
    pub groesse: u32,
    pub codepage: u32,
}

impl Spalte {
    pub const fn neu(id: u16, name: &'static str, typ: u32) -> Self {
        Self {
            id,
            name,
            typ,
            groesse: 0,
            codepage: 1252,
        }
    }

    fn feste_groesse(&self) -> usize {
        match self.typ {
            1 | 2 => 1,
            3 | 17 => 2,
            4 | 6 | 14 => 4,
            5 | 7 | 8 | 15 => 8,
            16 => 16,
            _ => self.groesse as usize,
        }
    }
}

/// Eine Tabelle mit Zeilen aus (Spalten-ID, Rohwert).
pub struct Tabelle {
    pub name: &'static str,
    pub spalten: Vec<Spalte>,
    pub zeilen: Vec<Vec<(u16, Vec<u8>)>>,
}

/// Datensatz im neuen Format. Fehlende feste und variable Spalten sind leer.
pub fn datensatz(spalten: &[Spalte], werte: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let wert = |id: u16| werte.iter().find(|(i, _)| *i == id).map(|(_, v)| v);
    let mut sp: Vec<&Spalte> = spalten.iter().collect();
    sp.sort_by_key(|c| c.id);
    let fest: Vec<&&Spalte> = sp.iter().filter(|c| c.id < 128).collect();
    let var: Vec<&&Spalte> = sp.iter().filter(|c| (128..256).contains(&c.id)).collect();
    let last_fixed = fest.last().map_or(0, |c| c.id);
    let last_var = var.last().map_or(127, |c| c.id);

    let mut d = vec![last_fixed as u8, last_var as u8, 0, 0];
    let mut bitmap = vec![0u8; usize::from(last_fixed).div_ceil(8)];
    for c in &fest {
        let n = c.feste_groesse();
        match wert(c.id) {
            Some(v) => {
                let mut v = v.clone();
                v.resize(n, 0);
                d.extend_from_slice(&v);
            }
            None => {
                d.extend(std::iter::repeat_n(0, n));
                let bit = usize::from(c.id - 1);
                bitmap[bit / 8] |= 1 << (bit % 8);
            }
        }
    }
    d.extend_from_slice(&bitmap);
    let fixed_end = d.len() as u16;
    d[2..4].copy_from_slice(&fixed_end.to_le_bytes());

    // Variable Spalten: Endoffsets, dann Daten.
    let mut daten = Vec::new();
    let mut ende = Vec::new();
    for id in 128..=last_var {
        match wert(id) {
            Some(v) => {
                daten.extend_from_slice(v);
                ende.push(daten.len() as u16);
            }
            None => ende.push(daten.len() as u16 | 0x8000),
        }
    }
    for e in ende {
        d.extend_from_slice(&e.to_le_bytes());
    }
    d.extend_from_slice(&daten);

    // Getaggte Spalten: Verzeichnis (ID, Offset), dann Werte.
    let getaggt: Vec<(u16, &Vec<u8>)> = sp
        .iter()
        .filter(|c| c.id >= 256)
        .filter_map(|c| wert(c.id).map(|v| (c.id, v)))
        .collect();
    let mut offset = getaggt.len() * 4;
    for (id, v) in &getaggt {
        d.extend_from_slice(&id.to_le_bytes());
        d.extend_from_slice(&(offset as u16).to_le_bytes());
        offset += v.len();
    }
    for (_, v) in &getaggt {
        d.extend_from_slice(v);
    }
    d
}

/// Blattseite (Wurzel) mit den Knoten; Schlüssel ist die laufende Nummer.
fn blattseite(knoten: &[Vec<u8>]) -> Vec<u8> {
    let mut s = vec![0u8; SEITE];
    // Wurzel, Blatt, neues Datensatzformat.
    s[36..40].copy_from_slice(&0x2003u32.to_le_bytes());
    let tags = knoten.len() + 1;
    s[34..36].copy_from_slice(&(tags as u16).to_le_bytes());
    let mut pos = 0usize;
    for (i, daten) in knoten.iter().enumerate() {
        let mut tag = Vec::new();
        tag.extend_from_slice(&4u16.to_le_bytes());
        tag.extend_from_slice(&(i as u32).to_be_bytes());
        tag.extend_from_slice(daten);
        assert!(KOPF + pos + tag.len() + tags * 4 <= SEITE, "Seite zu voll");
        s[KOPF + pos..KOPF + pos + tag.len()].copy_from_slice(&tag);
        let at = SEITE - (i + 2) * 4;
        s[at..at + 2].copy_from_slice(&(tag.len() as u16).to_le_bytes());
        s[at + 2..at + 4].copy_from_slice(&(pos as u16).to_le_bytes());
        pos += tag.len();
    }
    s
}

fn katalogspalten() -> Vec<Spalte> {
    vec![
        Spalte::neu(1, "ObjidTable", 4),
        Spalte::neu(2, "Type", 3),
        Spalte::neu(3, "Id", 4),
        Spalte::neu(4, "ColtypOrPgnoFDP", 4),
        Spalte::neu(5, "SpaceUsage", 4),
        Spalte::neu(6, "Flags", 4),
        Spalte::neu(7, "PagesOrLocale", 4),
        Spalte::neu(8, "RootFlag", 1),
        Spalte::neu(9, "RecordOffset", 3),
        Spalte::neu(10, "LCMapFlags", 4),
        Spalte::neu(11, "KeyMost", 17),
        Spalte::neu(12, "LVChunkMax", 4),
        Spalte::neu(128, "Name", 10),
    ]
}

/// Ganze Datenbank: Dateikopf, Schattenkopf, Katalog auf Seite 4, danach
/// je Tabelle eine Seite. `zustand` 3 heißt sauber geschlossen.
pub fn datenbank(tabellen: &[Tabelle], zustand: u32) -> Vec<u8> {
    let kat = katalogspalten();
    let mut eintraege = Vec::new();
    for (i, t) in tabellen.iter().enumerate() {
        let objekt = (i as u32 + 10).to_le_bytes().to_vec();
        let seite = KATALOG + 1 + i as u32;
        eintraege.push(datensatz(
            &kat,
            &[
                (1, objekt.clone()),
                (2, 1u16.to_le_bytes().to_vec()),
                (3, objekt.clone()),
                (4, seite.to_le_bytes().to_vec()),
                (128, t.name.as_bytes().to_vec()),
            ],
        ));
        for c in &t.spalten {
            eintraege.push(datensatz(
                &kat,
                &[
                    (1, objekt.clone()),
                    (2, 2u16.to_le_bytes().to_vec()),
                    (3, u32::from(c.id).to_le_bytes().to_vec()),
                    (4, c.typ.to_le_bytes().to_vec()),
                    (5, c.groesse.to_le_bytes().to_vec()),
                    (7, c.codepage.to_le_bytes().to_vec()),
                    (128, c.name.as_bytes().to_vec()),
                ],
            ));
        }
    }
    let seiten = KATALOG as usize + 1 + tabellen.len();
    let mut db = vec![0u8; (seiten + 1) * SEITE];
    for kopf in [0, SEITE] {
        db[kopf + 4..kopf + 8].copy_from_slice(&[0xef, 0xcd, 0xab, 0x89]);
        db[kopf + 8..kopf + 12].copy_from_slice(&0x620u32.to_le_bytes());
        db[kopf + 52..kopf + 56].copy_from_slice(&zustand.to_le_bytes());
        db[kopf + 232..kopf + 236].copy_from_slice(&0x14u32.to_le_bytes());
        db[kopf + 236..kopf + 240].copy_from_slice(&(SEITE as u32).to_le_bytes());
    }
    let mut setze = |nummer: u32, inhalt: Vec<u8>| {
        let at = (nummer as usize + 1) * SEITE;
        db[at..at + SEITE].copy_from_slice(&inhalt);
    };
    setze(KATALOG, blattseite(&eintraege));
    for (i, t) in tabellen.iter().enumerate() {
        let zeilen: Vec<Vec<u8>> = t.zeilen.iter().map(|z| datensatz(&t.spalten, z)).collect();
        setze(KATALOG + 1 + i as u32, blattseite(&zeilen));
    }
    db
}
