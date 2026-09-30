//! ShellBags: welche Ordner ein Benutzer im Explorer geöffnet hat, auch auf
//! Wechseldatenträgern und im Netz.
//!
//! Quelle ist der Baum `BagMRU` in der UsrClass.dat (ab Windows 7) und in der
//! NTUSER.DAT. Jeder Schlüssel enthält nummerierte Werte mit je einem Shell
//! Item und einen gleichnamigen Unterschlüssel für die Einträge darunter; der
//! Pfad ergibt sich aus der Folge der Shell Items. `MRUListEx` gibt die
//! Reihenfolge der letzten Verwendung an.
//!
//! Zeitangaben: Die FAT-Zeiten (`element_*`) stammen aus dem Shell Item und
//! beschreiben den Ordner zum Zeitpunkt der Aufzeichnung. `zuletzt_verwendet` ist abgeleitet:
//! die Änderungszeit des Elternschlüssels, die nur für dessen zuletzt
//! verwendeten Eintrag (erste Stelle in `MRUListEx`) gilt.

use std::collections::HashMap;

use stratum_core::time::filetime_to_iso;
use stratum_registry::{Hive, Key};

use crate::shellitem::{parse_item, ShellItem};
use crate::{AnalysisContext, Analyzer, Finding, Outcome};

const USRCLASS_BAGMRU: &str = "Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU";
const NTUSER_BAGMRU: [&str; 2] = [
    "Software\\Microsoft\\Windows\\Shell\\BagMRU",
    "Software\\Microsoft\\Windows\\ShellNoRoam\\BagMRU",
];
const MAX_DEPTH: usize = 64;
const MAX_FINDINGS: usize = 100_000;

/// Analyzer für ShellBags.
pub struct ShellBagsAnalyzer;

impl Analyzer for ShellBagsAnalyzer {
    fn domain(&self) -> &str {
        "useraktivitaet"
    }

    fn run(&self, ctx: &AnalysisContext<'_>) -> Outcome {
        let mut out = Outcome::default();
        for inst in ctx.installs.iter() {
            let before = out.findings.len();
            let software = inst
                .hives
                .software
                .as_deref()
                .and_then(|b| Hive::parse(b).ok());
            let mut names = ClsidNames {
                software: software.as_ref(),
                cache: HashMap::new(),
            };
            let quellen = inst
                .usrclass
                .iter()
                .map(|(u, b)| (u, b, "UsrClass.dat", &[USRCLASS_BAGMRU][..]))
                .chain(
                    inst.ntuser
                        .iter()
                        .map(|(u, b)| (u, b, "NTUSER.DAT", &NTUSER_BAGMRU[..])),
                );
            for (user, bytes, hive_name, pfade) in quellen {
                let hive = match Hive::parse(bytes) {
                    Ok(h) => h,
                    Err(e) => {
                        out.warnings
                            .push(format!("{hive_name} von {user} nicht lesbar: {e}"));
                        continue;
                    }
                };
                for pfad in pfade {
                    let Ok(Some(key)) = hive.open_key(pfad) else {
                        continue;
                    };
                    let mut walk = Walk {
                        user,
                        hive_name,
                        names: &mut names,
                        out: &mut out,
                    };
                    walk.key(&key, pfad, "", &[], 0);
                }
            }
            out.tag_origin(before, &inst.origin);
        }
        out
    }
}

/// Anzeigenamen von Ordner-GUIDs aus `SOFTWARE\Classes\CLSID` des Images.
struct ClsidNames<'s, 'h> {
    software: Option<&'s Hive<'h>>,
    cache: HashMap<String, Option<String>>,
}

impl ClsidNames<'_, '_> {
    fn get(&mut self, guid: &str) -> Option<String> {
        let software = self.software;
        self.cache
            .entry(guid.to_string())
            .or_insert_with(|| {
                let key = software?
                    .open_key(&format!("Classes\\CLSID\\{{{guid}}}"))
                    .ok()??;
                key.value("")
                    .ok()?
                    .and_then(|v| v.as_string())
                    .filter(|s| !s.is_empty() && !s.starts_with('@'))
            })
            .clone()
    }
}

struct Walk<'w, 's, 'h> {
    user: &'w str,
    hive_name: &'static str,
    names: &'w mut ClsidNames<'s, 'h>,
    out: &'w mut Outcome,
}

impl Walk<'_, '_, '_> {
    fn key(
        &mut self,
        key: &Key<'_, '_>,
        key_path: &str,
        bag: &str,
        parents: &[String],
        depth: usize,
    ) {
        if depth > MAX_DEPTH {
            self.out.warnings.push(format!(
                "{key_path}: ShellBag-Baum tiefer als {MAX_DEPTH}, abgebrochen"
            ));
            return;
        }
        let Ok(values) = key.values() else {
            self.out
                .warnings
                .push(format!("{key_path}: Werte nicht lesbar"));
            return;
        };
        let mru = values
            .iter()
            .find(|v| v.name().eq_ignore_ascii_case("MRUListEx"))
            .map(|v| mru_list(v.data()))
            .unwrap_or_default();
        let subkeys = key.subkeys().unwrap_or_default();
        let mut entries: Vec<_> = values
            .iter()
            .filter_map(|v| v.name().parse::<u32>().ok().map(|n| (n, v)))
            .collect();
        entries.sort_by_key(|(n, _)| *n);
        for (n, v) in entries {
            if self.out.findings.len() >= MAX_FINDINGS {
                self.out
                    .warnings
                    .push(format!("Grenze von {MAX_FINDINGS} ShellBags erreicht"));
                return;
            }
            let item = parse_item(v.data());
            let teil = self.display(&item);
            let mut pfad: Vec<String> = parents.to_vec();
            pfad.push(teil);
            let bag_n = if bag.is_empty() {
                n.to_string()
            } else {
                format!("{bag}\\{n}")
            };
            let child = subkeys.iter().find(|s| s.name() == n.to_string());
            let mut f = Finding::new(
                "useraktivitaet",
                pfad.join("\\"),
                format!("HKCU {} {}\\{}", self.user, self.hive_name, key_path),
            )
            .with("art", "shellbag")
            .with("benutzer", self.user)
            .with("hive", self.hive_name)
            .with("wert", n.to_string())
            .with("bagmru", &bag_n)
            .with("hive_offset", v.file_offset().to_string())
            .with("key_hive_offset", key.file_offset().to_string());
            f = with_item(f, &item);
            if let Some(g) = item.guid.as_deref().and_then(|g| self.names.get(g)) {
                f = f
                    .with("guid_name", g)
                    .with("guid_name_quelle", "SOFTWARE\\Classes\\CLSID");
            }
            if let Some(pos) = mru.iter().position(|&m| m == n) {
                f = f.with("mru_position", pos.to_string());
                if pos == 0 {
                    if let Some(utc) = filetime_to_iso(key.last_written()) {
                        f = f.with("zuletzt_verwendet_utc", utc);
                    }
                    if let Some((s, _)) = stratum_registry::filetime_to_unix(key.last_written()) {
                        f = f.with("zuletzt_verwendet_unix", s.to_string()).with(
                            "zeit_herkunft",
                            "Änderungszeit des Elternschlüssels, gilt für den ersten Eintrag in MRUListEx",
                        );
                    }
                }
            }
            if let Some(slot) = child
                .and_then(|c| c.value("NodeSlot").ok().flatten())
                .and_then(|v| v.as_u32())
            {
                f = f.with("node_slot", slot.to_string());
            }
            self.out.findings.push(f);
            if let Some(child) = child {
                self.key(child, &format!("{key_path}\\{n}"), &bag_n, &pfad, depth + 1);
            }
        }
    }

    /// Pfadteil eines Eintrags: eigener Name, sonst Name der GUID aus dem
    /// Image, sonst die GUID, sonst eine Kennzeichnung als unbekannt.
    fn display(&mut self, item: &ShellItem) -> String {
        if let Some(name) = &item.name {
            // Laufwerke heißen "C:\\"; der Trenner kommt beim Zusammensetzen.
            return name.trim_end_matches('\\').to_string();
        }
        if let Some(g) = &item.guid {
            return self.names.get(g).unwrap_or_else(|| format!("{{{g}}}"));
        }
        format!("[unbekannt {:#04x}]", item.typ)
    }
}

/// `MRUListEx`: Folge von 32-Bit-Nummern, Ende mit 0xffffffff.
fn mru_list(data: &[u8]) -> Vec<u32> {
    data.chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .take_while(|&n| n != u32::MAX)
        .collect()
}

/// Überträgt die Felder eines Shell Items in einen Fund.
pub(crate) fn with_item(mut f: Finding, item: &ShellItem) -> Finding {
    f = f
        .with("element_art", item.art)
        .with("element_typ", format!("{:#04x}", item.typ));
    let text = [
        ("guid", item.guid.clone()),
        ("kurzname", item.kurzname.clone()),
        ("roh", item.roh.clone()),
        ("zeichenkette", item.zeichenkette.clone()),
        (
            "sortierindex",
            item.sortierindex.map(|v| format!("{v:#04x}")),
        ),
        ("kategorie", item.kategorie.map(|v| v.to_string())),
        (
            "groesse",
            item.groesse.filter(|&g| g > 0).map(|v| v.to_string()),
        ),
        (
            "erweiterung_version",
            item.erweiterung_version.map(|v| v.to_string()),
        ),
        ("mft_record", item.mft.map(|(r, _)| r.to_string())),
        ("mft_sequenz", item.mft.map(|(_, s)| s.to_string())),
    ];
    for (k, v) in text {
        if let Some(v) = v {
            f = f.with(k, v);
        }
    }
    for (k, t) in [
        ("element_erstellt", item.erstellt),
        ("element_geaendert", item.geaendert),
        ("element_zugriff", item.zugriff),
    ] {
        if let Some(t) = t {
            if let (Some(iso), Some(unix)) = (t.iso(), t.unix()) {
                f = f
                    .with(format!("{k}_utc"), iso)
                    .with(format!("{k}_unix"), unix.to_string());
            }
        }
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Gegen echte UsrClass.dat und SOFTWARE sowie die Ausgabe von RegRipper
    /// `shellbags`: gleiche Einträge und gleiche MRU-Zeitpunkte.
    #[test]
    #[ignore = "benötigt STRATUM_HIVELOG_REFERENCE und STRATUM_SHELLITEM_REFERENCE"]
    fn regripper_referenz() {
        let hives =
            std::path::PathBuf::from(std::env::var_os("STRATUM_HIVELOG_REFERENCE").unwrap());
        let items =
            std::path::PathBuf::from(std::env::var_os("STRATUM_SHELLITEM_REFERENCE").unwrap());
        let usrclass = std::fs::read(hives.join("UsrClass.dat")).unwrap();
        let software_bytes = std::fs::read(hives.join("SOFTWARE")).unwrap();
        let hive = Hive::parse(&usrclass).unwrap();
        let software = Hive::parse(&software_bytes).unwrap();
        let mut names = ClsidNames {
            software: Some(&software),
            cache: HashMap::new(),
        };
        let mut out = Outcome::default();
        let key = hive.open_key(USRCLASS_BAGMRU).unwrap().unwrap();
        Walk {
            user: "ich",
            hive_name: "UsrClass.dat",
            names: &mut names,
            out: &mut out,
        }
        .key(&key, USRCLASS_BAGMRU, "", &[], 0);

        // RegRipper-Zeilen: "MRU-Zeit | ... |Pfad [Desktop\2\1\]".
        let rr = std::fs::read_to_string(items.join("regripper_shellbags.txt")).unwrap();
        let mut erwartet = Vec::new();
        for zeile in rr.lines().filter(|z| z.contains("[Desktop")) {
            let bag = zeile
                .rsplit("[Desktop\\")
                .next()
                .unwrap()
                .trim_end_matches(']')
                .trim_end_matches('\\')
                .to_string();
            let mru = zeile.split('|').next().unwrap().trim().replace(' ', "T");
            erwartet.push((bag, mru));
        }
        assert_eq!(out.findings.len(), erwartet.len());
        for (bag, mru) in &erwartet {
            let f = out
                .findings
                .iter()
                .find(|f| &f.attributes["bagmru"] == bag)
                .unwrap_or_else(|| panic!("{bag} fehlt"));
            match f.attributes.get("zuletzt_verwendet_utc") {
                Some(t) => assert!(t.starts_with(mru.as_str()), "{bag}: {t} statt {mru}"),
                None => assert!(mru.is_empty(), "{bag}: MRU-Zeit {mru} fehlt"),
            }
        }
        for f in &out.findings {
            eprintln!(
                "{:8} {:30} {:?}",
                f.attributes["bagmru"], f.attributes["element_art"], f.name
            );
        }
    }
}
