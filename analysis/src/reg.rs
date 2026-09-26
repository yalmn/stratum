//! Registry-basierte Domänen: Autostart (Persistence), USB-Geräte und
//! Benutzeraktivität.
//!
//! Diese Analyzer lesen ausschliesslich die bereits im Kontext vorliegenden
//! Hives (SOFTWARE, SYSTEM je Installation und NTUSER.DAT je Benutzer) und
//! brauchen keinen Dateizugriff mehr. Damit sind sie sehr schnell.

use stratum_registry::Hive;

use crate::{AnalysisContext, Analyzer, Finding, Outcome};

// Persistence (Autostart)

/// Findet Autostart-Einträge in den Run-/RunOnce-Schlüsseln (HKLM und HKCU).
pub struct PersistenceAnalyzer;

const RUN_KEYS: [&str; 2] = [
    "Microsoft\\Windows\\CurrentVersion\\Run",
    "Microsoft\\Windows\\CurrentVersion\\RunOnce",
];

impl Analyzer for PersistenceAnalyzer {
    fn domain(&self) -> &str {
        "persistence"
    }

    fn run(&self, ctx: &AnalysisContext<'_>) -> Outcome {
        let mut out = Outcome::default();
        for inst in &ctx.installs {
            let before = out.findings.len();
            // HKLM aus dem SOFTWARE-Hive.
            if let Some(bytes) = &inst.hives.software {
                match Hive::parse(bytes) {
                    Ok(hive) => run_keys(&hive, "", "HKLM SOFTWARE", &mut out),
                    Err(e) => out.warnings.push(format!("SOFTWARE nicht lesbar: {e}")),
                }
            }
            // HKCU aus jeder NTUSER.DAT.
            for (user, bytes) in &inst.ntuser {
                match Hive::parse(bytes) {
                    Ok(hive) => run_keys(&hive, "Software\\", &format!("HKCU {user}"), &mut out),
                    Err(e) => out
                        .warnings
                        .push(format!("NTUSER von {user} nicht lesbar: {e}")),
                }
            }
            out.tag_origin(before, &inst.origin);
        }
        out
    }
}

fn run_keys(hive: &Hive, prefix: &str, ort: &str, out: &mut Outcome) {
    for suffix in RUN_KEYS {
        let path = format!("{prefix}{suffix}");
        let Ok(Some(key)) = hive.open_key(&path) else {
            continue;
        };
        let Ok(values) = key.values() else { continue };
        for v in values {
            let name = v.name();
            if name.is_empty() {
                continue;
            }
            let cmd = v.as_string().unwrap_or_default();
            out.findings.push(
                Finding::new("persistence", name, format!("{ort}\\{suffix}"))
                    .with("befehl", cmd)
                    .with("ort", ort),
            );
        }
    }
}

// USB-Geräte

/// Listet die je angeschlossenen USB-Massenspeicher aus `Enum\USBSTOR`.
pub struct UsbAnalyzer;

impl Analyzer for UsbAnalyzer {
    fn domain(&self) -> &str {
        "usb"
    }

    fn run(&self, ctx: &AnalysisContext<'_>) -> Outcome {
        let mut out = Outcome::default();
        for inst in &ctx.installs {
            let before = out.findings.len();
            let Some(bytes) = &inst.hives.system else {
                continue;
            };
            let hive = match Hive::parse(bytes) {
                Ok(h) => h,
                Err(e) => {
                    out.warnings.push(format!("SYSTEM nicht lesbar: {e}"));
                    continue;
                }
            };
            let cs = current_control_set(&hive);
            let base = format!("{cs}\\Enum\\USBSTOR");
            let Ok(Some(usbstor)) = hive.open_key(&base) else {
                continue;
            };
            let Ok(devices) = usbstor.subkeys() else {
                continue;
            };
            for dev in devices {
                let Ok(instances) = dev.subkeys() else {
                    continue;
                };
                for inst_key in instances {
                    let friendly = inst_key
                        .value("FriendlyName")
                        .ok()
                        .flatten()
                        .and_then(|v| v.as_string())
                        .unwrap_or_else(|| dev.name().to_string());
                    out.findings.push(
                        Finding::new(
                            "usb",
                            friendly,
                            format!("SYSTEM\\{base}\\{}\\{}", dev.name(), inst_key.name()),
                        )
                        .with("geraet", dev.name())
                        .with("seriennummer", inst_key.name()),
                    );
                }
            }
            out.tag_origin(before, &inst.origin);
        }
        out
    }
}

// Programmausführung: BAM/DAM

/// Liest die letzten Ausführungszeiten je Programm aus dem Background/Desktop
/// Activity Moderator (`Services\bam` bzw. `dam`) im SYSTEM-Hive. Die Werte je
/// Benutzer-SID tragen als Namen den Programmpfad, die ersten 8 Byte sind eine
/// FILETIME der letzten Ausführung.
pub struct BamAnalyzer;

impl Analyzer for BamAnalyzer {
    fn domain(&self) -> &str {
        "programmausfuehrung"
    }

    fn run(&self, ctx: &AnalysisContext<'_>) -> Outcome {
        let mut out = Outcome::default();
        for inst in &ctx.installs {
            let before = out.findings.len();
            let Some(bytes) = &inst.hives.system else {
                continue;
            };
            let hive = match Hive::parse(bytes) {
                Ok(h) => h,
                Err(e) => {
                    out.warnings.push(format!("SYSTEM nicht lesbar: {e}"));
                    continue;
                }
            };
            let cs = current_control_set(&hive);
            for dienst in ["bam", "dam"] {
                // Windows 10 ab 1809 hat die Ebene "State"; ältere nicht.
                for zwischen in ["State\\UserSettings", "UserSettings"] {
                    let base = format!("{cs}\\Services\\{dienst}\\{zwischen}");
                    let Ok(Some(us)) = hive.open_key(&base) else {
                        continue;
                    };
                    let Ok(sids) = us.subkeys() else { continue };
                    for sid in sids {
                        bam_entries(&sid, &base, dienst, &mut out);
                    }
                }
            }
            out.tag_origin(before, &inst.origin);
        }
        out
    }
}

fn bam_entries(
    sid_key: &stratum_registry::Key<'_, '_>,
    base: &str,
    dienst: &str,
    out: &mut Outcome,
) {
    let sid = sid_key.name();
    let Ok(values) = sid_key.values() else { return };
    for v in values {
        let name = v.name();
        // Nur Werte, die wie ein Programmpfad aussehen (Geräte- oder Laufwerkspfad).
        if !(name.starts_with("\\Device\\") || name.contains(":\\")) {
            continue;
        }
        let data = v.data();
        if data.len() < 8 {
            continue;
        }
        let ft = u64::from_le_bytes(data[..8].try_into().unwrap());
        let mut f = Finding::new(
            "programmausfuehrung",
            name,
            format!("SYSTEM\\{base}\\{sid}"),
        )
        .with("art", if dienst == "bam" { "bam" } else { "dam" })
        .with("sid", sid);
        if let Some(z) = ft_unix(ft) {
            f = f.with("letzte_ausfuehrung_unix", z.to_string());
        }
        out.findings.push(f);
    }
}

// Benutzeraktivität

/// Wertet je Benutzer TypedURLs und UserAssist aus der NTUSER.DAT aus.
pub struct UserActivityAnalyzer;

const TYPED_URLS: &str = "Software\\Microsoft\\Internet Explorer\\TypedURLs";
const USERASSIST: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist";
const EXPLORER: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer";

impl Analyzer for UserActivityAnalyzer {
    fn domain(&self) -> &str {
        "useraktivitaet"
    }

    fn run(&self, ctx: &AnalysisContext<'_>) -> Outcome {
        let mut out = Outcome::default();
        for inst in &ctx.installs {
            let before = out.findings.len();
            for (user, bytes) in &inst.ntuser {
                match Hive::parse(bytes) {
                    Ok(hive) => {
                        typed_urls(&hive, user, &mut out);
                        userassist(&hive, user, &mut out);
                        run_mru(&hive, user, &mut out);
                        typed_paths(&hive, user, &mut out);
                        word_wheel(&hive, user, &mut out);
                        recent_docs(&hive, user, &mut out);
                    }
                    Err(e) => out
                        .warnings
                        .push(format!("NTUSER von {user} nicht lesbar: {e}")),
                }
            }
            out.tag_origin(before, &inst.origin);
        }
        out
    }
}

fn typed_urls(hive: &Hive, user: &str, out: &mut Outcome) {
    let Ok(Some(key)) = hive.open_key(TYPED_URLS) else {
        return;
    };
    let Ok(values) = key.values() else { return };
    for v in values {
        if let Some(url) = v.as_string() {
            if !url.is_empty() {
                out.findings.push(
                    Finding::new("useraktivitaet", url, format!("HKCU {user}\\TypedURLs"))
                        .with("art", "typed_url")
                        .with("benutzer", user),
                );
            }
        }
    }
}

fn userassist(hive: &Hive, user: &str, out: &mut Outcome) {
    let Ok(Some(root)) = hive.open_key(USERASSIST) else {
        return;
    };
    let Ok(guids) = root.subkeys() else { return };
    for guid in guids {
        let Ok(Some(count)) = guid.subkey("Count") else {
            continue;
        };
        let Ok(values) = count.values() else { continue };
        for v in values {
            let name = rot13(v.name());
            if name.is_empty() {
                continue;
            }
            out.findings.push(
                Finding::new("useraktivitaet", name, format!("HKCU {user}\\UserAssist"))
                    .with("art", "userassist")
                    .with("benutzer", user),
            );
        }
    }
}

/// Ausführen-Dialog: `Explorer\RunMRU`. Jeder Wert (ausser `MRUList`) ist ein
/// eingegebener Befehl, der mit `\1` endet.
fn run_mru(hive: &Hive, user: &str, out: &mut Outcome) {
    let path = format!("{EXPLORER}\\RunMRU");
    let Ok(Some(key)) = hive.open_key(&path) else {
        return;
    };
    let Ok(values) = key.values() else { return };
    let zeit = ft_unix(key.last_written());
    for v in values {
        if v.name().eq_ignore_ascii_case("MRUList") {
            continue;
        }
        let Some(cmd) = v.as_string() else { continue };
        let cmd = cmd.trim_end_matches("\\1").trim_end_matches('\\');
        if cmd.is_empty() {
            continue;
        }
        let mut f = Finding::new("useraktivitaet", cmd, format!("HKCU {user}\\RunMRU"))
            .with("art", "run_mru")
            .with("benutzer", user);
        if let Some(z) = zeit {
            f = f.with("key_letzte_aenderung_unix", z.to_string());
        }
        out.findings.push(f);
    }
}

/// Explorer-Adressleiste: `Explorer\TypedPaths` (Werte `url1`, `url2`, ...).
fn typed_paths(hive: &Hive, user: &str, out: &mut Outcome) {
    let path = format!("{EXPLORER}\\TypedPaths");
    let Ok(Some(key)) = hive.open_key(&path) else {
        return;
    };
    let Ok(values) = key.values() else { return };
    for v in values {
        let Some(p) = v.as_string() else { continue };
        if p.is_empty() {
            continue;
        }
        out.findings.push(
            Finding::new("useraktivitaet", p, format!("HKCU {user}\\TypedPaths"))
                .with("art", "typed_path")
                .with("benutzer", user),
        );
    }
}

/// Explorer-Suche: `Explorer\WordWheelQuery`. Werte sind nach `MRUListEx`
/// nummeriert und enthalten den Suchbegriff als UTF-16LE.
fn word_wheel(hive: &Hive, user: &str, out: &mut Outcome) {
    let path = format!("{EXPLORER}\\WordWheelQuery");
    let Ok(Some(key)) = hive.open_key(&path) else {
        return;
    };
    let Ok(values) = key.values() else { return };
    let zeit = ft_unix(key.last_written());
    for v in values {
        if v.name().eq_ignore_ascii_case("MRUListEx") {
            continue;
        }
        let term = utf16_prefix(v.data());
        if term.is_empty() {
            continue;
        }
        let mut f = Finding::new(
            "useraktivitaet",
            term,
            format!("HKCU {user}\\WordWheelQuery"),
        )
        .with("art", "explorer_suche")
        .with("benutzer", user);
        if let Some(z) = zeit {
            f = f.with("key_letzte_aenderung_unix", z.to_string());
        }
        out.findings.push(f);
    }
}

/// Zuletzt geöffnete Dateien: `Explorer\RecentDocs` und die Unterschlüssel je
/// Endung. Die Werte beginnen mit dem Dateinamen als UTF-16LE.
fn recent_docs(hive: &Hive, user: &str, out: &mut Outcome) {
    let base = format!("{EXPLORER}\\RecentDocs");
    let Ok(Some(root)) = hive.open_key(&base) else {
        return;
    };
    // Der Wurzelschlüssel und jeder Endungs-Unterschlüssel tragen Einträge.
    let mut keys = vec![(root.clone(), "RecentDocs".to_string())];
    if let Ok(subs) = root.subkeys() {
        for s in subs {
            let label = format!("RecentDocs\\{}", s.name());
            keys.push((s, label));
        }
    }
    for (key, label) in keys {
        let Ok(values) = key.values() else { continue };
        let zeit = ft_unix(key.last_written());
        for v in values {
            let n = v.name();
            if n.eq_ignore_ascii_case("MRUListEx") || n.is_empty() {
                continue;
            }
            let name = utf16_prefix(v.data());
            if name.is_empty() {
                continue;
            }
            let mut f = Finding::new("useraktivitaet", name, format!("HKCU {user}\\{label}"))
                .with("art", "recent_doc")
                .with("benutzer", user);
            if let Some(z) = zeit {
                f = f.with("key_letzte_aenderung_unix", z.to_string());
            }
            out.findings.push(f);
        }
    }
}

/// Liest eine führende UTF-16LE-Zeichenkette (bis zur Doppel-Null) aus Rohdaten.
fn utf16_prefix(data: &[u8]) -> String {
    let units: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

/// FILETIME (100-ns seit 1601) in Unix-Sekunden, oder `None` bei 0.
fn ft_unix(ft: u64) -> Option<i64> {
    if ft == 0 {
        return None;
    }
    stratum_registry::filetime_to_unix(ft).map(|(s, _)| s)
}

/// Bestimmt das aktive ControlSet eines SYSTEM-Hives, z. B. "ControlSet001".
fn current_control_set(system: &Hive) -> String {
    let n = system
        .open_key("Select")
        .ok()
        .flatten()
        .and_then(|k| k.value("Current").ok().flatten())
        .and_then(|v| v.as_u32())
        .unwrap_or(1);
    format!("ControlSet{n:03}")
}

/// ROT13, wie UserAssist die Programmpfade verschleiert. Nur ASCII-Buchstaben
/// werden verschoben.
fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' => (((c as u8 - b'a' + 13) % 26) + b'a') as char,
            'A'..='Z' => (((c as u8 - b'A' + 13) % 26) + b'A') as char,
            _ => c,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::HiveBuilder;
    use crate::context::AnalysisContext;
    use crate::windows::{Hives, WindowsInstall};
    use crate::NtfsTarget;

    const REG_SZ: u32 = 1;

    fn utf16z(s: &str) -> Vec<u8> {
        s.encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect()
    }

    #[test]
    fn rot13_hin_und_zurueck() {
        assert_eq!(rot13("Hallo"), "Unyyb");
        assert_eq!(rot13(&rot13("C:\\prog.exe")), "C:\\prog.exe");
    }

    // Baut einen Kontext mit einem Install, dessen Hive-Bytes vorgegeben sind.
    fn ctx_with(img: &stratum_core::ImageReader, inst: WindowsInstall) -> AnalysisContext<'_> {
        let mut c = AnalysisContext::new(img, vec![]);
        c.installs = vec![inst];
        c
    }

    fn dummy_img() -> (tempfile::NamedTempFile, stratum_core::ImageReader) {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(&[0u8; 512]).unwrap();
        f.flush().unwrap();
        let img = stratum_core::ImageReader::open(f.path()).unwrap();
        (f, img)
    }

    #[test]
    fn persistence_hklm_run() {
        // SOFTWARE-Hive mit Microsoft\Windows\CurrentVersion\Run\Updater.
        let mut b = HiveBuilder::new();
        let updater = b.vk("Updater", REG_SZ, &utf16z("C:\\evil.exe"));
        let run = b.key("Run", None, &[updater]);
        let cv_list = b.lh(&[run]);
        let cv = b.key_with_list("CurrentVersion", cv_list, 1, &[]);
        let win_list = b.lh(&[cv]);
        let win = b.key_with_list("Windows", win_list, 1, &[]);
        let ms_list = b.lh(&[win]);
        let ms = b.key_with_list("Microsoft", ms_list, 1, &[]);
        let root_list = b.lh(&[ms]);
        let root = b.key_with_list("ROOT", root_list, 1, &[]);
        let software = b.finish(root);

        let inst = WindowsInstall {
            origin: "live".into(),
            target: NtfsTarget {
                index: 0,
                offset: 0,
                size: 0,
            },
            hives: Hives {
                software: Some(software),
                ..Default::default()
            },
            computer_name: None,
            timezone: None,
            accounts: vec![],
            ntuser: vec![],
            warnings: vec![],
        };
        let (_f, img) = dummy_img();
        let ctx = ctx_with(&img, inst);
        let out = PersistenceAnalyzer.run(&ctx);
        assert_eq!(out.findings.len(), 1);
        let f = &out.findings[0];
        assert_eq!(f.domain, "persistence");
        assert_eq!(f.name, "Updater");
        assert_eq!(
            f.attributes.get("befehl").map(String::as_str),
            Some("C:\\evil.exe")
        );
    }

    #[test]
    fn utf16_prefix_bis_doppelnull() {
        // "abc" UTF-16LE + Doppel-Null + Rest (PIDL-Bytes).
        let mut d = utf16z("abc");
        d.extend_from_slice(&[0x14, 0x00, 0xff]);
        assert_eq!(utf16_prefix(&d), "abc");
    }

    #[test]
    fn recentdocs_liest_dateiname() {
        // RecentDocs\.txt mit einem Wert "0" = "brief.txt\0\0" + PIDL-Rest.
        let mut val = utf16z("brief.txt");
        val.extend_from_slice(&[0x30, 0x00, 0x01, 0x02]); // PIDL-Rest
        let mut b = HiveBuilder::new();
        let v0 = b.vk("0", 3, &val); // REG_BINARY
        let txt = b.key(".txt", None, &[v0]);
        let rd_list = b.lh(&[txt]);
        let rd = b.key_with_list("RecentDocs", rd_list, 1, &[]);
        let ex_list = b.lh(&[rd]);
        let ex = b.key_with_list("Explorer", ex_list, 1, &[]);
        let cv_list = b.lh(&[ex]);
        let cv = b.key_with_list("CurrentVersion", cv_list, 1, &[]);
        let win_list = b.lh(&[cv]);
        let win = b.key_with_list("Windows", win_list, 1, &[]);
        let ms_list = b.lh(&[win]);
        let ms = b.key_with_list("Microsoft", ms_list, 1, &[]);
        let sw_list = b.lh(&[ms]);
        let sw = b.key_with_list("Software", sw_list, 1, &[]);
        let root_list = b.lh(&[sw]);
        let root = b.key_with_list("ROOT", root_list, 1, &[]);
        let ntuser = b.finish(root);

        let hive = Hive::parse(&ntuser).unwrap();
        let mut out = Outcome::default();
        recent_docs(&hive, "alice", &mut out);
        assert!(out.findings.iter().any(|f| f.name == "brief.txt"
            && f.attributes.get("art").map(String::as_str) == Some("recent_doc")));
    }

    #[test]
    fn useractivity_typed_url() {
        let mut b = HiveBuilder::new();
        let url1 = b.vk("url1", REG_SZ, &utf16z("http://beispiel.tld/"));
        let typed = b.key("TypedURLs", None, &[url1]);
        let ie_list = b.lh(&[typed]);
        let ie = b.key_with_list("Internet Explorer", ie_list, 1, &[]);
        let ms_list = b.lh(&[ie]);
        let ms = b.key_with_list("Microsoft", ms_list, 1, &[]);
        let sw_list = b.lh(&[ms]);
        let sw = b.key_with_list("Software", sw_list, 1, &[]);
        let root_list = b.lh(&[sw]);
        let root = b.key_with_list("ROOT", root_list, 1, &[]);
        let ntuser = b.finish(root);

        let inst = WindowsInstall {
            origin: "live".into(),
            target: NtfsTarget {
                index: 0,
                offset: 0,
                size: 0,
            },
            hives: Hives::default(),
            computer_name: None,
            timezone: None,
            accounts: vec![],
            ntuser: vec![("alice".into(), ntuser)],
            warnings: vec![],
        };
        let (_f, img) = dummy_img();
        let ctx = ctx_with(&img, inst);
        let out = UserActivityAnalyzer.run(&ctx);
        assert!(out.findings.iter().any(|f| f.name == "http://beispiel.tld/"
            && f.attributes.get("art").map(String::as_str) == Some("typed_url")));
    }
}
