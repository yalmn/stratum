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

const RUN_KEYS: [&str; 5] = [
    "Microsoft\\Windows\\CurrentVersion\\Run",
    "Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "Microsoft\\Windows\\CurrentVersion\\RunServices",
    "Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
    "Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
];

impl Analyzer for PersistenceAnalyzer {
    fn domain(&self) -> &str {
        "persistence"
    }

    fn run(&self, ctx: &AnalysisContext<'_>) -> Outcome {
        let mut out = Outcome::default();
        for inst in &ctx.installs {
            let before = out.findings.len();
            // HKLM aus dem SOFTWARE-Hive: Run-Schluessel plus Winlogon,
            // AppInit_DLLs und Image File Execution Options.
            if let Some(bytes) = &inst.hives.software {
                match Hive::parse(bytes) {
                    Ok(hive) => {
                        run_keys(&hive, "", "HKLM SOFTWARE", &mut out);
                        winlogon(&hive, &mut out);
                        appinit_dlls(&hive, &mut out);
                        ifeo_debugger(&hive, &mut out);
                    }
                    Err(e) => out.warnings.push(format!("SOFTWARE nicht lesbar: {e}")),
                }
            }
            // SYSTEM-Hive: auffaellige Dienste.
            if let Some(bytes) = &inst.hives.system {
                match Hive::parse(bytes) {
                    Ok(hive) => services(&hive, &mut out),
                    Err(e) => out.warnings.push(format!("SYSTEM nicht lesbar: {e}")),
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

/// Winlogon: `Shell` sollte `explorer.exe`, `Userinit` `...\userinit.exe,` sein.
/// Abweichungen sind ein klassischer Autostart-Missbrauch und werden markiert.
fn winlogon(hive: &Hive, out: &mut Outcome) {
    const PATH: &str = "Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
    let Ok(Some(key)) = hive.open_key(PATH) else {
        return;
    };
    for (name, normal) in [("Shell", "explorer.exe"), ("Userinit", "userinit.exe")] {
        let Some(val) = key.value(name).ok().flatten().and_then(|v| v.as_string()) else {
            continue;
        };
        let auffaellig = !val.to_ascii_lowercase().contains(normal);
        out.findings.push(
            Finding::new("persistence", name, format!("HKLM SOFTWARE\\{PATH}"))
                .with("befehl", val)
                .with("ort", "Winlogon")
                .with("auffaellig", if auffaellig { "ja" } else { "nein" }),
        );
    }
}

/// `AppInit_DLLs` wird in jeden Prozess geladen, der user32.dll nutzt. Ein
/// nicht leerer Wert ist auffällig.
fn appinit_dlls(hive: &Hive, out: &mut Outcome) {
    const PATH: &str = "Microsoft\\Windows NT\\CurrentVersion\\Windows";
    let Ok(Some(key)) = hive.open_key(PATH) else {
        return;
    };
    let Some(val) = key
        .value("AppInit_DLLs")
        .ok()
        .flatten()
        .and_then(|v| v.as_string())
    else {
        return;
    };
    if val.trim().is_empty() {
        return;
    }
    out.findings.push(
        Finding::new(
            "persistence",
            "AppInit_DLLs",
            format!("HKLM SOFTWARE\\{PATH}"),
        )
        .with("befehl", val)
        .with("ort", "AppInit_DLLs")
        .with("auffaellig", "ja"),
    );
}

/// Image File Execution Options: ein `Debugger`-Wert kapert den Start des
/// jeweiligen Programms (auch fuer "Sticky Keys"-artige Hintertueren).
fn ifeo_debugger(hive: &Hive, out: &mut Outcome) {
    const PATH: &str = "Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
    let Ok(Some(root)) = hive.open_key(PATH) else {
        return;
    };
    let Ok(progs) = root.subkeys() else { return };
    for prog in progs {
        let Some(dbg) = prog
            .value("Debugger")
            .ok()
            .flatten()
            .and_then(|v| v.as_string())
        else {
            continue;
        };
        if dbg.trim().is_empty() {
            continue;
        }
        out.findings.push(
            Finding::new(
                "persistence",
                prog.name(),
                format!("HKLM SOFTWARE\\{PATH}\\{}", prog.name()),
            )
            .with("befehl", dbg)
            .with("ort", "IFEO-Debugger")
            .with("auffaellig", "ja"),
        );
    }
}

/// Dienste aus `SYSTEM\{CS}\Services`, deren `ImagePath` in einem für Systemdienste
/// ungewöhnlichen, vom Nutzer beschreibbaren Ort liegt. Die vollständige
/// Dienstliste wäre zu verrauscht; gemeldet wird nur Auffälliges.
fn services(hive: &Hive, out: &mut Outcome) {
    let cs = current_control_set(hive);
    let base = format!("{cs}\\Services");
    let Ok(Some(root)) = hive.open_key(&base) else {
        return;
    };
    let Ok(dienste) = root.subkeys() else { return };
    for dienst in dienste {
        let Some(image) = dienst
            .value("ImagePath")
            .ok()
            .flatten()
            .and_then(|v| v.as_string())
        else {
            continue;
        };
        if !ungewoehnlicher_dienstpfad(&image) {
            continue;
        }
        let start = dienst
            .value("Start")
            .ok()
            .flatten()
            .and_then(|v| v.as_u32());
        let mut f = Finding::new(
            "persistence",
            dienst.name(),
            format!("SYSTEM\\{base}\\{}", dienst.name()),
        )
        .with("befehl", image)
        .with("ort", "Dienst")
        .with("auffaellig", "ja");
        if let Some(s) = start {
            f = f.with("start_typ", s.to_string());
        }
        out.findings.push(f);
    }
}

/// Prüft, ob ein Dienst-`ImagePath` in einem vom Nutzer beschreibbaren oder
/// sonst ungewöhnlichen Ort liegt (statt System32, SysWOW64, drivers, WinSxS).
fn ungewoehnlicher_dienstpfad(image: &str) -> bool {
    let lower = image.to_ascii_lowercase();
    const VERDAECHTIG: [&str; 6] = [
        "\\users\\",
        "\\temp\\",
        "\\appdata\\",
        "\\programdata\\",
        "\\downloads\\",
        "\\public\\",
    ];
    if VERDAECHTIG.iter().any(|p| lower.contains(p)) {
        return true;
    }
    // Dienste ohne Pfad-Referenz auf ein Systemverzeichnis, die aber eine
    // ausführbare Datei starten, sind ebenfalls einen Blick wert.
    let system = [
        "\\windows\\system32",
        "\\windows\\syswow64",
        "\\windows\\",
        "\\systemroot",
    ];
    (lower.contains(".exe") || lower.contains(".dll")) && !system.iter().any(|p| lower.contains(p))
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
            mounted_devices(&hive, &mut out);
            for (user, ubytes) in &inst.ntuser {
                if let Ok(uhive) = Hive::parse(ubytes) {
                    mount_points2(&uhive, user, &mut out);
                }
            }
            out.tag_origin(before, &inst.origin);
        }
        out
    }
}

/// `MountedDevices` (SYSTEM-Wurzel): ordnet Laufwerksbuchstaben und Volumes den
/// Geräten zu. Für Wechseldatenträger enthält der Wert eine Textreferenz auf das
/// USBSTOR-Gerät; nur solche werden gemeldet (Festplatten sind reine Signaturen).
fn mounted_devices(hive: &Hive, out: &mut Outcome) {
    let Ok(Some(key)) = hive.open_key("MountedDevices") else {
        return;
    };
    let Ok(values) = key.values() else { return };
    for v in values {
        let text = utf16_prefix_lossy(v.data());
        let up = text.to_ascii_uppercase();
        if !(up.contains("USBSTOR") || up.contains("USB#")) {
            continue;
        }
        out.findings.push(
            Finding::new("usb", v.name(), "SYSTEM\\MountedDevices")
                .with("art", "mounted_device")
                .with(
                    "geraet",
                    text.trim_matches(|c: char| c.is_control()).to_string(),
                ),
        );
    }
}

/// `MountPoints2` (NTUSER): Volumes und Netzlaufwerke, die der Benutzer
/// eingebunden hat. Die Unterschlüsselnamen sind Volume-GUIDs, Laufwerks-
/// buchstaben oder `##server#share`; die Änderungszeit gibt den letzten Zugriff.
fn mount_points2(hive: &Hive, user: &str, out: &mut Outcome) {
    const PATH: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2";
    let Ok(Some(key)) = hive.open_key(PATH) else {
        return;
    };
    let Ok(subs) = key.subkeys() else { return };
    for s in subs {
        let name = s.name();
        // CPC/Steuer-Unterschlüssel überspringen.
        if name.eq_ignore_ascii_case("CPC") || name.is_empty() {
            continue;
        }
        let mut f = Finding::new("usb", name, format!("HKCU {user}\\MountPoints2"))
            .with("art", "mount_point")
            .with("benutzer", user);
        if let Some(z) = ft_unix(s.last_written()) {
            f = f.with("letzter_zugriff_unix", z.to_string());
        }
        out.findings.push(f);
    }
}

/// Wie [`utf16_prefix`], aber ersetzt keine Datenreste und liefert auch bei
/// eingebetteten Nullen brauchbaren Text (für MountedDevices-Werte).
fn utf16_prefix_lossy(data: &[u8]) -> String {
    let units: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .filter(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
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
                        last_visited_mru(&hive, user, &mut out);
                        opensave_mru(&hive, user, &mut out);
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

/// Öffnen-/Speichern-Dialog: `ComDlg32\LastVisitedPidlMRU` (und die ältere
/// `LastVisitedMRU`). Jeder Wert beginnt mit dem Namen des Programms, mit dem
/// eine Datei geöffnet oder gespeichert wurde, als UTF-16LE.
fn last_visited_mru(hive: &Hive, user: &str, out: &mut Outcome) {
    for key_name in ["LastVisitedPidlMRU", "LastVisitedMRU"] {
        let path = format!("{EXPLORER}\\ComDlg32\\{key_name}");
        let Ok(Some(key)) = hive.open_key(&path) else {
            continue;
        };
        let Ok(values) = key.values() else { continue };
        let zeit = ft_unix(key.last_written());
        for v in values {
            if v.name().eq_ignore_ascii_case("MRUListEx") {
                continue;
            }
            let prog = utf16_prefix(v.data());
            if prog.is_empty() {
                continue;
            }
            let mut f = Finding::new(
                "useraktivitaet",
                prog,
                format!("HKCU {user}\\ComDlg32\\{key_name}"),
            )
            .with("art", "dialog_programm")
            .with("benutzer", user);
            if let Some(z) = zeit {
                f = f.with("key_letzte_aenderung_unix", z.to_string());
            }
            out.findings.push(f);
        }
    }
}

/// Öffnen-/Speichern-Dialog: `ComDlg32\OpenSavePidlMRU`. Je Endung ein
/// Unterschlüssel, dessen Werte reine PIDLs (ITEMIDLIST) sind. Aus dem letzten
/// Shell-Element wird der Dateiname gelesen.
fn opensave_mru(hive: &Hive, user: &str, out: &mut Outcome) {
    const PATH: &str =
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU";
    let Ok(Some(root)) = hive.open_key(PATH) else {
        return;
    };
    let Ok(exts) = root.subkeys() else { return };
    for ext in exts {
        let Ok(values) = ext.values() else { continue };
        let zeit = ft_unix(ext.last_written());
        for v in values {
            if v.name().eq_ignore_ascii_case("MRUListEx") {
                continue;
            }
            let Some(name) = pidl_last_name(v.data()) else {
                continue;
            };
            let mut f = Finding::new(
                "useraktivitaet",
                name,
                format!("HKCU {user}\\OpenSavePidlMRU\\{}", ext.name()),
            )
            .with("art", "dialog_datei")
            .with("benutzer", user);
            if let Some(z) = zeit {
                f = f.with("key_letzte_aenderung_unix", z.to_string());
            }
            out.findings.push(f);
        }
    }
}

/// Liest den Dateinamen aus dem letzten Element einer PIDL (ITEMIDLIST). Bevorzugt
/// den Unicode-Langnamen aus dem `0xBEEF0004`-Erweiterungsblock, sonst den
/// ANSI-Namen des Shell-Elements. `None`, wenn nichts Brauchbares gefunden wird.
fn pidl_last_name(pidl: &[u8]) -> Option<String> {
    // SHITEMID-Kette ablaufen und das letzte nicht-leere Element behalten.
    let mut pos = 0usize;
    let mut last: Option<&[u8]> = None;
    while pos + 2 <= pidl.len() {
        let size = u16::from_le_bytes([pidl[pos], pidl[pos + 1]]) as usize;
        if size < 2 {
            break; // Abschluss (cb == 0)
        }
        let end = pos + size;
        if end > pidl.len() {
            break;
        }
        last = Some(&pidl[pos..end]);
        pos = end;
    }
    let item = last?;

    // Unicode-Langname aus dem BEEF0004-Block (Signatur 04 00 EF BE).
    if let Some(name) = beef_long_name(item) {
        return Some(name);
    }
    // Fallback: ANSI-Name eines Datei-/Ordner-Elements ab Offset 14.
    if item.len() > 14 && matches!(item.get(2), Some(0x31 | 0x32 | 0xb1 | 0x35 | 0x36)) {
        let ansi: Vec<u8> = item[14..].iter().copied().take_while(|&c| c != 0).collect();
        if !ansi.is_empty() {
            return Some(String::from_utf8_lossy(&ansi).into_owned());
        }
    }
    None
}

/// Sucht im Shell-Element den `0xBEEF0004`-Block und liest daraus den ersten
/// null-terminierten UTF-16LE-Namen (den Langnamen der Datei).
fn beef_long_name(item: &[u8]) -> Option<String> {
    let sig = [0x04, 0x00, 0xEF, 0xBE];
    let mut p = None;
    for i in 0..item.len().saturating_sub(4) {
        if item[i..i + 4] == sig {
            p = Some(i);
            break;
        }
    }
    let sig_pos = p?;
    // Nach der Signatur folgen versionsabhängige Festfelder, dann der Unicode-
    // Name. Ab der Signatur an geraden Offsets die erste plausible
    // UTF-16-Zeichenkette suchen (Buchstabe, Ziffer oder Punkt am Anfang).
    let after = sig_pos + 4;
    let mut off = after;
    while off + 2 <= item.len() {
        let u = u16::from_le_bytes([item[off], item[off + 1]]);
        let c = char::from_u32(u as u32);
        let plausibel = c
            .map(|c| c.is_alphanumeric() || matches!(c, '.' | '_' | '-' | '~' | ' '))
            .unwrap_or(false);
        if plausibel {
            let units: Vec<u16> = item[off..]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .take_while(|&u| u != 0)
                .collect();
            if units.len() >= 2 {
                let s = String::from_utf16_lossy(&units);
                if s.chars().any(|c| c.is_alphanumeric()) {
                    return Some(s);
                }
            }
        }
        off += 2;
    }
    None
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
    fn pidl_langname_aus_beef() {
        // Ein Datei-Shell-Element mit ANSI-Kurzname und BEEF0004-Langname.
        let mut item = Vec::new();
        let name_ansi = b"GEHEIM~1.DOC\0";
        let long: Vec<u8> = "Geheim Bericht.docx"
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect();
        // Kopf: size(2, spaeter), type=0x32, unbekannt, groesse, datum, zeit, attr
        let mut body = vec![0x32, 0x00];
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(name_ansi); // ANSI ab Offset 14
                                           // BEEF0004-Block
        body.extend_from_slice(&[0x2c, 0x00]); // BlockSize
        body.extend_from_slice(&[0x09, 0x00]); // Version
        body.extend_from_slice(&[0x04, 0x00, 0xEF, 0xBE]); // Signatur
        body.extend_from_slice(&[0u8; 16]); // Festfelder (Datum etc.)
        body.extend_from_slice(&long); // Unicode-Langname
        let size = (body.len() + 2) as u16;
        item.extend_from_slice(&size.to_le_bytes());
        item.extend_from_slice(&body);
        // PIDL: dieses Element + Abschluss (cb=0).
        let mut pidl = item.clone();
        pidl.extend_from_slice(&[0, 0]);

        assert_eq!(
            pidl_last_name(&pidl).as_deref(),
            Some("Geheim Bericht.docx")
        );
    }

    #[test]
    fn pidl_ansi_fallback() {
        // Element ohne BEEF-Block: ANSI-Name ab Offset 14 (Typ@2, Unbekannt@3,
        // dann Groesse/Datum/Zeit/Attribute = 10 Byte, dann der Name).
        let mut body = vec![0x32, 0x00];
        body.extend_from_slice(&[0u8; 10]);
        body.extend_from_slice(b"datei.txt\0");
        let size = (body.len() + 2) as u16;
        let mut pidl = size.to_le_bytes().to_vec();
        pidl.extend_from_slice(&body);
        pidl.extend_from_slice(&[0, 0]);
        assert_eq!(pidl_last_name(&pidl).as_deref(), Some("datei.txt"));
    }

    #[test]
    fn dienstpfad_bewertung() {
        assert!(ungewoehnlicher_dienstpfad(
            "C:\\Users\\ich\\AppData\\Local\\Temp\\svc.exe"
        ));
        assert!(ungewoehnlicher_dienstpfad("C:\\ProgramData\\x\\run.exe"));
        assert!(ungewoehnlicher_dienstpfad("D:\\tools\\agent.exe"));
        assert!(!ungewoehnlicher_dienstpfad(
            "\\SystemRoot\\System32\\drivers\\disk.sys"
        ));
        assert!(!ungewoehnlicher_dienstpfad(
            "C:\\Windows\\System32\\svchost.exe -k netsvcs"
        ));
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
