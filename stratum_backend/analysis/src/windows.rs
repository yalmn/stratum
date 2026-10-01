//! Windows-Grunddaten je NTFS-Partition: Registry-Hives extrahieren, daraus
//! Zeitzone, Rechnername und lokale Konten ableiten.
//!
//! Diese Grunddaten werden einmalig beim Aufbau des [`AnalysisContext`] geleistet
//! und stehen allen Analyzern zur Verfügung. Die Zeitzone ist besonders wichtig,
//! weil jede zeitbasierte Domäne sie zur Deutung von Zeitstempeln braucht (nie
//! die Systemzeit des Analyserechners annehmen).
//!
//! [`AnalysisContext`]: crate::AnalysisContext

use serde::Serialize;

use stratum_core::ImageReader;
use stratum_creds::{extract_local_accounts, Account};
use stratum_ntfs::NtfsVolume;
use stratum_registry::{recover, Hive, LogFormat, Recovery, TransactionLog};

use crate::context::NtfsTarget;

const SYSTEM_PATH: &str = "Windows/System32/config/SYSTEM";
const SAM_PATH: &str = "Windows/System32/config/SAM";
const SOFTWARE_PATH: &str = "Windows/System32/config/SOFTWARE";
const SECURITY_PATH: &str = "Windows/System32/config/SECURITY";
const AMCACHE_PATH: &str = "Windows/AppCompat/Programs/Amcache.hve";

/// Extrahierte Hive-Rohdaten einer Installation.
#[derive(Debug, Default)]
pub struct Hives {
    /// SYSTEM-Hive.
    pub system: Option<Vec<u8>>,
    /// SAM-Hive.
    pub sam: Option<Vec<u8>>,
    /// SOFTWARE-Hive.
    pub software: Option<Vec<u8>>,
    /// SECURITY-Hive.
    pub security: Option<Vec<u8>>,
    /// Amcache-Hive (`Windows\AppCompat\Programs\Amcache.hve`).
    pub amcache: Option<Vec<u8>>,
}

/// Zeitzone laut Registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TimeZone {
    /// Name des Zeitzonen-Schlüssels, z. B. "W. Europe Standard Time".
    pub key_name: String,
    /// Aktiver Zeitversatz zu UTC in Minuten (aus ActiveTimeBias).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_bias_minutes: Option<i32>,
}

/// Zustand einer Transaktionslogdatei.
#[derive(Debug, Clone, Serialize)]
pub struct LogStatus {
    /// Dateiname, z. B. `SYSTEM.LOG1`.
    pub datei: String,
    /// Größe in Byte.
    pub groesse: u64,
    /// `neu`, `alt_nicht_unterstuetzt`, `leer` oder `ungueltig`.
    pub format: &'static str,
    /// Lesbare Logeinträge (auch bereits eingespielte).
    pub eintraege: usize,
    /// Einträge mit falscher Marvin-Prüfsumme.
    pub hash_fehler: usize,
    /// Sequenzbereich der Einträge, z. B. `380..384`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequenzen: Option<String>,
}

/// Zustand eines Hives nach der Prüfung gegen seine Transaktionslogs.
#[derive(Debug, Clone, Serialize)]
pub struct HiveStatus {
    /// Kurzname, z. B. `SYSTEM` oder `NTUSER.DAT (alice)`.
    pub name: String,
    /// Pfad im Volume.
    pub pfad: String,
    /// `sauber`, `wiederhergestellt` oder `unsauber_nicht_wiederhergestellt`.
    pub zustand: &'static str,
    /// Sequenznummern und Prüfsumme des Kopfs im Image.
    pub sequenz_primaer: u32,
    /// Siehe `sequenz_primaer`.
    pub sequenz_sekundaer: u32,
    /// Prüfsumme des Kopfs im Image stimmt.
    pub pruefsumme_ok: bool,
    /// Eingespielte Abschnitte, z. B. `SYSTEM.LOG1: 390..391`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub eingespielt: Vec<String>,
    /// Einträge, die neuer als ein sauberer Hive sind; Windows spielt sie
    /// ebenfalls nicht ein.
    #[serde(skip_serializing_if = "is_zero")]
    pub neuere_eintraege_ignoriert: usize,
    /// Grund, falls ein unsauberer Hive nicht wiederhergestellt werden konnte.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grund: Option<&'static str>,
    /// Geprüfte Logdateien.
    pub logs: Vec<LogStatus>,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

/// Eine Windows-Installation auf einer NTFS-Partition mitsamt Grunddaten.
pub struct WindowsInstall {
    /// Herkunft des Volumes: `"live"` oder z. B. `"VSS#1 (2021-01-01)"`.
    pub origin: String,
    /// Partition, auf der die Installation liegt.
    pub target: NtfsTarget,
    /// Extrahierte Hives.
    pub hives: Hives,
    /// Rechnername.
    pub computer_name: Option<String>,
    /// Zeitzone (für alle zeitbasierten Analyzer).
    pub timezone: Option<TimeZone>,
    /// Lokale Konten mit NT-Hash.
    pub accounts: Vec<Account>,
    /// NTUSER.DAT je Benutzer (Benutzername, Rohbytes) für HKCU-basierte
    /// Analyzer.
    pub ntuser: Vec<(String, Vec<u8>)>,
    /// UsrClass.dat je Benutzer (Benutzername, Rohbytes), etwa für ShellBags.
    pub usrclass: Vec<(String, Vec<u8>)>,
    /// ANSI-Codepage des Systems laut `Control\Nls\CodePage\ACP`, z. B. `1252`.
    pub ansi_codepage: Option<String>,
    /// Zustand der geladenen Hives und ihrer Transaktionslogs.
    pub hive_status: Vec<HiveStatus>,
    /// Auffälligkeiten beim Aufbau.
    pub warnings: Vec<String>,
}

/// Sucht auf jedem NTFS-Bereich eine Windows-Installation und baut die
/// Grunddaten auf. Bereiche ohne Windows (kein SYSTEM-Hive) liefern keinen
/// Eintrag.
pub fn extract_installs(img: &ImageReader, targets: &[NtfsTarget]) -> Vec<WindowsInstall> {
    let mut out = Vec::new();
    for &target in targets {
        match extract_one(img, target) {
            Ok(Some(install)) => out.push(install),
            Ok(None) => {}
            Err(e) => out.push(WindowsInstall {
                origin: "live".into(),
                target,
                hives: Hives::default(),
                computer_name: None,
                timezone: None,
                accounts: Vec::new(),
                ntuser: Vec::new(),
                usrclass: Vec::new(),
                ansi_codepage: None,
                hive_status: Vec::new(),
                warnings: vec![format!(
                    "NTFS-Partition bei Offset {} nicht lesbar: {e}",
                    target.offset
                )],
            }),
        }
    }
    out
}

/// Extrahiert je NTFS-Bereich die Windows-Installationen aus allen Volume Shadow
/// Copies (frühere Zustände). Registry-basierte Analyzer laufen dadurch
/// automatisch auch auf diese Snapshots.
pub fn extract_snapshots(img: &ImageReader, targets: &[NtfsTarget]) -> Vec<WindowsInstall> {
    let mut out = Vec::new();

    for &target in targets {
        let Some(bereich) = crate::schatten::ImageBereich::new(img, target) else {
            continue;
        };
        // Fehler meldet der Kontextaufbau; hier nur überspringen.
        let Ok(Some(vss)) = stratum_vss::Volume::open(bereich) else {
            continue;
        };
        for info in vss.stores() {
            let created = filetime_to_unix(info.creation_time)
                .map(|u| format!(" ({u})"))
                .unwrap_or_default();
            let origin = format!("VSS#{}{}", info.index + 1, created);
            let Ok(reader) = vss.reader(info.index) else {
                continue;
            };
            let size = reader.size();
            let mut vol = match NtfsVolume::from_reader(reader, 0, size) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if let Ok(Some(install)) = install_from_volume(&mut vol, target, origin) {
                out.push(install);
            }
        }
    }
    out
}

/// FILETIME (100-ns seit 1601) -> Unix-Sekunden.
fn filetime_to_unix(ft: u64) -> Option<i64> {
    const EPOCH_DIFF: u64 = 116_444_736_000_000_000;
    ft.checked_sub(EPOCH_DIFF).map(|t| (t / 10_000_000) as i64)
}

fn extract_one(
    img: &ImageReader,
    target: NtfsTarget,
) -> Result<Option<WindowsInstall>, stratum_ntfs::NtfsVolumeError> {
    let mut vol = NtfsVolume::open(img, target.offset, target.size)?;
    install_from_volume(&mut vol, target, "live".into())
}

/// Baut aus einem geöffneten NTFS-Volume die Windows-Grunddaten (Hives,
/// Zeitzone, Rechnername, Konten, NTUSER). `Ok(None)`, wenn kein SYSTEM-Hive
/// vorhanden ist (keine Windows-Installation).
fn install_from_volume<R: std::io::Read + std::io::Seek>(
    vol: &mut NtfsVolume<R>,
    target: NtfsTarget,
    origin: String,
) -> Result<Option<WindowsInstall>, stratum_ntfs::NtfsVolumeError> {
    if !vol.exists(SYSTEM_PATH)? {
        return Ok(None);
    }

    let mut warnings = Vec::new();
    let mut status = Vec::new();
    let mut load = |vol: &mut NtfsVolume<R>, path: &str, name: &str| {
        load_hive(vol, path, name, &mut status, &mut warnings)
    };
    let hives = Hives {
        system: load(vol, SYSTEM_PATH, "SYSTEM"),
        sam: load(vol, SAM_PATH, "SAM"),
        software: load(vol, SOFTWARE_PATH, "SOFTWARE"),
        security: load(vol, SECURITY_PATH, "SECURITY"),
        amcache: load(vol, AMCACHE_PATH, "Amcache.hve"),
    };
    let (ntuser, usrclass) = read_user_hives(vol, &mut status, &mut warnings);

    let mut computer_name = None;
    let mut timezone = None;
    let mut ansi_codepage = None;
    let mut accounts = Vec::new();

    if let Some(system_bytes) = &hives.system {
        match Hive::parse(system_bytes) {
            Ok(system_hive) => {
                // Der unsaubere Zustand steht bereits im Hive-Status.
                for w in system_hive.warnings() {
                    if !system_hive.base_block().is_dirty() || !w.starts_with("Hive unsauber") {
                        warnings.push(format!("SYSTEM: {w}"));
                    }
                }
                let cs = current_control_set(&system_hive);
                computer_name = read_computer_name(&system_hive, &cs);
                ansi_codepage = system_hive
                    .open_key(&format!("{cs}\\Control\\Nls\\CodePage"))
                    .ok()
                    .flatten()
                    .and_then(|k| k.value("ACP").ok().flatten())
                    .and_then(|v| v.as_string());
                timezone = read_timezone(&system_hive, &cs);

                // Konten brauchen zusätzlich den SAM-Hive.
                if let Some(sam_bytes) = &hives.sam {
                    match Hive::parse(sam_bytes) {
                        Ok(sam_hive) => match extract_local_accounts(&system_hive, &sam_hive) {
                            Ok(mut report) => {
                                accounts = report.accounts;
                                warnings.append(&mut report.warnings);
                            }
                            Err(e) => warnings.push(format!("Konten nicht lesbar: {e}")),
                        },
                        Err(e) => warnings.push(format!("SAM-Hive nicht lesbar: {e}")),
                    }
                } else {
                    warnings.push("SAM-Hive nicht gefunden, keine Konten".into());
                }
            }
            Err(e) => warnings.push(format!("SYSTEM-Hive nicht lesbar: {e}")),
        }
    }

    Ok(Some(WindowsInstall {
        origin,
        target,
        hives,
        computer_name,
        timezone,
        accounts,
        ntuser,
        usrclass,
        ansi_codepage,
        hive_status: status,
        warnings,
    }))
}

/// Nutzer-Hives: `Users\<name>\NTUSER.DAT` und
/// `Users\<name>\AppData\Local\Microsoft\Windows\UsrClass.dat`.
type UserHives = (Vec<(String, Vec<u8>)>, Vec<(String, Vec<u8>)>);

/// Liest NTUSER.DAT und UsrClass.dat jedes Benutzers, jeweils mit Log-Prüfung.
fn read_user_hives<R: std::io::Read + std::io::Seek>(
    vol: &mut NtfsVolume<R>,
    status: &mut Vec<HiveStatus>,
    warnings: &mut Vec<String>,
) -> UserHives {
    let mut out = Vec::new();
    let mut classes = Vec::new();
    let users = match vol.list_dir("Users") {
        Ok(Some(u)) => u,
        _ => return (out, classes),
    };
    for u in users {
        if !u.is_directory {
            continue;
        }
        let path = format!("Users\\{}\\NTUSER.DAT", u.name);
        let name = format!("NTUSER.DAT ({})", u.name);
        if let Some(data) = load_hive(vol, &path, &name, status, warnings) {
            out.push((u.name.clone(), data));
        }
        let path = format!(
            "Users\\{}\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat",
            u.name
        );
        let name = format!("UsrClass.dat ({})", u.name);
        if let Some(data) = load_hive(vol, &path, &name, status, warnings) {
            classes.push((u.name.clone(), data));
        }
    }
    (out, classes)
}

fn read_optional<R: std::io::Read + std::io::Seek>(
    vol: &mut NtfsVolume<R>,
    path: &str,
    warnings: &mut Vec<String>,
) -> Option<Vec<u8>> {
    match vol.read_file(path) {
        Ok(Some(f)) => Some(f.data),
        Ok(None) => None,
        Err(e) => {
            warnings.push(format!("{path} nicht lesbar: {e}"));
            None
        }
    }
}

/// Liest einen Hive samt `.LOG1`/`.LOG2`, prüft ihn wie der Windows-Kern beim
/// Laden und spielt die Logs bei einem unsauberen Hive im Speicher ein. Die
/// Dateien im Image bleiben unverändert. Der Zustand landet in `status`.
fn load_hive<R: std::io::Read + std::io::Seek>(
    vol: &mut NtfsVolume<R>,
    path: &str,
    name: &str,
    status: &mut Vec<HiveStatus>,
    warnings: &mut Vec<String>,
) -> Option<Vec<u8>> {
    let primary = read_optional(vol, path, warnings)?;
    let rohe: Vec<(String, Vec<u8>)> = [".LOG1", ".LOG2"]
        .iter()
        .filter_map(|suffix| {
            let log_path = format!("{path}{suffix}");
            read_optional(vol, &log_path, warnings).map(|d| (log_path, d))
        })
        .collect();
    Some(evaluate_hive(primary, &rohe, path, name, status, warnings))
}

/// Prüft einen gelesenen Hive gegen seine Logs (`rohe`: Pfad und Inhalt) und
/// liefert die zu verwendenden Bytes, bei Bedarf wiederhergestellt.
pub(crate) fn evaluate_hive(
    primary: Vec<u8>,
    rohe: &[(String, Vec<u8>)],
    path: &str,
    name: &str,
    status: &mut Vec<HiveStatus>,
    warnings: &mut Vec<String>,
) -> Vec<u8> {
    let logs: Vec<TransactionLog<'_>> =
        rohe.iter().map(|(_, d)| TransactionLog::parse(d)).collect();
    let datei = |log_path: &str| {
        log_path
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(log_path)
            .to_string()
    };
    let log_status = rohe
        .iter()
        .zip(&logs)
        .map(|((log_path, data), log)| LogStatus {
            datei: datei(log_path),
            groesse: data.len() as u64,
            format: log.format.name(),
            eintraege: log.entries.len(),
            hash_fehler: log.entries.iter().filter(|e| !e.hashes_ok).count(),
            sequenzen: match (log.entries.first(), log.entries.last()) {
                (Some(a), Some(b)) => Some(format!("{}..{}", a.sequence, b.sequence)),
                _ => None,
            },
        })
        .collect();
    let (seq1, seq2, pruefsumme_ok) = match Hive::parse(&primary) {
        Ok(h) => {
            let b = h.base_block();
            (b.primary_seq, b.secondary_seq, b.checksum_ok())
        }
        Err(_) => (0, 0, false),
    };
    let mut st = HiveStatus {
        name: name.to_string(),
        pfad: path.to_string(),
        zustand: "sauber",
        sequenz_primaer: seq1,
        sequenz_sekundaer: seq2,
        pruefsumme_ok,
        eingespielt: Vec::new(),
        neuere_eintraege_ignoriert: 0,
        grund: None,
        logs: log_status,
    };
    let data = match recover(&primary, &logs) {
        Recovery::Clean { ignored } => {
            st.neuere_eintraege_ignoriert = ignored;
            primary
        }
        Recovery::Recovered {
            data,
            applied,
            base_from_log,
        } => {
            st.zustand = "wiederhergestellt";
            st.eingespielt = applied
                .iter()
                .map(|a| format!("{}: {}..{}", datei(&rohe[a.log].0), a.from, a.to))
                .collect();
            warnings.push(format!(
                "{name}: aus Transaktionslogs wiederhergestellt ({}{}); Hive-Offsets in Funden beziehen sich auf den wiederhergestellten Stand",
                st.eingespielt.join(", "),
                if base_from_log { ", Kopf aus dem Log" } else { "" }
            ));
            data
        }
        Recovery::Failed(reason) => {
            st.zustand = "unsauber_nicht_wiederhergestellt";
            st.grund = Some(reason);
            warnings.push(format!(
                "{name}: unsauber geschrieben (Sequenz {seq1}/{seq2}), Transaktionslogs nicht einspielbar: {reason}"
            ));
            primary
        }
    };
    if logs.iter().any(|l| l.format == LogFormat::Alt) && st.zustand != "sauber" {
        warnings.push(format!(
            "{name}: Transaktionslog im alten Format (vor Windows 8.1) wird nicht eingespielt"
        ));
    }
    status.push(st);
    data
}

/// Bestimmt das aktive ControlSet, z. B. "ControlSet001".
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

fn read_computer_name(system: &Hive, cs: &str) -> Option<String> {
    let path = format!("{cs}\\Control\\ComputerName\\ComputerName");
    system
        .open_key(&path)
        .ok()
        .flatten()?
        .value("ComputerName")
        .ok()
        .flatten()?
        .as_string()
}

fn read_timezone(system: &Hive, cs: &str) -> Option<TimeZone> {
    let path = format!("{cs}\\Control\\TimeZoneInformation");
    let key = system.open_key(&path).ok().flatten()?;
    let key_name = key
        .value("TimeZoneKeyName")
        .ok()
        .flatten()
        .and_then(|v| v.as_string())?;
    let active_bias_minutes = key
        .value("ActiveTimeBias")
        .ok()
        .flatten()
        .and_then(|v| v.as_u32())
        .map(|b| b as i32);
    Some(TimeZone {
        key_name,
        active_bias_minutes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::HiveBuilder;
    use stratum_registry::marvin64;

    fn pruefsumme(data: &mut [u8]) {
        let x = data[..508].chunks_exact(4).fold(0u32, |acc, c| {
            acc ^ u32::from_le_bytes([c[0], c[1], c[2], c[3]])
        });
        let x = match x {
            0xFFFF_FFFF => 0xFFFF_FFFE,
            0 => 1,
            x => x,
        };
        data[508..512].copy_from_slice(&x.to_le_bytes());
    }

    fn hive(primary: u32, secondary: u32) -> Vec<u8> {
        let mut b = HiveBuilder::new();
        let root = b.key("ROOT", None, &[]);
        let mut data = b.finish(root);
        data[4..8].copy_from_slice(&primary.to_le_bytes());
        data[8..12].copy_from_slice(&secondary.to_le_bytes());
        pruefsumme(&mut data);
        data
    }

    /// Logdatei mit einem Eintrag, der die erste Hive-Bin-Seite ersetzt.
    fn log(primary: &[u8], seq: u32, fuell: u8) -> Vec<u8> {
        let mut log = primary[..512].to_vec();
        log[4..8].copy_from_slice(&seq.to_le_bytes());
        log[8..12].copy_from_slice(&seq.to_le_bytes());
        log[28..32].copy_from_slice(&6u32.to_le_bytes());
        pruefsumme(&mut log);
        let hbins = u32::from_le_bytes(primary[40..44].try_into().unwrap());
        let mut seite = primary[4096..8192].to_vec();
        seite[100] = fuell;
        let mut e = vec![0u8; 48 + 4096];
        e.resize(e.len().div_ceil(512) * 512, 0);
        let size = e.len() as u32;
        e[..4].copy_from_slice(b"HvLE");
        e[4..8].copy_from_slice(&size.to_le_bytes());
        e[12..16].copy_from_slice(&seq.to_le_bytes());
        e[16..20].copy_from_slice(&hbins.to_le_bytes());
        e[20..24].copy_from_slice(&1u32.to_le_bytes());
        e[44..48].copy_from_slice(&4096u32.to_le_bytes());
        e[48..48 + 4096].copy_from_slice(&seite);
        let seed = 0x82EF_4D88_7A4E_55C5;
        let h1 = marvin64(&e[40..], seed);
        e[24..32].copy_from_slice(&h1.to_le_bytes());
        let h2 = marvin64(&e[..32], seed);
        e[32..40].copy_from_slice(&h2.to_le_bytes());
        log.extend_from_slice(&e);
        log
    }

    fn pruefe(primary: Vec<u8>, logs: &[(String, Vec<u8>)]) -> (Vec<u8>, HiveStatus, Vec<String>) {
        let (mut status, mut warnings) = (Vec::new(), Vec::new());
        let data = evaluate_hive(
            primary,
            logs,
            "cfg/SYSTEM",
            "SYSTEM",
            &mut status,
            &mut warnings,
        );
        (data, status.pop().unwrap(), warnings)
    }

    #[test]
    fn sauberer_hive_ohne_hinweis() {
        let h = hive(5, 5);
        let (data, st, warnings) = pruefe(h.clone(), &[("cfg/SYSTEM.LOG1".into(), Vec::new())]);
        assert_eq!(data, h);
        assert_eq!(st.zustand, "sauber");
        assert_eq!(st.logs[0].format, "leer");
        assert!(warnings.is_empty());
    }

    #[test]
    fn unsauberer_hive_wird_aus_dem_log_wiederhergestellt() {
        let h = hive(6, 5);
        let logs = [("cfg/SYSTEM.LOG1".to_string(), log(&h, 5, 0xab))];
        let (data, st, warnings) = pruefe(h.clone(), &logs);
        assert_eq!(st.zustand, "wiederhergestellt");
        assert_eq!(st.eingespielt, ["SYSTEM.LOG1: 5..5"]);
        assert_eq!(st.logs[0].eintraege, 1);
        assert_eq!(st.logs[0].hash_fehler, 0);
        assert_eq!(data[4096 + 100], 0xab);
        assert!(warnings[0].contains("wiederhergestellt"));
        // Der wiederhergestellte Hive ist sauber und lesbar.
        let parsed = Hive::parse(&data).unwrap();
        assert!(!parsed.base_block().is_dirty());
        assert!(parsed.root().is_ok());
    }

    #[test]
    fn unsauber_ohne_logs_bleibt_mit_hinweis() {
        let h = hive(6, 5);
        let (data, st, warnings) = pruefe(h.clone(), &[]);
        assert_eq!(data, h);
        assert_eq!(st.zustand, "unsauber_nicht_wiederhergestellt");
        assert!(st.grund.is_some());
        assert!(warnings[0].contains("nicht einspielbar"));
    }

    /// Echter SYSTEM-Hive samt Logs, in den unsauberen Zustand vor dem
    /// jüngsten Logeintrag versetzt: Das Einspielen muss den Hive-Stand im
    /// Image exakt ergeben.
    #[test]
    #[ignore = "benötigt STRATUM_HIVELOG_REFERENCE mit SYSTEM und SYSTEM.LOG1/LOG2"]
    fn echte_logs_stellen_system_wieder_her() {
        let dir = std::path::PathBuf::from(std::env::var_os("STRATUM_HIVELOG_REFERENCE").unwrap());
        let original = std::fs::read(dir.join("SYSTEM")).unwrap();
        let logs: Vec<(String, Vec<u8>)> = ["SYSTEM.LOG1", "SYSTEM.LOG2"]
            .iter()
            .map(|n| (format!("cfg/{n}"), std::fs::read(dir.join(n)).unwrap()))
            .collect();
        let (_, st, warnings) = pruefe(original.clone(), &logs);
        assert_eq!(st.zustand, "sauber");
        assert!(warnings.is_empty());

        let letzte = TransactionLog::parse(&logs[0].1).entries[0].sequence;
        let mut dirty = original.clone();
        dirty[8..12].copy_from_slice(&letzte.to_le_bytes());
        pruefsumme(&mut dirty);
        let (data, st, _) = pruefe(dirty, &logs);
        assert_eq!(st.zustand, "wiederhergestellt");
        assert_eq!(st.eingespielt, [format!("SYSTEM.LOG1: {letzte}..{letzte}")]);
        assert_eq!(data[4096..], original[4096..]);
        let hive = Hive::parse(&data).unwrap();
        let cs = current_control_set(&hive);
        assert!(read_computer_name(&hive, &cs).is_some());
        eprintln!("{st:?}");
    }
}
