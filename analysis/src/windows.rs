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
use stratum_registry::Hive;

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
    use std::io::Cursor;
    let data = img.as_slice();
    let mut out = Vec::new();

    for &target in targets {
        let start = target.offset as usize;
        let end = match start.checked_add(target.size as usize) {
            Some(e) if e <= data.len() => e,
            _ => continue,
        };
        let mut cursor = Cursor::new(&data[start..end]);
        let Ok(vss) = vshadow::VssVolume::new(&mut cursor) else {
            continue;
        };
        for i in 0..vss.store_count() {
            let created = vss
                .store_info(i)
                .ok()
                .and_then(|s| filetime_to_unix(s.creation_time))
                .map(|u| format!(" ({u})"))
                .unwrap_or_default();
            let origin = format!("VSS#{}{}", i + 1, created);
            let Ok(reader) = vss.store_reader(&mut cursor, i) else {
                continue;
            };
            let mut vol = match NtfsVolume::from_reader(reader, 0, target.size) {
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
    let Some(system) = vol.read_file(SYSTEM_PATH)? else {
        return Ok(None);
    };

    let mut warnings = Vec::new();
    let hives = Hives {
        sam: read_optional(vol, SAM_PATH, &mut warnings),
        software: read_optional(vol, SOFTWARE_PATH, &mut warnings),
        security: read_optional(vol, SECURITY_PATH, &mut warnings),
        amcache: read_optional(vol, AMCACHE_PATH, &mut warnings),
        system: Some(system.data),
    };

    let mut computer_name = None;
    let mut timezone = None;
    let mut accounts = Vec::new();

    if let Some(system_bytes) = &hives.system {
        match Hive::parse(system_bytes) {
            Ok(system_hive) => {
                for w in system_hive.warnings() {
                    warnings.push(format!("SYSTEM: {w}"));
                }
                let cs = current_control_set(&system_hive);
                computer_name = read_computer_name(&system_hive, &cs);
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

    // NTUSER.DAT je Benutzer (für HKCU-basierte Analyzer).
    let ntuser = read_ntuser_hives(vol, &mut warnings);

    Ok(Some(WindowsInstall {
        origin,
        target,
        hives,
        computer_name,
        timezone,
        accounts,
        ntuser,
        warnings,
    }))
}

/// Liest die NTUSER.DAT jedes Benutzers unter `Users\<name>\NTUSER.DAT`.
fn read_ntuser_hives<R: std::io::Read + std::io::Seek>(
    vol: &mut NtfsVolume<R>,
    warnings: &mut Vec<String>,
) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let users = match vol.list_dir("Users") {
        Ok(Some(u)) => u,
        _ => return out,
    };
    for u in users {
        if !u.is_directory {
            continue;
        }
        let path = format!("Users\\{}\\NTUSER.DAT", u.name);
        match vol.read_file(&path) {
            Ok(Some(f)) => out.push((u.name.clone(), f.data)),
            Ok(None) => {}
            Err(e) => warnings.push(format!("NTUSER.DAT von {} nicht lesbar: {e}", u.name)),
        }
    }
    out
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
