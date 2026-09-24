//! Auswertung einer NTFS-Partition: Registry-Eckdaten und lokale Konten.

use anyhow::{Context, Result};

use stratum_core::ImageReader;
use stratum_creds::extract_local_accounts;
use stratum_ntfs::NtfsVolume;
use stratum_registry::Hive;

use crate::report::{TimeZone, WindowsReport};

/// Pfade der beiden Hives im NTFS.
const SYSTEM_PATH: &str = "Windows/System32/config/SYSTEM";
const SAM_PATH: &str = "Windows/System32/config/SAM";

/// Untersucht eine NTFS-Partition und liefert einen Teilreport.
///
/// Fehlt Windows auf der Partition (keine Hives), wird `Ok(None)`
/// zurückgegeben, damit reine Datenpartitionen den Lauf nicht stören.
pub fn analyze(
    img: &ImageReader,
    index: u32,
    offset: u64,
    size: u64,
) -> Result<Option<WindowsReport>> {
    let mut vol = NtfsVolume::open(img, offset, size)
        .with_context(|| format!("NTFS-Partition {index} bei Offset {offset} nicht lesbar"))?;

    let Some(system) = vol.read_file(SYSTEM_PATH)? else {
        return Ok(None);
    };

    let mut report = WindowsReport {
        partition_index: index,
        partition_offset: offset,
        ..Default::default()
    };

    let system_hive = Hive::parse(&system.data).context("SYSTEM-Hive nicht lesbar")?;
    for w in system_hive.warnings() {
        report.warnings.push(format!("SYSTEM: {w}"));
    }

    let cs = current_control_set(&system_hive);
    report.computer_name = computer_name(&system_hive, &cs);
    report.timezone = timezone(&system_hive, &cs);

    // Konten brauchen zusätzlich den SAM-Hive.
    match vol.read_file(SAM_PATH)? {
        Some(sam) => {
            let sam_hive = Hive::parse(&sam.data).context("SAM-Hive nicht lesbar")?;
            match extract_local_accounts(&system_hive, &sam_hive) {
                Ok(mut creds) => {
                    report.accounts = creds.accounts;
                    report.warnings.append(&mut creds.warnings);
                }
                Err(e) => report.warnings.push(format!("Konten nicht lesbar: {e}")),
            }
        }
        None => report
            .warnings
            .push("SAM-Hive nicht gefunden, keine Konten".into()),
    }

    Ok(Some(report))
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

fn computer_name(system: &Hive, cs: &str) -> Option<String> {
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

fn timezone(system: &Hive, cs: &str) -> Option<TimeZone> {
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
