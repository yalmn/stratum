//! Parser für Windows-Registry-Hives im regf-Format.
//!
//! Der Parser arbeitet nur lesend auf einem Byte-Slice und kopiert nur dort,
//! wo es nicht anders geht (Big-Data-Werte, Namen). Gedacht ist er für den
//! gezielten Zugriff auf einzelne Schlüssel per Pfad, nicht für einen
//! vollständigen Dump aller Werte.
//!
//! Alle Offsets in [`Key`] und [`Value`] beziehen sich auf die Hive-Datei.
//! Die Umrechnung auf einen Offset im Image übernimmt die Schicht, die die
//! Datei aus dem Dateisystem liest.
//!
//! Formatgrundlage ist die öffentliche Beschreibung des regf-Formats von
//! Maxim Suhanov ("Windows registry file format specification").

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod hive;
mod key;
mod value;

#[cfg(test)]
#[path = "../tests/common/builder.rs"]
mod builder;

pub use error::HiveError;
pub use hive::{BaseBlock, Hive};
pub use key::Key;
pub use value::{Value, ValueType};

/// Wandelt einen Windows-FILETIME (100-ns-Intervalle seit 1601-01-01 UTC)
/// in Sekunden und Nanosekunden seit der Unix-Epoche (UTC) um.
///
/// Gibt `None` zurück, wenn der Zeitpunkt vor 1970 liegt.
pub fn filetime_to_unix(ft: u64) -> Option<(i64, u32)> {
    const EPOCH_DIFF: u64 = 116_444_736_000_000_000;
    let t = ft.checked_sub(EPOCH_DIFF)?;
    Some(((t / 10_000_000) as i64, ((t % 10_000_000) * 100) as u32))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetime() {
        assert_eq!(filetime_to_unix(116_444_736_000_000_000), Some((0, 0)));
        // 2021-01-01T00:00:00Z
        assert_eq!(
            filetime_to_unix(132_539_328_000_000_000),
            Some((1_609_459_200, 0))
        );
        assert_eq!(filetime_to_unix(116_444_736_000_000_015), Some((0, 1_500)));
        assert_eq!(filetime_to_unix(0), None);
    }
}
