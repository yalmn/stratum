/// Fehler beim Lesen eines Hives.
///
/// Offsets sind immer Offsets in der Hive-Datei.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HiveError {
    /// Die Datei ist kleiner als der Base Block (4096 Bytes).
    #[error("Hive zu klein: {0} Bytes")]
    TooSmall(usize),

    /// Die Signatur `regf` fehlt.
    #[error("keine regf-Signatur")]
    BadSignature,

    /// Eine Zelle liegt ganz oder teilweise außerhalb der Datei oder hat eine
    /// unplausible Größe.
    #[error("ungültige Zelle an Offset {offset:#x}")]
    BadCell {
        /// Offset der Zelle in der Datei.
        offset: u64,
    },

    /// Eine Zelle hat nicht die erwartete Signatur.
    #[error("an Offset {offset:#x} erwartet {expected}, gefunden {found:?}")]
    UnexpectedCell {
        /// Offset der Zelle in der Datei.
        offset: u64,
        /// Erwartete Signatur, z. B. `"nk"`.
        expected: &'static str,
        /// Tatsächlich gefundene zwei Bytes.
        found: [u8; 2],
    },

    /// Ein Zähler (Unterschlüssel, Werte, Segmente) passt nicht zur Größe der
    /// Zelle, in der die Einträge stehen.
    #[error("Zähler {count} an Offset {offset:#x} passt nicht in die Zelle")]
    BadCount {
        /// Offset der Zelle in der Datei.
        offset: u64,
        /// Angegebene Anzahl.
        count: u32,
    },

    /// Die angegebene Datenlänge eines Werts ist unplausibel.
    #[error("Wert an Offset {offset:#x}: Datenlänge {len} unplausibel")]
    BadDataLength {
        /// Offset der vk-Zelle in der Datei.
        offset: u64,
        /// Angegebene Länge.
        len: u32,
    },

    /// Unterschlüssel-Listen sind tiefer verschachtelt als erlaubt.
    #[error("Unterschlüssel-Liste an Offset {offset:#x} zu tief verschachtelt")]
    ListTooDeep {
        /// Offset der Liste in der Datei.
        offset: u64,
    },
}
