//! YARA 4.5 über die lokale CLI. Das Ausgabeformat folgt cli/yara.c:
//! https://github.com/VirusTotal/yara/blob/v4.5.5/cli/yara.c
use crate::prozess::ausfuehren;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

/// Fehler des lokalen YARA-Connectors.
pub use crate::ConnectorFehler as YaraFehler;
/// Bytebezug einer von YARA gespeicherten String-Übereinstimmung.
#[derive(Debug, serde::Serialize)]
pub struct StringTreffer {
    /// Logischer Dateioffset.
    pub offset: u64,
    /// Länge der von YARA gespeicherten Matchdaten, nicht zwingend des gesamten Matches.
    pub gespeicherte_laenge: u64,
    /// String-ID der Regel.
    pub string: String,
}
/// Zutreffende Regel. Auch Bedingungen ohne String können zutreffen.
#[derive(Debug, serde::Serialize)]
pub struct RegelTreffer {
    /// Regelname.
    pub regel: String,
    /// Gemeldete String-Übereinstimmungen.
    pub strings: Vec<StringTreffer>,
}
/// Ergebnis eines begrenzten Scans.
#[derive(Debug, serde::Serialize)]
pub struct YaraErgebnis {
    /// Ausgeführte Werkzeugversion.
    pub version: String,
    /// Zutreffende Regeln, höchstens 500.
    pub treffer: Vec<RegelTreffer>,
    /// Nicht an der Regelgrenze angehalten.
    pub vollstaendig: bool,
}
/// Regeltext begrenzen und Dateieinbindungen ausschließen.
pub fn regeln_pruefen(text: &str) -> Result<(), YaraFehler> {
    if text.trim().is_empty() || text.len() > 65536 || text.contains('\0') {
        return Err(YaraFehler::Eingabe(
            "Regeltext muss 1 bis 65536 Bytes enthalten".into(),
        ));
    }
    // Bewusst konservativ: auch das Wort in Kommentaren und Strings wird abgewiesen.
    if text
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .any(|s| s == "include")
    {
        return Err(YaraFehler::Eingabe(
            "include ist nicht erlaubt, auch nicht in Kommentaren oder Strings".into(),
        ));
    }
    Ok(())
}

/// Ausgabe von `yara -L` auswerten. Nicht erkannte Zeilen ergeben einen Fehler.
pub fn ausgabe_lesen(text: &str, groesse: u64) -> Result<Vec<RegelTreffer>, YaraFehler> {
    let fehler = || YaraFehler::Eingabe("Werkzeugausgabe ungültig oder außerhalb der Datei".into());
    if text.len() > 1024 * 1024 {
        return Err(fehler());
    }
    let mut treffer: Vec<RegelTreffer> = Vec::new();
    let mut strings = 0;
    for line in text.lines().filter(|s| !s.is_empty()) {
        if let Some(rest) = line.strip_prefix("0x") {
            let mut fields = rest.split(':');
            let offset =
                u64::from_str_radix(fields.next().ok_or_else(fehler)?, 16).map_err(|_| fehler())?;
            let len: u64 = fields
                .next()
                .ok_or_else(fehler)?
                .parse()
                .map_err(|_| fehler())?;
            let id = fields.next().ok_or_else(fehler)?;
            if fields.next().is_some()
                || !id.starts_with('$')
                || !id[1..]
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_')
                || offset.checked_add(len).is_none_or(|end| end > groesse)
                || strings >= 10000
            {
                return Err(fehler());
            }
            treffer
                .last_mut()
                .ok_or_else(fehler)?
                .strings
                .push(StringTreffer {
                    offset,
                    gespeicherte_laenge: len,
                    string: id.into(),
                });
            strings += 1;
        } else {
            let (name, target) = line.split_once(' ').ok_or_else(fehler)?;
            if name.is_empty()
                || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                || target != "target.bin"
                || treffer.len() >= 500
            {
                return Err(fehler());
            }
            treffer.push(RegelTreffer {
                regel: name.into(),
                strings: Vec::new(),
            });
        }
    }
    Ok(treffer)
}

/// Verfügbarkeit vor dem Lesen einer möglicherweise großen Evidence-Datei prüfen.
pub fn bereitschaft(abbruch: &dyn Fn() -> bool) -> Result<String, YaraFehler> {
    if !cfg!(target_os = "linux") {
        return Err(YaraFehler::Eingabe(
            "Lokaler YARA-Connector benötigt Linux mit /usr/bin/yara und /usr/bin/prlimit".into(),
        ));
    }
    let mut version = Command::new("/usr/bin/yara");
    version.arg("--version");
    let version = ausfuehren(version, Duration::from_secs(5), abbruch)?
        .trim()
        .to_string();
    let mut v = version.split('.');
    if v.next() != Some("4")
        || v.next()
            .and_then(|n| n.parse::<u32>().ok())
            .is_none_or(|n| n < 5)
    {
        return Err(YaraFehler::Eingabe(
            "YARA 4.5 oder neuer innerhalb Version 4 erforderlich".into(),
        ));
    }
    if !Path::new("/usr/bin/prlimit").is_file() {
        return Err(YaraFehler::Eingabe("/usr/bin/prlimit fehlt".into()));
    }
    Ok(version)
}

/// Scan im privaten Arbeitsordner mit rules.yar und target.bin.
/// Linux: 1 GiB Adressraum, 60 CPU-Sekunden, 65 Sekunden Gesamtzeit.
/// Kein Shell-Aufruf und keine Ausführung des Dateiinhalts.
pub fn scannen(
    ordner: &Path,
    groesse: u64,
    abbruch: &dyn Fn() -> bool,
) -> Result<YaraErgebnis, YaraFehler> {
    use std::io::Read;
    let version = bereitschaft(abbruch)?;
    let mut rules = String::new();
    std::fs::File::open(ordner.join("rules.yar"))?
        .take(65537)
        .read_to_string(&mut rules)?;
    regeln_pruefen(&rules)?;
    let target = std::fs::metadata(ordner.join("target.bin"))?;
    if !target.is_file() || target.len() != groesse || groesse > 256 * 1024 * 1024 {
        return Err(YaraFehler::Eingabe(
            "Arbeitskopie fehlt, ist unvollständig oder größer als 256 MiB".into(),
        ));
    }
    let mut cmd = Command::new("/usr/bin/prlimit");
    cmd.current_dir(ordner).args([
        "--as=1073741824",
        "--cpu=60",
        "--nofile=64",
        "--",
        "/usr/bin/yara",
        "-L",
        "-q",
        "--fail-on-warnings",
        "--max-strings-per-rule=1000",
        "--max-rules=500",
        "--timeout=60",
        "rules.yar",
        "target.bin",
    ]);
    let text = ausfuehren(cmd, Duration::from_secs(65), abbruch)?;
    let treffer = ausgabe_lesen(&text, groesse)?;
    Ok(YaraErgebnis {
        version,
        vollstaendig: treffer.len() < 500,
        treffer,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn regelgrenzen_und_herkunft() {
        assert!(regeln_pruefen("rule a { condition: true }").is_ok());
        assert!(regeln_pruefen("include \"/etc/passwd\"").is_err());
        assert!(regeln_pruefen(&"a".repeat(65537)).is_err());
        let r = ausgabe_lesen("Test target.bin\n0x2:3:$a\nEmpty target.bin\n", 5).unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].strings[0].offset, 2);
        assert!(ausgabe_lesen("Test target.bin\n0xffffffffffffffff:3:$a\n", 5).is_err());
        assert!(ausgabe_lesen("0x0:1:$a\n", 5).is_err());
        assert!(ausgabe_lesen("Test other.bin\n", 5).is_err());
    }
}
