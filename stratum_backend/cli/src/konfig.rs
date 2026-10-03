//! Konfigurationsdatei `stratum.toml`.
//!
//! Gesucht wird in dieser Reihenfolge: `STRATUM_KONFIG` (muss existieren),
//! `./stratum.toml`, `$XDG_CONFIG_HOME/stratum/stratum.toml` bzw.
//! `~/.config/stratum/stratum.toml`, `/etc/stratum/stratum.toml`. Die erste
//! gefundene gilt. Umgebungsvariablen gehen der Datei vor, Optionen auf der
//! Kommandozeile beiden.
//!
//! ```toml
//! [datenbank]
//! url = "postgres://stratum@127.0.0.1:5432/stratum"
//! passwort_datei = ".stratum_db_passwort"   # relativ zur Konfigurationsdatei
//!
//! [konto]
//! name = "admin"                            # Vorgabe für --als
//!
//! [jobs]
//! ausgabe = "/var/lib/stratum/jobs"          # Reports der Jobs, je Job ein Ordner
//!
//! [server]
//! oberflaeche = "stratum_frontend/dist"      # gebaute Weboberfläche
//! ```

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{Context, Result};
use serde::Deserialize;

/// Inhalt der Datei.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Konfig {
    #[serde(default)]
    datenbank: Datenbank,
    #[serde(default)]
    konto: Konto,
    #[serde(default)]
    jobs: Jobs,
    #[serde(default)]
    server: Server,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Server {
    oberflaeche: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Jobs {
    ausgabe: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Datenbank {
    url: Option<String>,
    passwort_datei: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Konto {
    name: Option<String>,
}

/// Geladene Konfiguration mit ihrem Pfad.
#[derive(Debug, Default)]
pub struct Geladen {
    pfad: Option<PathBuf>,
    inhalt: Konfig,
}

fn kandidaten() -> Vec<PathBuf> {
    let mut k = vec![PathBuf::from("stratum.toml")];
    match std::env::var_os("XDG_CONFIG_HOME") {
        Some(x) if !x.is_empty() => k.push(PathBuf::from(x).join("stratum/stratum.toml")),
        _ => {
            if let Some(h) = std::env::var_os("HOME") {
                k.push(PathBuf::from(h).join(".config/stratum/stratum.toml"));
            }
        }
    }
    k.push(PathBuf::from("/etc/stratum/stratum.toml"));
    k
}

fn lesen(p: &Path) -> Result<Konfig> {
    let text = std::fs::read_to_string(p)
        .with_context(|| format!("Konfiguration nicht lesbar: {}", p.display()))?;
    toml::from_str(&text).with_context(|| format!("Konfiguration fehlerhaft: {}", p.display()))
}

fn laden() -> Result<Geladen> {
    if let Some(p) = std::env::var_os("STRATUM_KONFIG") {
        let p = PathBuf::from(p);
        return Ok(Geladen {
            inhalt: lesen(&p)?,
            pfad: Some(p),
        });
    }
    for p in kandidaten() {
        if p.is_file() {
            return Ok(Geladen {
                inhalt: lesen(&p)?,
                pfad: Some(p),
            });
        }
    }
    Ok(Geladen::default())
}

/// Die Konfiguration, einmal geladen.
pub fn konfig() -> Result<&'static Geladen> {
    static K: OnceLock<Geladen> = OnceLock::new();
    if let Some(k) = K.get() {
        return Ok(k);
    }
    let k = laden()?;
    Ok(K.get_or_init(|| k))
}

impl Geladen {
    /// Pfad der geladenen Datei.
    pub fn pfad(&self) -> Option<&Path> {
        self.pfad.as_deref()
    }

    /// Datenbank-URL: `STRATUM_DB_URL`, sonst die Datei.
    pub fn db_url(&self) -> Option<String> {
        std::env::var("STRATUM_DB_URL")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| self.inhalt.datenbank.url.clone())
    }

    /// Passwortdatei der Datenbank: `STRATUM_DB_PASSWORT_DATEI`, sonst die
    /// Datei (relative Pfade dort relativ zur Konfigurationsdatei).
    pub fn db_passwort_datei(&self) -> Option<PathBuf> {
        if let Some(p) = std::env::var_os("STRATUM_DB_PASSWORT_DATEI").filter(|p| !p.is_empty()) {
            return Some(PathBuf::from(p));
        }
        let p = self.inhalt.datenbank.passwort_datei.clone()?;
        Some(match (&self.pfad, p.is_relative()) {
            (Some(k), true) => k.parent().unwrap_or(Path::new(".")).join(p),
            _ => p,
        })
    }

    /// Ausgabeordner der Jobs: `STRATUM_JOB_AUSGABE`, sonst die Datei
    /// (relativ zur Konfigurationsdatei), sonst `stratum-jobs`.
    pub fn jobs_ausgabe(&self) -> PathBuf {
        if let Some(p) = std::env::var_os("STRATUM_JOB_AUSGABE").filter(|p| !p.is_empty()) {
            return PathBuf::from(p);
        }
        match (&self.inhalt.jobs.ausgabe, &self.pfad) {
            (Some(p), Some(k)) if p.is_relative() => k.parent().unwrap_or(Path::new(".")).join(p),
            (Some(p), _) => p.clone(),
            (None, _) => PathBuf::from("stratum-jobs"),
        }
    }

    /// Gebaute Weboberfläche: `STRATUM_OBERFLAECHE`, sonst die Datei
    /// (relativ zur Konfigurationsdatei), sonst `stratum_frontend/dist`,
    /// wenn dort eine `index.html` liegt.
    pub fn oberflaeche(&self) -> Option<PathBuf> {
        if let Some(p) = std::env::var_os("STRATUM_OBERFLAECHE").filter(|p| !p.is_empty()) {
            return Some(PathBuf::from(p));
        }
        match (&self.inhalt.server.oberflaeche, &self.pfad) {
            (Some(p), Some(k)) if p.is_relative() => {
                Some(k.parent().unwrap_or(Path::new(".")).join(p))
            }
            (Some(p), _) => Some(p.clone()),
            (None, _) => {
                let p = PathBuf::from("stratum_frontend/dist");
                p.join("index.html").is_file().then_some(p)
            }
        }
    }

    /// Vorgabe für `--als`: `STRATUM_KONTO`, sonst die Datei.
    pub fn konto(&self) -> Option<String> {
        std::env::var("STRATUM_KONTO")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| self.inhalt.konto.name.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datei_lesen_und_relative_pfade() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("stratum.toml");
        std::fs::write(
            &p,
            "[datenbank]\nurl = \"postgres://x@127.0.0.1/y\"\npasswort_datei = \"pw\"\n\
             [konto]\nname = \"admin\"\n",
        )
        .unwrap();
        let g = Geladen {
            inhalt: lesen(&p).unwrap(),
            pfad: Some(p.clone()),
        };
        assert_eq!(
            g.inhalt.datenbank.url.as_deref(),
            Some("postgres://x@127.0.0.1/y")
        );
        assert_eq!(
            g.inhalt.datenbank.passwort_datei.as_deref(),
            Some(Path::new("pw"))
        );
        assert_eq!(g.inhalt.konto.name.as_deref(), Some("admin"));
        // Relative Passwortdatei gilt vom Ordner der Konfiguration aus (nur
        // wenn die Umgebung nichts vorgibt).
        if std::env::var_os("STRATUM_DB_PASSWORT_DATEI").is_none() {
            assert_eq!(g.db_passwort_datei(), Some(d.path().join("pw")));
        }
    }

    #[test]
    fn unbekannte_schluessel_werden_abgelehnt() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("stratum.toml");
        std::fs::write(&p, "[datenbank]\nurll = \"tippfehler\"\n").unwrap();
        assert!(lesen(&p).is_err());
    }
}
