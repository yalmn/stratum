//! DNS und WHOIS als explizite externe Abfragen. Heutige Antworten sind
//! Anreicherung zur Untersuchungszeit und keine historische Evidence.
use crate::prozess::ausfuehren;
use crate::ConnectorFehler as YaraFehler;
use std::net::IpAddr;
use std::process::Command;
use std::time::Duration;

/// IP, Domain oder HTTP(S)-URL auf den abzufragenden Host reduzieren.
/// URL-Pfade werden nicht abgerufen; Zugangsdaten in URLs sind unzulässig.
pub fn host_eingabe(input: &str) -> Result<String, YaraFehler> {
    let input = input.trim();
    let bad =
        || YaraFehler::Eingabe("IP, Domain oder HTTP(S)-URL ohne Zugangsdaten erforderlich".into());
    if input.is_empty() || input.len() > 2048 || input.bytes().any(|b| b.is_ascii_control()) {
        return Err(bad());
    }
    let host = if input.contains("://") {
        let u = url::Url::parse(input).map_err(|_| bad())?;
        if !["http", "https"].contains(&u.scheme())
            || !u.username().is_empty()
            || u.password().is_some()
        {
            return Err(bad());
        }
        match u.host().ok_or_else(bad)? {
            url::Host::Domain(h) => h.to_string(),
            url::Host::Ipv4(ip) => ip.to_string(),
            url::Host::Ipv6(ip) => ip.to_string(),
        }
    } else {
        input.trim_end_matches('.').to_ascii_lowercase()
    };
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip.to_string());
    }
    if host.len() > 253
        || !host.contains('.')
        || !host.split('.').all(|part| {
            !part.is_empty()
                && part.len() <= 63
                && !part.starts_with('-')
                && !part.ends_with('-')
                && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(bad());
    }
    Ok(host)
}
/// Eine vollständige Werkzeugantwort mit Quelle und tatsächlicher Version.
#[derive(Debug, serde::Serialize)]
pub struct Antwort {
    /// DNS-A, DNS-AAAA, DNS-PTR oder WHOIS.
    pub art: String,
    /// Werkzeugversion.
    pub version: String,
    /// Erfolgreiche Antwort oder Fehler dieser Einzelabfrage.
    pub erfolgreich: bool,
    /// Vollständiges Transkript oder begründeter Fehler; höchstens 1 MiB.
    pub text: String,
    /// Beginn der Einzelabfrage, leer wenn das Werkzeug nicht verfügbar war.
    pub abgefragt_am: Option<String>,
    /// Ende dieser Einzelabfrage oder Verfügbarkeitsprüfung.
    pub beendet_am: String,
}
/// Externe Abfragen auf Linux. Keine Abfrage findet ohne Auswahl statt.
/// Einzelabfragen werden auf 20 Sekunden begrenzt; Abbruch bleibt möglich.
pub fn abfragen(
    host: &str,
    dns: bool,
    whois: bool,
    abbruch: &dyn Fn() -> bool,
) -> Result<Vec<Antwort>, YaraFehler> {
    if host_eingabe(host)? != host || (!dns && !whois) {
        return Err(YaraFehler::Eingabe(
            "Normalisierter Host und mindestens eine Abfrage erforderlich".into(),
        ));
    }
    if !cfg!(target_os = "linux") {
        return Err(YaraFehler::Eingabe(
            "Netzwerk-Connector benötigt Linux mit nslookup bzw. whois".into(),
        ));
    }
    let mut results = Vec::new();
    let mut run =
        |tool: &str, version_arg: &str, kind: &str, args: &[&str]| -> Result<(), YaraFehler> {
            if abbruch() {
                return Err(YaraFehler::Abgebrochen);
            }
            let mut v = Command::new(tool);
            v.arg(version_arg);
            let version = match crate::prozess::version(v, abbruch) {
                Ok(v) => v.trim().to_string(),
                Err(YaraFehler::Abgebrochen) => return Err(YaraFehler::Abgebrochen),
                Err(e) => {
                    results.push(Antwort {
                        art: kind.into(),
                        version: "nicht verfügbar".into(),
                        erfolgreich: false,
                        text: e.to_string(),
                        abgefragt_am: None,
                        beendet_am: chrono::Utc::now().to_rfc3339(),
                    });
                    return Ok(());
                }
            };
            let abgefragt_am = chrono::Utc::now().to_rfc3339();
            let mut cmd = Command::new(tool);
            cmd.args(args);
            let (erfolgreich, text) = match ausfuehren(cmd, Duration::from_secs(20), abbruch) {
                Ok(text) => (true, text),
                Err(YaraFehler::Abgebrochen) => return Err(YaraFehler::Abgebrochen),
                Err(e) => (false, e.to_string()),
            };
            results.push(Antwort {
                art: kind.into(),
                version,
                erfolgreich,
                text,
                abgefragt_am: Some(abgefragt_am),
                beendet_am: chrono::Utc::now().to_rfc3339(),
            });
            Ok(())
        };
    if dns {
        if host.parse::<IpAddr>().is_ok() {
            run(
                "/usr/bin/nslookup",
                "-version",
                "DNS-PTR",
                &["-timeout=5", "-retry=1", "-type=PTR", host],
            )?;
        } else {
            run(
                "/usr/bin/nslookup",
                "-version",
                "DNS-A",
                &["-timeout=5", "-retry=1", "-type=A", host],
            )?;
            run(
                "/usr/bin/nslookup",
                "-version",
                "DNS-AAAA",
                &["-timeout=5", "-retry=1", "-type=AAAA", host],
            )?;
        }
    }
    if whois {
        run("/usr/bin/whois", "--version", "WHOIS", &["--", host])?;
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn host_normalisieren_ohne_url_abruf() {
        assert_eq!(
            host_eingabe("https://Example.org/private?q=secret").unwrap(),
            "example.org"
        );
        assert_eq!(
            host_eingabe("https://[2001:db8::1]/").unwrap(),
            "2001:db8::1"
        );
        assert_eq!(host_eingabe("2001:DB8::1").unwrap(), "2001:db8::1");
        for invalid in [
            "-version",
            "example.org;id",
            "https://user:pw@example.org",
            "ftp://example.org",
            "bad..org",
            "example.org\n--server",
            "example.org/path",
        ] {
            assert!(host_eingabe(invalid).is_err(), "{invalid}");
        }
    }
}
