//! Online-Prüfung, ob ein gefundener Hidden Service noch erreichbar ist.
//!
//! Diese Prüfung verlässt die reine Offline-Analyse und geht ins Tor-Netz. Sie
//! läuft daher nur auf ausdrücklichen Wunsch (`--check-onion`) und setzt einen
//! laufenden Tor-Dienst mit SOCKS5-Proxy voraus (Standard `127.0.0.1:9050`).
//!
//! Es wird lediglich eine Verbindung über den Proxy zur `.onion`-Adresse auf
//! Port 80 aufgebaut (SOCKS5 CONNECT); der Erfolg der Verbindung zeigt, dass der
//! Dienst erreichbar ist. Es werden keine Inhalte abgerufen.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use stratum_analysis::Finding;

/// Zeitlimit für Verbindung und Antwort.
const TIMEOUT: Duration = Duration::from_secs(30);

/// Prüft die Erreichbarkeit aller in den Funden enthaltenen `.onion`-Adressen
/// über den Tor-SOCKS5-Proxy und liefert je Adresse einen Fund.
pub fn check_onions(findings: &[Finding], proxy: &str) -> Vec<Finding> {
    // Eindeutige Onion-Adressen aus den Tor-Funden sammeln.
    let mut adressen: Vec<&str> = findings
        .iter()
        .filter(|f| f.domain == "tor")
        .filter_map(|f| {
            let host = f.name.split(['/', ' ']).find(|t| t.ends_with(".onion"))?;
            Some(host)
        })
        .collect();
    adressen.sort_unstable();
    adressen.dedup();

    adressen
        .into_iter()
        .map(|onion| {
            let (erreichbar, hinweis) = match reach(proxy, onion, 80) {
                Ok(true) => ("ja", String::new()),
                Ok(false) => ("nein", "Verbindung vom Proxy abgelehnt".to_string()),
                Err(e) => ("unbekannt", e),
            };
            let mut f = Finding::new("tor", onion.to_string(), format!("Tor SOCKS5 {proxy}"))
                .with("art", "liveness")
                .with("erreichbar", erreichbar);
            if !hinweis.is_empty() {
                f = f.with("hinweis", hinweis);
            }
            f
        })
        .collect()
}

/// Baut über den SOCKS5-Proxy eine Verbindung zu `host:port` auf. `Ok(true)`,
/// wenn der Proxy die Verbindung herstellt.
fn reach(proxy: &str, host: &str, port: u16) -> Result<bool, String> {
    let addr = proxy
        .to_socket_addrs()
        .map_err(|e| format!("Proxy-Adresse ungültig: {e}"))?
        .next()
        .ok_or_else(|| "Proxy-Adresse leer".to_string())?;
    let mut stream = TcpStream::connect_timeout(&addr, TIMEOUT)
        .map_err(|e| format!("Proxy nicht erreichbar: {e}"))?;
    stream.set_read_timeout(Some(TIMEOUT)).ok();
    stream.set_write_timeout(Some(TIMEOUT)).ok();

    // SOCKS5-Handshake ohne Authentifizierung.
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .map_err(|e| e.to_string())?;
    let mut hello = [0u8; 2];
    stream.read_exact(&mut hello).map_err(|e| e.to_string())?;
    if hello != [0x05, 0x00] {
        return Err("Proxy spricht kein SOCKS5 ohne Auth".to_string());
    }

    // CONNECT mit Domainname (ATYP 0x03) an host:port.
    let host = host.as_bytes();
    if host.len() > 255 {
        return Err("Hostname zu lang".to_string());
    }
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    req.extend_from_slice(host);
    req.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&req).map_err(|e| e.to_string())?;

    // Antwort: Version, Reply-Code (0x00 = Erfolg), ...
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).map_err(|e| e.to_string())?;
    Ok(resp[1] == 0x00)
}
