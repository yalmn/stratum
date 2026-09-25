//! Domäne „Tor / Hidden Service": beantwortet, ob das Image einen versteckten
//! Dienst im Tor-Netz betrieben oder Tor genutzt hat.
//!
//! Die Analyse ist rein offline und gezielt: über den Pfad-Index werden die
//! bekannten Tor-Artefakte gesucht und gelesen, nicht der Rohdatenträger.
//!
//! - `hostname` in einem Hidden-Service-Verzeichnis enthält die `.onion`-Adresse.
//! - `hs_ed25519_secret_key` ist der private Schlüssel des Dienstes; sein
//!   Vorhandensein belegt, dass der Dienst hier betrieben wurde (nicht nur
//!   besucht).
//! - `torrc` konfiguriert Tor (`HiddenServiceDir`, `HiddenServicePort`, ...).
//! - Eine Webserver-Konfiguration, die nur auf `127.0.0.1` lauscht, ist ein
//!   typisches Backend hinter einem Hidden Service.
//!
//! Ob der Dienst noch erreichbar ist, lässt sich offline nicht feststellen; das
//! ist Aufgabe einer späteren, ausdrücklich einzuschaltenden Online-Prüfung.

use stratum_ntfs::NtfsVolume;

use crate::{AnalysisContext, Analyzer, Finding, Outcome};

/// Länge einer v3-Onion-Adresse ohne die Endung `.onion`.
const ONION_LEN: usize = 56;
/// Höchstmenge, die aus einer Konfigurationsdatei betrachtet wird.
const MAX_CONFIG: usize = 1 << 20;

/// Analyzer für Tor-Hidden-Service-Spuren.
pub struct TorAnalyzer;

impl Analyzer for TorAnalyzer {
    fn domain(&self) -> &str {
        "tor"
    }

    fn run(&self, ctx: &AnalysisContext<'_>) -> Outcome {
        let mut out = Outcome::default();

        for v in &ctx.volumes {
            let mut vol = match NtfsVolume::open(ctx.img, v.target.offset, v.target.size) {
                Ok(vol) => vol,
                Err(e) => {
                    out.warnings
                        .push(format!("Offset {} nicht lesbar: {e}", v.target.offset));
                    continue;
                }
            };

            // hostname: enthaelt die .onion-Adresse des Hidden Service.
            for e in v.by_name("hostname") {
                if let Some(data) = read(&mut vol, e.mft_record, &e.path) {
                    if let Some(addr) = find_onion(&data) {
                        out.findings.push(
                            Finding::new("tor", addr, &e.path)
                                .with("art", "hidden_service_hostname")
                                .with("hinweis", "Onion-Adresse eines betriebenen Hidden Service"),
                        );
                    }
                }
            }

            // Privater Schlüssel: belegt den Betrieb des Dienstes.
            for name in ["hs_ed25519_secret_key", "hs_ed25519_public_key"] {
                for e in v.by_name(name) {
                    out.findings.push(
                        Finding::new("tor", name, &e.path)
                            .with("art", "hidden_service_key")
                            .with(
                                "hinweis",
                                if name.contains("secret") {
                                    "privater Schlüssel des Hidden Service (Betrieb belegt)"
                                } else {
                                    "öffentlicher Schlüssel des Hidden Service"
                                },
                            ),
                    );
                }
            }

            // torrc: Konfiguration von Tor und Hidden Services.
            for e in v.by_name("torrc") {
                if let Some(data) = read(&mut vol, e.mft_record, &e.path) {
                    let mut had_line = false;
                    for line in text(&data).lines() {
                        let t = line.trim();
                        if t.is_empty() || t.starts_with('#') {
                            continue;
                        }
                        let low = t.to_ascii_lowercase();
                        if low.starts_with("hiddenservicedir")
                            || low.starts_with("hiddenserviceport")
                            || low.starts_with("socksport")
                            || low.starts_with("controlport")
                        {
                            had_line = true;
                            out.findings.push(
                                Finding::new("tor", t.to_string(), &e.path)
                                    .with("art", "torrc_direktive"),
                            );
                        }
                    }
                    if !had_line {
                        out.findings.push(
                            Finding::new("tor", "torrc", &e.path).with("art", "torrc_gefunden"),
                        );
                    }
                    if let Some(addr) = find_onion(&data) {
                        out.findings
                            .push(Finding::new("tor", addr, &e.path).with("art", "onion_in_torrc"));
                    }
                }
            }

            // Tor-Browser-Programmdatei.
            for e in v.by_name("tor.exe") {
                out.findings
                    .push(Finding::new("tor", "tor.exe", &e.path).with("art", "tor_programm"));
            }

            // Webserver-Konfiguration, die nur auf localhost lauscht: typisches
            // Backend hinter einem Hidden Service.
            for name in ["nginx.conf", "httpd.conf", "apache2.conf"] {
                for e in v.by_name(name) {
                    if let Some(data) = read(&mut vol, e.mft_record, &e.path) {
                        if let Some(line) = find_localhost_listen(&data) {
                            out.findings.push(
                                Finding::new("tor", line, &e.path)
                                    .with("art", "webserver_localhost")
                                    .with(
                                        "hinweis",
                                        "Webserver lauscht nur lokal (mögliches Hidden-Service-Backend)",
                                    ),
                            );
                        }
                    }
                }
            }
        }

        out
    }
}

fn read(vol: &mut NtfsVolume<'_>, record: u64, path: &str) -> Option<Vec<u8>> {
    vol.read_file_by_record(record, path)
        .ok()
        .flatten()
        .map(|f| f.data)
}

/// Die ersten `MAX_CONFIG` Bytes als verlustfrei dekodierter Text.
fn text(data: &[u8]) -> String {
    let end = data.len().min(MAX_CONFIG);
    String::from_utf8_lossy(&data[..end]).into_owned()
}

/// Sucht die erste gültige v3-Onion-Adresse (56 base32-Zeichen vor `.onion`).
fn find_onion(data: &[u8]) -> Option<String> {
    let needle = b".onion";
    let end = data.len().min(MAX_CONFIG);
    let hay = &data[..end];
    let mut i = 0;
    while let Some(pos) = find(&hay[i..], needle) {
        let start = i + pos;
        if let Some(addr_start) = start.checked_sub(ONION_LEN) {
            let addr = &hay[addr_start..start];
            if addr.iter().all(|&b| is_base32(b)) {
                let full: String = hay[addr_start..start + needle.len()]
                    .iter()
                    .map(|&b| b as char)
                    .collect();
                return Some(full);
            }
        }
        i = start + needle.len();
    }
    None
}

/// Sucht eine `listen`/`Listen`-Zeile, die an 127.0.0.1 bzw. localhost gebunden ist.
fn find_localhost_listen(data: &[u8]) -> Option<String> {
    for line in text(data).lines() {
        let t = line.trim();
        let low = t.to_ascii_lowercase();
        if low.starts_with("listen") && (low.contains("127.0.0.1") || low.contains("localhost")) {
            return Some(t.to_string());
        }
    }
    None
}

fn is_base32(b: u8) -> bool {
    b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b)
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn onion_aus_hostname() {
        let addr = "a".repeat(ONION_LEN);
        let data = format!("{addr}.onion\n");
        assert_eq!(find_onion(data.as_bytes()), Some(format!("{addr}.onion")));
    }

    #[test]
    fn kurze_onion_wird_nicht_erkannt() {
        assert_eq!(find_onion(b"kurz.onion\n"), None);
    }

    #[test]
    fn localhost_listen_erkannt() {
        let cfg = "server {\n  listen 127.0.0.1:8080;\n}\n";
        assert_eq!(
            find_localhost_listen(cfg.as_bytes()).as_deref(),
            Some("listen 127.0.0.1:8080;")
        );
        assert!(find_localhost_listen(b"listen 0.0.0.0:80;").is_none());
    }
}
