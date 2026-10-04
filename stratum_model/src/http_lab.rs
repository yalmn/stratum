//! Offline-HTTP-Rekonstruktion. Die Antwort ist eine Hypothese, keine Evidence.
use serde::{Deserialize, Serialize};

/// Richtung der untersuchten Kommunikation, vom Analysten festgelegt.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpDirection {
    /// Angreifer-Request an das untersuchte System.
    Incoming,
    /// Verbindung vom untersuchten System zum verdächtigen Server.
    Outgoing,
}

/// Quellobjekt, dessen ursprüngliche Provenance unverändert erhalten bleibt.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpSource {
    /// Nur artifact oder entity.
    pub kind: String,
    /// Objekt-ID im selben Fall.
    pub id: uuid::Uuid,
}

/// Ein einzelner, ausdrücklich angeforderter Offline-Versuch.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpReplayRequest {
    /// Untersuchungsrichtung, kein automatisch bestätigter Angriff.
    pub direction: HttpDirection,
    /// Ursprüngliche HTTP(S)-URL. Niemals das tatsächliche Verbindungsziel.
    pub url: String,
    /// HTTP-Methode.
    pub method: String,
    /// Zusätzliche Header, ohne Transportsteuerung oder Zugangsdaten.
    pub headers: Vec<[String; 2]>,
    /// Synthetischer UTF-8-Requestbody.
    pub body: String,
    /// Hypothetischer Antwortstatus des simulierten Servers.
    pub simulated_status: u16,
    /// Hypothetischer UTF-8-Antwortbody.
    pub simulated_body: String,
    /// Zu prüfende Annahme, vom Analysten formuliert.
    pub hypothesis: String,
    /// Optionaler Quellenverweis; ohne Quelle ist der Versuch manuell.
    pub source: Option<HttpSource>,
}

impl HttpReplayRequest {
    /// Prüft Limits und unterstützte HTTP-Semantik ohne Netzwerkzugriff.
    pub fn pruefen(&self) -> Result<(), String> {
        if self.url.len() > 2048 || self.url.bytes().any(|b| b.is_ascii_control()) {
            return Err("URL ungültig oder länger als 2048 Bytes".into());
        }
        let u = url::Url::parse(&self.url).map_err(|_| "HTTP(S)-URL erforderlich")?;
        if !["http", "https"].contains(&u.scheme())
            || u.host().is_none()
            || !u.username().is_empty()
            || u.password().is_some()
            || u.fragment().is_some()
        {
            return Err("HTTP(S)-URL ohne Zugangsdaten oder Fragment erforderlich".into());
        }
        if !["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]
            .contains(&self.method.as_str())
        {
            return Err("HTTP-Methode nicht unterstützt".into());
        }
        if self.body.len() > 65536 || self.simulated_body.len() > 65536 {
            return Err("Request und Antwort höchstens jeweils 64 KiB UTF-8".into());
        }
        if !(200..=599).contains(&self.simulated_status)
            || self.hypothesis.trim().is_empty()
            || self.hypothesis.len() > 2000
        {
            return Err(
                "Antwortstatus 200 bis 599 und Hypothese bis 2000 Bytes erforderlich".into(),
            );
        }
        if self.headers.len() > 32 {
            return Err("Höchstens 32 Header".into());
        }
        let mut names = std::collections::HashSet::new();
        for [name, value] in &self.headers {
            let key = name.to_ascii_lowercase();
            if name.is_empty()
                || name.len() > 128
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
                || value.len() > 2048
                || value.bytes().any(|b| !(32..=126).contains(&b))
                || !names.insert(key.clone())
                || [
                    "host",
                    "content-length",
                    "transfer-encoding",
                    "connection",
                    "expect",
                    "authorization",
                    "proxy-authorization",
                    "cookie",
                    "upgrade",
                    "trailer",
                ]
                .contains(&key.as_str())
            {
                return Err(
                    "Header ungültig, doppelt oder für Transport/Zugangsdaten reserviert".into(),
                );
            }
        }
        if self
            .source
            .as_ref()
            .is_some_and(|s| !["artifact", "entity"].contains(&s.kind.as_str()))
        {
            return Err("Quelle muss Artefakt oder Entität sein".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn request_grenzen_und_transportsteuerung() {
        let mut r = HttpReplayRequest {
            direction: HttpDirection::Outgoing,
            url: "https://suspicious.invalid/beacon?id=fixture".into(),
            method: "POST".into(),
            headers: vec![],
            body: "ping".into(),
            simulated_status: 200,
            simulated_body: "ok".into(),
            hypothesis: "Synthetischen Beacon prüfen".into(),
            source: None,
        };
        assert!(r.pruefen().is_ok());
        for name in [
            "Host",
            "Cookie",
            "Authorization",
            "Transfer-Encoding",
            "bad\r\nheader",
        ] {
            r.headers = vec![[name.into(), "x".into()]];
            assert!(r.pruefen().is_err());
        }
        r.headers = vec![["X-Test".into(), "x\r\ny".into()]];
        assert!(r.pruefen().is_err());
        r.headers.clear();
        r.method = "CONNECT".into();
        assert!(r.pruefen().is_err());
        r.method = "GET".into();
        r.body = "a".repeat(65537);
        assert!(r.pruefen().is_err());
        r.body.clear();
        for u in [
            "file:///etc/passwd",
            "http://user:password@example.org/",
            "http://example.org/#fragment",
        ] {
            r.url = u.into();
            assert!(r.pruefen().is_err());
        }
    }
}
