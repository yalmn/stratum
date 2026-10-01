//! Entität: ein Objekt mit eigener Identität (Benutzer, Datei, Host, ...).
//!
//! Die Identität hängt nie am Anzeigenamen, sondern an einem kanonischen
//! Schlüssel je Art ([`canonical`]). Unsichere Zusammenführungen werden nicht
//! still vorgenommen, sondern als Beziehung `POSSIBLY_SAME_AS` modelliert.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::ids::{CaseId, EntityId};

/// Art einer Entität.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    /// Rechner.
    Host,
    /// Benutzerkonto.
    UserAccount,
    /// Benutzergruppe.
    UserGroup,
    /// Datei.
    File,
    /// Datenstrom einer Datei.
    FileStream,
    /// Verzeichnis.
    Directory,
    /// Volume oder Laufwerksbuchstabe (Ergänzung zur Zielarchitektur).
    Volume,
    /// Netzwerkfreigabe (Ergänzung zur Zielarchitektur).
    NetworkShare,
    /// Prozess.
    Process,
    /// Dienst.
    Service,
    /// Geplante Aufgabe.
    ScheduledTask,
    /// Registry-Schlüssel.
    RegistryKey,
    /// Registry-Wert.
    RegistryValue,
    /// IP-Adresse.
    IpAddress,
    /// Netzwerk-Endpunkt (Adresse und Port).
    NetworkEndpoint,
    /// Domänenname.
    DomainName,
    /// URL.
    Url,
    /// MAC-Adresse.
    MacAddress,
    /// Netzwerkschnittstelle.
    NetworkInterface,
    /// E-Mail-Adresse.
    EmailAddress,
    /// Browser-Profil.
    BrowserProfile,
    /// USB-Gerät.
    UsbDevice,
    /// Zertifikat.
    Certificate,
    /// Hashwert.
    Hash,
    /// Software.
    Software,
    /// Paket.
    Package,
    /// Container.
    Container,
    /// Virtuelle Maschine.
    VirtualMachine,
    /// Datenbank.
    Database,
    /// Datenbankkonto.
    DatabaseAccount,
    /// Cloud-Konto.
    CloudAccount,
    /// Cloud-Ressource.
    CloudResource,
    /// Mobilgerät.
    MobileDevice,
    /// Anwendung.
    Application,
    /// Schadsoftware.
    Malware,
    /// Werkzeug.
    Tool,
    /// Sonstiges.
    Other,
}

impl EntityKind {
    /// Name der Art wie in JSON (für Schlüssel und IDs).
    pub fn as_str(self) -> String {
        serde_json::to_value(self)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default()
    }
}

/// Eine Entität.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entity {
    /// Deterministische ID aus Fall, Art und kanonischem Schlüssel.
    pub id: EntityId,
    /// Fall.
    pub case_id: CaseId,
    /// Art.
    pub kind: EntityKind,
    /// Kanonischer Schlüssel (Identität).
    pub canonical_key: String,
    /// Anzeigename (nie Identität).
    pub display_name: String,
    /// Weitere Angaben.
    pub attributes: JsonValue,
    /// Erstmals gesehen (Artefaktzeit).
    pub first_seen: Option<DateTime<Utc>>,
    /// Zuletzt gesehen (Artefaktzeit).
    pub last_seen: Option<DateTime<Utc>>,
    /// Zeitpunkt der Erfassung in stratum (Analysezeit).
    pub created_at: DateTime<Utc>,
}

impl Entity {
    /// Entität mit ID aus Fall, Art und kanonischem Schlüssel.
    pub fn new(
        case_id: CaseId,
        kind: EntityKind,
        canonical_key: String,
        display_name: String,
        created_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id: EntityId::derive(case_id, &kind.as_str(), &canonical_key),
            case_id,
            kind,
            canonical_key,
            display_name,
            attributes: JsonValue::Null,
            first_seen: None,
            last_seen: None,
            created_at,
        }
    }
}

/// Kanonische Schlüssel nach den Identitätsregeln der Zielarchitektur.
pub mod canonical {
    use std::net::IpAddr;

    /// Windows-Benutzer: SID vor `DOMÄNE\Benutzer` vor Benutzername. Groß-
    /// und Kleinschreibung zählt bei Windows-Namen nicht.
    pub fn windows_user(
        sid: Option<&str>,
        domain: Option<&str>,
        user: Option<&str>,
    ) -> Option<String> {
        if let Some(sid) = sid.map(str::trim).filter(|s| is_sid(s)) {
            return Some(format!("sid:{}", sid.to_ascii_uppercase()));
        }
        let user = user.map(str::trim).filter(|u| !u.is_empty())?;
        match domain.map(str::trim).filter(|d| !d.is_empty() && *d != ".") {
            Some(d) => Some(format!(
                "name:{}\\{}",
                d.to_lowercase(),
                user.to_lowercase()
            )),
            None => Some(format!("name:{}", user.to_lowercase())),
        }
    }

    fn is_sid(s: &str) -> bool {
        let mut teile = s.split('-');
        teile.next().is_some_and(|p| p.eq_ignore_ascii_case("S")) && teile.next() == Some("1") && {
            let rest: Vec<&str> = teile.collect();
            !rest.is_empty()
                && rest
                    .iter()
                    .all(|t| !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit()))
        }
    }

    /// NTFS-Datei: SHA-256 der Evidence, Volume-Offset, MFT-Nummer und
    /// Sequenznummer. Über den Evidence-Hash statt der Import-ID, damit ein
    /// erneuter Import dieselbe Identität ergibt.
    pub fn ntfs_file(
        evidence_sha256: &str,
        volume_offset: u64,
        mft_record: u64,
        sequence: u16,
    ) -> String {
        format!(
            "ntfs:{}:{volume_offset}:{mft_record}:{sequence}",
            evidence_sha256.to_ascii_lowercase()
        )
    }

    /// Prozess: Host, Boot- bzw. Sitzungskontext, PID und Startzeit
    /// (FILETIME oder Unix-Zeit als Text, wie in der Quelle).
    pub fn process(host: &str, boot_context: &str, pid: u64, start: &str) -> String {
        format!(
            "process:{}:{boot_context}:{pid}:{start}",
            host.to_lowercase()
        )
    }

    /// Domänenname: Kleinbuchstaben, ohne abschließenden Punkt. Internationale
    /// Namen werden nicht in Punycode umgewandelt.
    pub fn domain(fqdn: &str) -> Option<String> {
        let d = fqdn.trim().trim_end_matches('.').to_lowercase();
        (!d.is_empty() && !d.contains(char::is_whitespace)).then_some(d)
    }

    /// IP-Adresse in Normalform (IPv6 komprimiert, Kleinbuchstaben).
    pub fn ip(addr: &str) -> Option<String> {
        addr.trim().parse::<IpAddr>().ok().map(|a| a.to_string())
    }

    /// Hashwert: Algorithmus und Hex-Wert in Kleinbuchstaben.
    pub fn hash(algorithm: &str, value: &str) -> Option<String> {
        let v = value.trim().to_ascii_lowercase();
        (!v.is_empty() && v.bytes().all(|b| b.is_ascii_hexdigit()))
            .then(|| format!("{}:{v}", algorithm.trim().to_ascii_lowercase()))
    }
}

#[cfg(test)]
mod tests {
    use super::canonical::*;
    use super::*;
    use uuid::Uuid;

    #[test]
    fn windows_benutzer_nach_rangfolge() {
        assert_eq!(
            windows_user(Some("s-1-5-21-1-2-3-1001"), Some("WIN"), Some("Alice")).as_deref(),
            Some("sid:S-1-5-21-1-2-3-1001")
        );
        assert_eq!(
            windows_user(None, Some("CORP"), Some("Alice")).as_deref(),
            Some("name:corp\\alice")
        );
        assert_eq!(
            windows_user(None, Some("."), Some("ALICE")).as_deref(),
            Some("name:alice")
        );
        // Ungültige SID fällt auf den Namen zurück.
        assert_eq!(
            windows_user(Some("S-1-x"), None, Some("bob")).as_deref(),
            Some("name:bob")
        );
        assert_eq!(windows_user(None, None, None), None);
    }

    #[test]
    fn netz_und_hash() {
        assert_eq!(ip(" 2001:DB8:0:0:0:0:0:1 ").as_deref(), Some("2001:db8::1"));
        assert_eq!(ip("10.0.0.1").as_deref(), Some("10.0.0.1"));
        assert_eq!(ip("10.0.0.256"), None);
        assert_eq!(domain("Login.Live.COM.").as_deref(), Some("login.live.com"));
        assert_eq!(domain(" "), None);
        assert_eq!(hash("SHA256", "ABCdef").as_deref(), Some("sha256:abcdef"));
        assert_eq!(hash("md5", "xyz"), None);
    }

    #[test]
    fn gleiche_identitaet_gleiche_id() {
        let fall = CaseId(Uuid::from_u128(1));
        let t = DateTime::from_timestamp(0, 0).unwrap();
        let a = Entity::new(
            fall,
            EntityKind::UserAccount,
            windows_user(Some("S-1-5-18"), None, None).unwrap(),
            "SYSTEM".into(),
            t,
        );
        let b = Entity::new(
            fall,
            EntityKind::UserAccount,
            windows_user(Some("s-1-5-18"), None, Some("Lokales System")).unwrap(),
            "Lokales System".into(),
            t,
        );
        assert_eq!(a.id, b.id);
        assert_eq!(EntityKind::UserAccount.as_str(), "user_account");
        assert_eq!(ntfs_file("ABC", 1024, 42, 3), "ntfs:abc:1024:42:3");
    }
}
