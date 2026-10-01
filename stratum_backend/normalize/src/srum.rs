//! SRUM: Ressourcennutzung je Programm und Konto aus `SRUDB.dat`.
//!
//! Jede Zeile ergibt ein Ereignis mit Programm, Konto und Rechner. Die Zeit
//! ist `TimeStamp` der Zeile. Was dieser Zeitpunkt genau festhält (Ende des
//! Erfassungszeitraums oder Zeitpunkt des Schreibens), ist nicht belegt; er
//! wird deshalb als Artefaktzeit gekennzeichnet, nicht als Zeitpunkt der
//! Nutzung.
//!
//! Das Programm hängt vom Kennungstyp in `SruDbIdMapTable` ab:
//! - Typ 1: Dienstname (an den Daten geprüft: Dnscache, Dhcp, wuauserv),
//!   dieselbe Entität wie bei Persistenz und Ereignis 7045.
//! - Typ 2: App-Paket.
//! - Typ 0: Pfad (Datei), Programmname oder eine Kennung der App-Timeline
//!   wie `!!svchost.exe!2104/11/12:20:36:41!19466![netsvcs]`, aus der der
//!   Programmname genommen wird.
//! - Typ 3: Konto (SID).

use serde_json::json;
use stratum_analysis::RawFinding;
use stratum_model::{
    ArtifactKind, Entity, EntityId, EntityKind, Event, EventId, EventKind, EventParticipant,
    ForensicTime, ParticipantRole, Relationship, RelationshipKind, SourceLocator, TimeSemantics,
};

use crate::hilfen::{
    artefakt, benutzer, datei, dienst, herkunft, herkunft_zusatz, host, ntfs, text, zahl,
};
use crate::{Abbildung, Baukasten, GELESEN};

pub fn abbilden(f: &RawFinding, b: &mut Baukasten<'_>) -> Abbildung {
    let zeile = text(f, "art") == Some("srum");
    let schluessel = format!(
        "srum:{}:{}:{}:{}{}",
        text(f, "mft_record").unwrap_or("?"),
        text(f, "tabelle").unwrap_or("db"),
        text(f, "AutoIncId").unwrap_or(""),
        text(f, "datei_offset").unwrap_or(""),
        herkunft_zusatz(f)
    );
    let (locator, ok) = match ntfs(f) {
        Some(l) => (l, true),
        None => (
            SourceLocator::FileLine {
                path: f.source.clone(),
                line: 0,
                byte_offset: zahl(f, "datei_offset"),
            },
            false,
        ),
    };
    let kind = if zeile {
        ArtifactKind::EseRecord
    } else {
        ArtifactKind::NtfsStream
    };
    let (aid, oid) = artefakt(
        b,
        f,
        kind,
        locator.clone(),
        &schluessel,
        if zeile { "srum_record" } else { "srum_db" },
    );
    if !zeile {
        return vollstaendig(ok);
    }

    let zeit = text(f, "zeitpunkt_ole")
        .and_then(|s| s.parse::<f64>().ok())
        .and_then(|t| ForensicTime::from_ole_date(t, TimeSemantics::ArtifactTime));
    let gesehen = zeit.as_ref().map(|z| z.utc);
    let programm = programm(b, f, gesehen);
    let konto = text(f, "konto").and_then(|sid| benutzer(b, None, Some(sid), None, gesehen));
    let prov = herkunft(b, f, aid, oid, locator);
    if let (Some(k), Some(p)) = (konto, programm) {
        let mut r = Relationship::new(b.k.case_id, RelationshipKind::Uses, k, p, GELESEN);
        r.attributes = json!({"quelle": "srum"});
        b.relationship(r, prov.clone());
    }
    let Some(zeit) = zeit else {
        return vollstaendig(ok);
    };
    let eid = EventId::derive(b.k.case_id, "srum_usage", &schluessel);
    let mut t = Vec::new();
    for (id, role) in [
        (programm, ParticipantRole::Executable),
        (konto, ParticipantRole::User),
        (host(b), ParticipantRole::Host),
    ] {
        if let Some(entity_id) = id {
            t.push(EventParticipant {
                event_id: eid,
                entity_id,
                role,
            });
        }
    }
    let mut attribute =
        json!({"art": "srum_usage", "quelle": "srum", "zeitpunkt": "srum_timestamp"});
    for k in ["anbieter", "tabelle"] {
        if let Some(v) = text(f, k) {
            attribute[k] = json!(v);
        }
    }
    b.event(
        Event {
            id: eid,
            case_id: b.k.case_id,
            kind: EventKind::Custom,
            occurred_at: Some(zeit),
            ended_at: None,
            attributes: attribute,
            derivation: GELESEN,
            created_at: b.k.zeitpunkt,
        },
        t,
        prov,
    );
    vollstaendig(ok)
}

fn vollstaendig(ok: bool) -> Abbildung {
    if ok {
        Abbildung::Vollstaendig
    } else {
        Abbildung::FundstelleUnvollstaendig
    }
}

/// Programmname aus einer Kennung der App-Timeline (`!!name.exe!…`).
pub(crate) fn timeline_name(kennung: &str) -> Option<&str> {
    kennung
        .strip_prefix("!!")?
        .split('!')
        .next()
        .filter(|n| !n.is_empty())
}

fn programm(
    b: &mut Baukasten<'_>,
    f: &RawFinding,
    gesehen: Option<chrono::DateTime<chrono::Utc>>,
) -> Option<EntityId> {
    let name = text(f, "programm")?;
    let anwendung = |b: &mut Baukasten<'_>, n: &str| {
        let e = Entity::new(
            b.k.case_id,
            EntityKind::Application,
            format!("programm:{}", n.to_lowercase()),
            n.to_string(),
            b.k.zeitpunkt,
        );
        b.entity(e, gesehen)
    };
    Some(match text(f, "programm_id_typ") {
        Some("1") => dienst(b, name, None, gesehen),
        Some("2") => anwendung(b, name),
        _ => {
            if let Some(n) = timeline_name(name) {
                anwendung(b, n)
            } else if name.starts_with('\\') || name.get(1..3) == Some(":\\") {
                // Dienstgruppe von svchost (`… [netsvcs]`) gehört nicht zum Pfad.
                let pfad = match name.find(" [") {
                    Some(i) if name.ends_with(']') => &name[..i],
                    _ => name,
                };
                datei(b, pfad, gesehen)
            } else {
                anwendung(b, name)
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::timeline_name;

    #[test]
    fn programmname_aus_timeline() {
        assert_eq!(
            timeline_name("!!svchost.exe!2104/11/12:20:36:41!19466![netsvcs] [TokenBroker]"),
            Some("svchost.exe")
        );
        assert_eq!(
            timeline_name("!!IsrDpc!1970/01/01:00:00:00!0!"),
            Some("IsrDpc")
        );
        assert_eq!(timeline_name("svchost.exe"), None);
        assert_eq!(timeline_name("!!"), None);
    }
}
