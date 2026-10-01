//! Programmausführung: Amcache, Shimcache und BAM/DAM.
//!
//! Die drei Quellen sagen Unterschiedliches aus und werden deshalb
//! unterschiedlich abgebildet:
//! - Amcache: die Datei war dem System bekannt, mit SHA-1. Die Zeit ist die
//!   letzte Änderung des Registry-Schlüssels, keine Ausführungszeit.
//! - Shimcache: die Datei war dem Kompatibilitäts-Cache bekannt. Die Zeit ist
//!   die Änderungszeit der Datei, keine Ausführung.
//! - BAM/DAM: letzte Ausführung durch einen Benutzer (SID).

use serde_json::json;
use stratum_analysis::RawFinding;
use stratum_model::{
    canonical, ArtifactKind, DerivationKind, Entity, EntityId, EntityKind, Event, EventId,
    EventKind, EventParticipant, ParticipantRole, Relationship, RelationshipKind, SourceLocator,
    TimeSemantics,
};

use crate::hilfen::{artefakt, benutzer, datei, herkunft, herkunft_zusatz, host, text, zahl, zeit};
use crate::{Abbildung, Baukasten, GELESEN};

pub fn abbilden(f: &RawFinding, b: &mut Baukasten<'_>) -> Abbildung {
    match (text(f, "quelle"), text(f, "art")) {
        (Some("amcache"), _) => amcache(f, b),
        (Some("shimcache"), _) => shimcache(f, b),
        (_, Some("bam" | "dam")) => bam(f, b),
        _ => {
            b.hinweis(format!(
                "Programmausführung ohne bekannte Quelle: {}",
                f.name
            ));
            Abbildung::FundstelleUnvollstaendig
        }
    }
}

fn vollstaendig(f: &RawFinding) -> Abbildung {
    if zahl(f, "hive_offset").is_some() {
        Abbildung::Vollstaendig
    } else {
        Abbildung::FundstelleUnvollstaendig
    }
}

/// Fundstelle in der Registry; der Hive-Name steht vor dem ersten `\` der
/// Quelle.
fn registry(f: &RawFinding, wert: Option<&str>) -> SourceLocator {
    let (hive, pfad) = f.source.split_once('\\').unwrap_or(("?", &f.source));
    SourceLocator::Registry {
        hive: hive.to_string(),
        key_path: pfad.to_string(),
        value_name: wert.map(str::to_string),
        cell_offset: zahl(f, "hive_offset"),
    }
}

fn mit_host(
    b: &mut Baukasten<'_>,
    eid: EventId,
    mut t: Vec<EventParticipant>,
) -> Vec<EventParticipant> {
    if let Some(h) = host(b) {
        t.push(EventParticipant {
            event_id: eid,
            entity_id: h,
            role: ParticipantRole::Host,
        });
    }
    t
}

fn teilnehmer(eid: EventId, entity_id: EntityId, role: ParticipantRole) -> EventParticipant {
    EventParticipant {
        event_id: eid,
        entity_id,
        role,
    }
}

/// Amcache `InventoryApplicationFile`: Datei mit SHA-1 und dem Zeitpunkt, zu
/// dem der Eintrag zuletzt geschrieben wurde.
fn amcache(f: &RawFinding, b: &mut Baukasten<'_>) -> Abbildung {
    let pfad = text(f, "pfad").unwrap_or(&f.name);
    let schluessel = format!("registry:{}{}", f.source, herkunft_zusatz(f));
    let locator = registry(f, None);
    let (aid, oid) = artefakt(
        b,
        f,
        ArtifactKind::RegistryKey,
        locator.clone(),
        &schluessel,
        "amcache_entry",
    );
    let zeit = zeit(f, "registriert", TimeSemantics::ArtifactTime);
    let did = datei(b, pfad, zeit.as_ref().map(|z| z.utc));

    if let Some(key) = text(f, "sha1").and_then(|h| canonical::hash("sha1", h)) {
        let anzeige = key.trim_start_matches("sha1:").to_string();
        let mut e = Entity::new(b.k.case_id, EntityKind::Hash, key, anzeige, b.k.zeitpunkt);
        e.attributes = json!({"algorithmus": "sha1"});
        let hid = b.entity(e, None);
        let prov = herkunft(b, f, aid, oid, locator.clone());
        b.relationship(
            Relationship::new(b.k.case_id, RelationshipKind::HasHash, did, hid, GELESEN),
            prov,
        );
    }

    if let Some(zeit) = zeit {
        let eid = EventId::derive(b.k.case_id, "amcache_recorded", &schluessel);
        let t = mit_host(b, eid, vec![teilnehmer(eid, did, ParticipantRole::File)]);
        let prov = herkunft(b, f, aid, oid, locator);
        b.event(
            Event {
                id: eid,
                case_id: b.k.case_id,
                kind: EventKind::Custom,
                occurred_at: Some(zeit),
                ended_at: None,
                attributes: json!({
                    "art": "amcache_recorded",
                    "quelle": "amcache",
                    "zeitpunkt": "schluessel_letzte_aenderung",
                }),
                derivation: GELESEN,
                created_at: b.k.zeitpunkt,
            },
            t,
            prov,
        );
    }
    vollstaendig(f)
}

/// Shimcache: ein Wert mit vielen Einträgen. Jeder Eintrag ist ein eigenes
/// Artefakt; die Fundstelle ist der Wert, die Position des Eintrags steht in
/// der Observation.
fn shimcache(f: &RawFinding, b: &mut Baukasten<'_>) -> Abbildung {
    let pfad = text(f, "pfad").unwrap_or(&f.name);
    let eintrag = text(f, "eintrag").unwrap_or("?");
    let schluessel = format!("registry:{}:{eintrag}{}", f.source, herkunft_zusatz(f));
    // Quelle endet auf `\AppCompatCache` (Wertname).
    let mut locator = registry(f, Some("AppCompatCache"));
    if let SourceLocator::Registry { key_path, .. } = &mut locator {
        if let Some(k) = key_path.strip_suffix("\\AppCompatCache") {
            *key_path = k.to_string();
        }
    }
    let (aid, oid) = artefakt(
        b,
        f,
        ArtifactKind::RegistryValue,
        locator.clone(),
        &schluessel,
        "shimcache_entry",
    );
    let zeit = zeit(f, "letzte_aenderung", TimeSemantics::EventTime);
    let did = datei(b, pfad, zeit.as_ref().map(|z| z.utc));
    if let Some(zeit) = zeit {
        let eid = EventId::derive(b.k.case_id, "file_modified", &schluessel);
        let t = mit_host(b, eid, vec![teilnehmer(eid, did, ParticipantRole::File)]);
        let prov = herkunft(b, f, aid, oid, locator);
        b.event(
            Event {
                id: eid,
                case_id: b.k.case_id,
                kind: EventKind::FileModified,
                occurred_at: Some(zeit),
                ended_at: None,
                attributes: json!({
                    "quelle": "shimcache",
                    "eintrag": eintrag,
                    "zeitpunkt": "datei_letzte_aenderung",
                }),
                // Die Zeit stammt aus dem Dateisystem und wurde vom Cache
                // übernommen; sie belegt keine Ausführung.
                derivation: DerivationKind::Derived,
                created_at: b.k.zeitpunkt,
            },
            t,
            prov,
        );
    }
    vollstaendig(f)
}

/// BAM/DAM: letzte Ausführung eines Programms durch den Benutzer mit der SID
/// des Schlüssels.
fn bam(f: &RawFinding, b: &mut Baukasten<'_>) -> Abbildung {
    let art = text(f, "art").unwrap_or("bam");
    let schluessel = format!("registry:{}:{}{}", f.source, f.name, herkunft_zusatz(f));
    let locator = registry(f, Some(&f.name));
    let (aid, oid) = artefakt(
        b,
        f,
        ArtifactKind::RegistryValue,
        locator.clone(),
        &schluessel,
        "bam_entry",
    );
    let zeit = zeit(f, "letzte_ausfuehrung", TimeSemantics::EventTime);
    let gesehen = zeit.as_ref().map(|z| z.utc);
    let did = datei(b, &f.name, gesehen);
    let uid = benutzer(b, None, text(f, "sid"), None, gesehen);
    if let Some(zeit) = zeit {
        let eid = EventId::derive(b.k.case_id, "process_start", &schluessel);
        let mut t = vec![teilnehmer(eid, did, ParticipantRole::Executable)];
        if let Some(u) = uid {
            t.push(teilnehmer(eid, u, ParticipantRole::User));
        }
        let t = mit_host(b, eid, t);
        let prov = herkunft(b, f, aid, oid, locator);
        b.event(
            Event {
                id: eid,
                case_id: b.k.case_id,
                kind: EventKind::ProcessStart,
                occurred_at: Some(zeit),
                ended_at: None,
                attributes: json!({"quelle": art, "zeitpunkt": "letzte_ausfuehrung"}),
                derivation: GELESEN,
                created_at: b.k.zeitpunkt,
            },
            t,
            prov,
        );
    }
    vollstaendig(f)
}
