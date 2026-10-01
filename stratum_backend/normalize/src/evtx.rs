//! Ereignisprotokolle: je Datensatz ein Artefakt, eine Observation und ein
//! Ereignis mit den beteiligten Personen, dem Rechner und weiteren Objekten.

use serde_json::json;
use stratum_analysis::RawFinding;
use stratum_model::{
    canonical, ArtifactKind, DerivationKind, Entity, EntityKind, Event, EventId, EventKind,
    EventParticipant, ParticipantRole, Relationship, RelationshipKind, SourceLocator,
};

use crate::hilfen::{
    artefakt, benutzer, datei, herkunft, herkunft_zusatz, host, ntfs, text, zahl, zeit_filetime,
};
use crate::{Abbildung, Baukasten, GELESEN};

/// Ereignisart, eigener Name bei `Custom` und Ableitungsstatus je Nummer.
fn art(id: u64) -> (EventKind, Option<&'static str>, DerivationKind) {
    use EventKind::*;
    match id {
        4624 | 21 => (UserLogon, None, GELESEN),
        4625 | 4648 | 1149 => (AuthenticationAttempt, None, GELESEN),
        4634 | 4647 => (UserLogoff, None, GELESEN),
        4672 => (Custom, Some("special_privileges_assigned"), GELESEN),
        4688 => (ProcessStart, None, GELESEN),
        4697 | 7045 => (ServiceInstalled, None, GELESEN),
        4720 => (Custom, Some("account_created"), GELESEN),
        4722 => (Custom, Some("account_enabled"), GELESEN),
        4725 => (Custom, Some("account_disabled"), GELESEN),
        4726 => (Custom, Some("account_deleted"), GELESEN),
        4728 | 4732 | 4756 => (Custom, Some("group_member_added"), GELESEN),
        1102 | 104 => (Custom, Some("log_cleared"), GELESEN),
        25 => (Custom, Some("rdp_session_reconnected"), GELESEN),
        // Start und Stopp des Ereignisprotokolldienstes gelten als Hinweis
        // auf Systemstart und Herunterfahren, sind aber selbst nur der Dienst.
        6005 => (SystemBoot, None, DerivationKind::Derived),
        6006 => (SystemShutdown, None, DerivationKind::Derived),
        _ => (Custom, Some("unbekannt"), GELESEN),
    }
}

pub fn abbilden(f: &RawFinding, b: &mut Baukasten<'_>) -> Abbildung {
    let id = zahl(f, "event_id").unwrap_or(0);
    let record = zahl(f, "event_record_id").unwrap_or(0);
    let schluessel = format!(
        "evtx:{}:{}:{record}{}",
        text(f, "volume_offset").unwrap_or("?"),
        text(f, "mft_record").unwrap_or("?"),
        herkunft_zusatz(f)
    );
    // Vollständig, wenn die Stelle des Datensatzes in der Datei bekannt ist.
    // Ein fehlender Image-Offset bei NTFS-komprimierten Protokollen ist kein
    // Mangel: dort gibt es keine einzelne physische Stelle.
    let (locator, vollstaendig) = match ntfs(f) {
        Some(l) => (l, zahl(f, "datei_offset").is_some()),
        // Ohne NTFS-Anker bleibt die Stelle in der Protokolldatei.
        None => (
            SourceLocator::Evtx {
                path: f.source.clone(),
                record_id: record,
            },
            false,
        ),
    };
    let (aid, oid) = artefakt(
        b,
        f,
        ArtifactKind::EvtxRecord,
        locator.clone(),
        &schluessel,
        &format!("evtx_{id}"),
    );

    let zeit = zeit_filetime(f, "filetime");
    let gesehen = zeit.as_ref().map(|t| t.utc);
    let (kind, eigen, ableitung) = art(id);
    let kind_name = eigen.map(str::to_string).unwrap_or_else(|| {
        serde_json::to_value(kind)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default()
    });
    let eid = EventId::derive(b.k.case_id, &kind_name, &schluessel);

    let mut teilnehmer = Vec::new();
    let mut dazu = |entity, role| {
        teilnehmer.push(EventParticipant {
            event_id: eid,
            entity_id: entity,
            role,
        })
    };
    if let Some(h) = host(b) {
        dazu(h, ParticipantRole::Host);
    }
    let person = benutzer(
        b,
        text(f, "benutzer"),
        text(f, "benutzer_sid"),
        text(f, "benutzer_domaene"),
        gesehen,
    );
    let ausfuehrender = benutzer(
        b,
        text(f, "ausfuehrender"),
        text(f, "ausfuehrender_sid"),
        text(f, "ausfuehrender_domaene"),
        gesehen,
    );
    let gruppe = text(f, "gruppe_sid").or(text(f, "gruppe")).map(|g| {
        let key = canonical::windows_user(text(f, "gruppe_sid"), None, text(f, "gruppe"))
            .unwrap_or_else(|| format!("name:{}", g.to_lowercase()));
        let e = Entity::new(
            b.k.case_id,
            EntityKind::UserGroup,
            key,
            text(f, "gruppe").unwrap_or(g).to_string(),
            b.k.zeitpunkt,
        );
        b.entity(e, gesehen)
    });
    if let Some(p) = person {
        dazu(
            p,
            if gruppe.is_some() {
                ParticipantRole::Subject
            } else {
                ParticipantRole::User
            },
        );
    }
    if let Some(a) = ausfuehrender {
        dazu(a, ParticipantRole::Actor);
    }
    if let Some(g) = gruppe {
        dazu(g, ParticipantRole::Object);
    }
    if let Some(ip) = text(f, "quell_ip").and_then(canonical::ip) {
        let e = Entity::new(
            b.k.case_id,
            EntityKind::IpAddress,
            format!("ip:{ip}"),
            ip,
            b.k.zeitpunkt,
        );
        dazu(b.entity(e, gesehen), ParticipantRole::SourceIp);
    }
    if let Some(p) = text(f, "prozess") {
        dazu(datei(b, p, gesehen), ParticipantRole::Executable);
    }
    if let Some(d) = text(f, "dienst") {
        let e = Entity::new(
            b.k.case_id,
            EntityKind::Service,
            format!(
                "dienst:{}:{}",
                b.k.host.as_deref().unwrap_or("?").to_lowercase(),
                d.to_lowercase()
            ),
            d.to_string(),
            b.k.zeitpunkt,
        );
        dazu(b.entity(e, gesehen), ParticipantRole::Object);
    }

    let mut attribute = json!({"event_id": id, "event_record_id": record});
    for k in ["kanal", "anbieter", "anmeldetyp", "arbeitsstation"] {
        if let Some(v) = text(f, k) {
            attribute[k] = json!(v);
        }
    }
    if eigen.is_some() {
        attribute["art"] = json!(kind_name);
    }
    if id == 4625 {
        attribute["erfolgreich"] = json!(false);
    }
    if id == 4648 {
        attribute["explizite_anmeldedaten"] = json!(true);
    }
    if matches!(id, 21 | 25 | 1149) {
        attribute["rdp"] = json!(true);
    }
    let prov = herkunft(b, f, aid, oid, locator);
    b.event(
        Event {
            id: eid,
            case_id: b.k.case_id,
            kind,
            occurred_at: zeit,
            ended_at: None,
            attributes: attribute,
            derivation: ableitung,
            created_at: b.k.zeitpunkt,
        },
        teilnehmer,
        prov.clone(),
    );

    // Gruppenmitgliedschaft als Beziehung, gültig ab dem Ereignis.
    if let (Some(p), Some(g)) = (person, gruppe) {
        let mut r = Relationship::new(
            b.k.case_id,
            RelationshipKind::MemberOf,
            p,
            g,
            DerivationKind::Derived,
        );
        r.valid_from = gesehen;
        b.relationship(r, prov.clone());
    }
    // Ein Konto, das auf diesem Rechner auftritt, gehört zu ihm.
    if let (Some(p), Some(h)) = (person, host(b)) {
        if gruppe.is_none() {
            b.relationship(
                Relationship::new(
                    b.k.case_id,
                    RelationshipKind::AccountOn,
                    p,
                    h,
                    DerivationKind::Derived,
                ),
                prov,
            );
        }
    }
    if vollstaendig {
        Abbildung::Vollstaendig
    } else {
        Abbildung::FundstelleUnvollstaendig
    }
}
