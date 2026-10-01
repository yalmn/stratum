//! Prefetch: je Datei ein Artefakt und eine Observation; die letzte
//! Ausführung als Ereignis „Prozessstart“ des Programms.

use serde_json::json;
use stratum_analysis::RawFinding;
use stratum_model::{
    ArtifactKind, Entity, EntityKind, Event, EventId, EventKind, EventParticipant, ParticipantRole,
    SourceLocator,
};

use crate::hilfen::{artefakt, herkunft, herkunft_zusatz, host, ntfs, text, zeit_unix};
use crate::{Abbildung, Baukasten, GELESEN};

pub fn abbilden(f: &RawFinding, b: &mut Baukasten<'_>) -> Abbildung {
    let datei = text(f, "prefetch_datei").unwrap_or(&f.source);
    let schluessel = format!(
        "prefetch:{}:{}{}",
        text(f, "volume_offset").unwrap_or("?"),
        text(f, "mft_record")
            .map(str::to_string)
            .unwrap_or_else(|| datei.to_lowercase()),
        herkunft_zusatz(f)
    );
    let (locator, vollstaendig) = match ntfs(f) {
        Some(l) => (l, true),
        None => (
            SourceLocator::FileLine {
                path: f.source.clone(),
                line: 0,
                byte_offset: None,
            },
            false,
        ),
    };
    let (aid, oid) = artefakt(
        b,
        f,
        ArtifactKind::PrefetchRecord,
        locator.clone(),
        &schluessel,
        "program_execution",
    );

    // Prefetch nennt nur den Programmnamen, keinen Pfad: Identität über den Namen.
    let name = text(f, "interner_name").unwrap_or(&f.name).to_string();
    let programm = Entity::new(
        b.k.case_id,
        EntityKind::Application,
        format!("programm:{}", name.to_lowercase()),
        name,
        b.k.zeitpunkt,
    );
    if let Some(zeit) = zeit_unix(f, "letzte_ausfuehrung_unix") {
        let gesehen = Some(zeit.utc);
        let pid = b.entity(programm, gesehen);
        let eid = EventId::derive(b.k.case_id, "process_start", &schluessel);
        let mut teilnehmer = vec![EventParticipant {
            event_id: eid,
            entity_id: pid,
            role: ParticipantRole::Executable,
        }];
        if let Some(h) = host(b) {
            teilnehmer.push(EventParticipant {
                event_id: eid,
                entity_id: h,
                role: ParticipantRole::Host,
            });
        }
        let mut attribute = json!({"quelle": "prefetch", "zeitpunkt": "letzte_ausfuehrung", "prefetch_datei": datei});
        for k in ["ausfuehrungszaehler", "erfasste_laufzeiten"] {
            if let Some(v) = text(f, k) {
                attribute[k] = json!(v);
            }
        }
        let prov = herkunft(b, f, aid, oid, locator);
        b.event(
            Event {
                id: eid,
                case_id: b.k.case_id,
                kind: EventKind::ProcessStart,
                occurred_at: Some(zeit),
                ended_at: None,
                attributes: attribute,
                derivation: GELESEN,
                created_at: b.k.zeitpunkt,
            },
            teilnehmer,
            prov,
        );
    } else {
        b.entity(programm, None);
    }
    if vollstaendig {
        Abbildung::Vollstaendig
    } else {
        Abbildung::FundstelleUnvollstaendig
    }
}
