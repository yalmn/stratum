//! Benutzeraktivität: UserAssist, MRU-Listen der NTUSER.DAT, LNK-Dateien,
//! Sprunglisten, ShellBags und ActivitiesCache.
//!
//! Jeder Eintrag ergibt eine Nutzungsbeziehung vom Benutzer zum Ziel. Ein
//! Ereignis entsteht nur, wenn eine Zeit belegbar zu genau diesem Eintrag
//! gehört:
//! - MRU-Listen: die letzte Änderung des Schlüssels gilt nur für den Eintrag an
//!   Position 0 (zuletzt verwendet). Das Ereignis ist abgeleitet.
//! - LNK-Dateien in `Recent`: Erstellzeit der Verknüpfung als erstes, Änderung
//!   als letztes Öffnen des Ziels (abgeleitet).
//! - UserAssist, TypedURLsTime und ActivitiesCache tragen eigene Zeiten.
//!
//! Die Zeiten des Ziels, die eine Verknüpfung mitführt, bleiben in der
//! Observation; sie beschreiben das Ziel zum Zeitpunkt der Verknüpfung.

use serde_json::{json, Value};
use stratum_analysis::RawFinding;
use stratum_model::{
    ArtifactKind, DerivationKind, Entity, EntityId, EntityKind, Event, EventId, EventKind,
    EventParticipant, ForensicTime, ParticipantRole, Relationship, RelationshipKind, SourceLocator,
    TimeSemantics,
};

use crate::hilfen::{
    artefakt, benutzer, herkunft, herkunft_zusatz, host, ntfs, pfad_entitaet, text, zahl, zeit,
    zeit_unix,
};
use crate::{Abbildung, Baukasten, GELESEN};

pub fn abbilden(f: &RawFinding, b: &mut Baukasten<'_>) -> Abbildung {
    match text(f, "art") {
        Some("userassist") => userassist(f, b),
        Some(
            art @ ("typed_url" | "typed_path" | "run_mru" | "explorer_suche" | "recent_doc"
            | "dialog_datei" | "dialog_programm"),
        ) => mru(f, b, art),
        Some(art @ ("lnk" | "jumplist")) => verknuepfung(f, b, art),
        Some("shellbag") => shellbag(f, b),
        Some("activities_cache") => aktivitaet(f, b),
        Some("activities_cache_db") => datenbank(f, b),
        _ => {
            b.hinweis(format!("Benutzeraktivität ohne bekannte Art: {}", f.name));
            Abbildung::FundstelleUnvollstaendig
        }
    }
}

/// Hive und Schlüsselpfad aus einer Quelle wie `HKCU ich\Software\...` oder
/// `HKCU ich UsrClass.dat\Local Settings\...`.
fn ntuser(f: &RawFinding) -> (String, String) {
    let nutzer = text(f, "benutzer").unwrap_or("?");
    let rest = f
        .source
        .strip_prefix("HKCU ")
        .and_then(|r| r.strip_prefix(nutzer))
        .unwrap_or(&f.source);
    if let Some(r) = rest.strip_prefix(" UsrClass.dat\\") {
        (format!("UsrClass.dat {nutzer}"), r.to_string())
    } else {
        (
            format!("NTUSER.DAT {nutzer}"),
            rest.trim_start_matches('\\').to_string(),
        )
    }
}

fn registry(f: &RawFinding, wert: Option<&str>) -> SourceLocator {
    let (hive, key_path) = ntuser(f);
    SourceLocator::Registry {
        hive,
        key_path,
        value_name: wert.map(str::to_string),
        cell_offset: zahl(f, "hive_offset"),
    }
}

fn vollstaendig(ok: bool) -> Abbildung {
    if ok {
        Abbildung::Vollstaendig
    } else {
        Abbildung::FundstelleUnvollstaendig
    }
}

fn nutzer(
    b: &mut Baukasten<'_>,
    f: &RawFinding,
    gesehen: Option<chrono::DateTime<chrono::Utc>>,
) -> Option<EntityId> {
    benutzer(b, text(f, "benutzer"), None, None, gesehen)
}

/// Programm ohne Pfad (Name oder AppUserModelID). Gleicher Schlüssel wie bei
/// Prefetch, damit derselbe Programmname zusammenfindet.
fn programm(
    b: &mut Baukasten<'_>,
    name: &str,
    gesehen: Option<chrono::DateTime<chrono::Utc>>,
) -> EntityId {
    let e = Entity::new(
        b.k.case_id,
        EntityKind::Application,
        format!("programm:{}", name.to_lowercase()),
        name.to_string(),
        b.k.zeitpunkt,
    );
    b.entity(e, gesehen)
}

/// Datei, von der nur der Name bekannt ist (RecentDocs, Öffnen-Dialog). Sie
/// wird nicht mit Pfad-Dateien gleichgesetzt.
fn dateiname(b: &mut Baukasten<'_>, name: &str) -> EntityId {
    let mut e = Entity::new(
        b.k.case_id,
        EntityKind::File,
        format!("dateiname:{}", name.to_lowercase()),
        name.to_string(),
        b.k.zeitpunkt,
    );
    e.attributes = json!({"nur_dateiname": true});
    b.entity(e, None)
}

/// URL mit kleingeschriebenem Schema und Host; Pfad und Abfrage bleiben.
fn url_schluessel(url: &str) -> String {
    let url = url.trim();
    match url.split_once("://") {
        Some((schema, rest)) => {
            let ende = rest.find(['/', '?', '#']).unwrap_or(rest.len());
            format!(
                "url:{}://{}{}",
                schema.to_ascii_lowercase(),
                rest[..ende].to_ascii_lowercase(),
                &rest[ende..]
            )
        }
        None => format!("url:{url}"),
    }
}

fn url(
    b: &mut Baukasten<'_>,
    url: &str,
    gesehen: Option<chrono::DateTime<chrono::Utc>>,
) -> EntityId {
    let e = Entity::new(
        b.k.case_id,
        EntityKind::Url,
        url_schluessel(url),
        url.to_string(),
        b.k.zeitpunkt,
    );
    b.entity(e, gesehen)
}

/// Beziehung Benutzer nutzt Ziel, mit der Quelle als Attribut.
fn nutzt(
    b: &mut Baukasten<'_>,
    uid: Option<EntityId>,
    ziel: EntityId,
    kind: RelationshipKind,
    quelle: &str,
    prov: stratum_model::ProvenanceRef,
) {
    let Some(uid) = uid else { return };
    let mut r = Relationship::new(b.k.case_id, kind, uid, ziel, GELESEN);
    r.attributes = json!({"quelle": quelle});
    b.relationship(r, prov);
}

#[allow(clippy::too_many_arguments)]
fn ereignis(
    b: &mut Baukasten<'_>,
    kind: EventKind,
    name: &str,
    schluessel: &str,
    zeit: ForensicTime,
    attribute: Value,
    ableitung: DerivationKind,
    teilnehmer: &[(EntityId, ParticipantRole)],
    prov: stratum_model::ProvenanceRef,
) {
    let eid = EventId::derive(b.k.case_id, name, schluessel);
    let mut t: Vec<EventParticipant> = teilnehmer
        .iter()
        .map(|&(entity_id, role)| EventParticipant {
            event_id: eid,
            entity_id,
            role,
        })
        .collect();
    if let Some(h) = host(b) {
        t.push(EventParticipant {
            event_id: eid,
            entity_id: h,
            role: ParticipantRole::Host,
        });
    }
    b.event(
        Event {
            id: eid,
            case_id: b.k.case_id,
            kind,
            occurred_at: Some(zeit),
            ended_at: None,
            attributes: attribute,
            derivation: ableitung,
            created_at: b.k.zeitpunkt,
        },
        t,
        prov,
    );
}

/// UserAssist: Programmstarts über die Explorer-Oberfläche mit Anzahl und
/// letzter Ausführung. `UEME_CTL*` sind Zähler ohne Programm.
fn userassist(f: &RawFinding, b: &mut Baukasten<'_>) -> Abbildung {
    let wert = text(f, "wertname_roh").unwrap_or(&f.name);
    let schluessel = format!("registry:{}:{wert}{}", f.source, herkunft_zusatz(f));
    let locator = registry(f, Some(wert));
    let (aid, oid) = artefakt(
        b,
        f,
        ArtifactKind::RegistryValue,
        locator.clone(),
        &schluessel,
        "userassist_entry",
    );
    let ok = zahl(f, "hive_offset").is_some();
    if f.name.starts_with("UEME_CTL") {
        return vollstaendig(ok);
    }
    let zeit = zeit(f, "letzte_ausfuehrung", TimeSemantics::EventTime);
    let gesehen = zeit.as_ref().map(|z| z.utc);
    let ziel = match text(f, "pfad_aufgeloest") {
        Some(p) => pfad_entitaet(b, EntityKind::File, p, gesehen),
        None if f.name.contains(":\\") => pfad_entitaet(b, EntityKind::File, &f.name, gesehen),
        None => programm(b, &f.name, gesehen),
    };
    let uid = nutzer(b, f, gesehen);
    let prov = herkunft(b, f, aid, oid, locator);
    nutzt(
        b,
        uid,
        ziel,
        RelationshipKind::Uses,
        "userassist",
        prov.clone(),
    );
    if let Some(zeit) = zeit {
        let mut attribute = json!({"quelle": "userassist", "zeitpunkt": "letzte_ausfuehrung"});
        for k in ["ausfuehrungen", "fokus_anzahl", "fokus_zeit_ms"] {
            if let Some(v) = text(f, k) {
                attribute[k] = json!(v);
            }
        }
        let mut t = vec![(ziel, ParticipantRole::Executable)];
        if let Some(u) = uid {
            t.push((u, ParticipantRole::User));
        }
        ereignis(
            b,
            EventKind::ProcessStart,
            "process_start",
            &schluessel,
            zeit,
            attribute,
            GELESEN,
            &t,
            prov,
        );
    }
    vollstaendig(ok)
}

/// MRU-Listen der NTUSER.DAT.
fn mru(f: &RawFinding, b: &mut Baukasten<'_>, art: &str) -> Abbildung {
    let wert = text(f, "wert");
    let schluessel = format!(
        "registry:{}:{}{}",
        f.source,
        wert.unwrap_or(&f.name),
        herkunft_zusatz(f)
    );
    let locator = registry(f, wert);
    let (aid, oid) = artefakt(
        b,
        f,
        ArtifactKind::RegistryValue,
        locator.clone(),
        &schluessel,
        art,
    );
    let ok = zahl(f, "hive_offset").is_some();

    // Zeit: eigene Eingabezeit (TypedURLsTime) oder die Schlüsselzeit, wenn
    // der Eintrag an Position 0 steht.
    let eigene = zeit(f, "eingegeben", TimeSemantics::EventTime);
    let erster = text(f, "mru_position") == Some("0");
    let schluesselzeit = if erster {
        zeit(f, "key_letzte_aenderung", TimeSemantics::EventTime)
    } else {
        None
    };
    let gesehen = eigene.as_ref().or(schluesselzeit.as_ref()).map(|z| z.utc);
    let uid = nutzer(b, f, gesehen);

    let (ziel, beziehung, rolle) = match art {
        "typed_url" => (
            Some(url(b, &f.name, gesehen)),
            RelationshipKind::Uses,
            ParticipantRole::Object,
        ),
        "typed_path" => (
            Some(pfad_entitaet(b, EntityKind::Directory, &f.name, gesehen)),
            RelationshipKind::Uses,
            ParticipantRole::Object,
        ),
        "recent_doc" | "dialog_datei" => (
            Some(dateiname(b, &f.name)),
            RelationshipKind::UsesFile,
            ParticipantRole::File,
        ),
        "dialog_programm" => (
            Some(programm(b, &f.name, gesehen)),
            RelationshipKind::Uses,
            ParticipantRole::Executable,
        ),
        // RunMRU und Explorer-Suche: Eingaben ohne eigene Entität.
        _ => (None, RelationshipKind::Uses, ParticipantRole::Object),
    };
    let prov = herkunft(b, f, aid, oid, locator);
    if let Some(z) = ziel {
        nutzt(b, uid, z, beziehung, art, prov.clone());
    }

    let (kind, name, attribute) = match art {
        "typed_url" => (EventKind::Custom, "url_typed", json!({"art": "url_typed"})),
        "typed_path" => (
            EventKind::Custom,
            "path_typed",
            json!({"art": "path_typed"}),
        ),
        "run_mru" => (
            EventKind::CommandEntered,
            "command_entered",
            json!({"befehl": f.name}),
        ),
        "explorer_suche" => (
            EventKind::Custom,
            "explorer_search",
            json!({"art": "explorer_search", "suchbegriff": f.name}),
        ),
        "dialog_programm" => (
            EventKind::Custom,
            "file_dialog_used",
            json!({"art": "file_dialog_used"}),
        ),
        _ => (EventKind::FileAccessed, "file_accessed", json!({})),
    };
    let (zeit, ableitung, zeitpunkt) = match (eigene, schluesselzeit) {
        (Some(z), _) => (z, GELESEN, "eingegeben"),
        (None, Some(z)) => (
            z,
            DerivationKind::Derived,
            "schluessel_letzte_aenderung_mru_position_0",
        ),
        (None, None) => return vollstaendig(ok),
    };
    let mut attribute = attribute;
    attribute["quelle"] = json!(art);
    attribute["zeitpunkt"] = json!(zeitpunkt);
    let mut t = Vec::new();
    if let Some(z) = ziel {
        t.push((z, rolle));
    }
    if let Some(u) = uid {
        t.push((u, ParticipantRole::User));
    }
    // Derselbe Eintrag steht oft in mehreren Listen (RecentDocs und
    // RecentDocs\Folder) mit derselben Schlüsselzeit. Ziel, Benutzer und Zeit
    // bestimmen das Ereignis; jede weitere Liste stützt es nur.
    let ereignis_schluessel = match ziel {
        Some(z) => format!(
            "{}:{}:{}",
            z.0,
            uid.map(|u| u.0.to_string()).unwrap_or_default(),
            zeit.utc.timestamp_nanos_opt().unwrap_or_default()
        ),
        None => schluessel.clone(),
    };
    ereignis(
        b,
        kind,
        name,
        &ereignis_schluessel,
        zeit,
        attribute,
        ableitung,
        &t,
        prov,
    );
    vollstaendig(ok)
}

/// LNK-Dateien in `Recent` und Einträge von Sprunglisten: Ziel mit Pfad und
/// Volume-Seriennummer.
fn verknuepfung(f: &RawFinding, b: &mut Baukasten<'_>, art: &str) -> Abbildung {
    let teil = text(f, "stream")
        .or(text(f, "datei_offset"))
        .map(|s| format!(":{s}"))
        .unwrap_or_default();
    let schluessel = format!(
        "{art}:{}:{}{teil}{}",
        text(f, "volume_offset").unwrap_or("?"),
        text(f, "mft_record")
            .map(str::to_string)
            .unwrap_or_else(|| f.source.to_lowercase()),
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
    let kind = if art == "lnk" {
        ArtifactKind::LnkRecord
    } else {
        ArtifactKind::JumpListEntry
    };
    let (aid, oid) = artefakt(b, f, kind, locator.clone(), &schluessel, art);
    let Some(zielpfad) = text(f, "zielpfad") else {
        return vollstaendig(ok);
    };
    let erstmals = zahl(f, "lnk_erstellt_filetime")
        .and_then(|ft| ForensicTime::from_filetime(ft, TimeSemantics::EventTime));
    let zuletzt = zahl(f, "lnk_geaendert_filetime")
        .and_then(|ft| ForensicTime::from_filetime(ft, TimeSemantics::EventTime));
    let gesehen = zuletzt.as_ref().or(erstmals.as_ref()).map(|z| z.utc);
    let did = pfad_entitaet(b, EntityKind::File, zielpfad, gesehen);
    let uid = nutzer(b, f, gesehen);
    let prov = herkunft(b, f, aid, oid, locator);
    nutzt(b, uid, did, RelationshipKind::UsesFile, art, prov.clone());

    if let Some(sn) = text(f, "laufwerk_seriennummer") {
        let e = Entity::new(
            b.k.case_id,
            EntityKind::Volume,
            format!("volume_seriennummer:{}", sn.to_ascii_lowercase()),
            format!("Volume-Seriennummer {sn}"),
            b.k.zeitpunkt,
        );
        let vid = b.entity(e, None);
        b.relationship(
            Relationship::new(b.k.case_id, RelationshipKind::LocatedOn, did, vid, GELESEN),
            prov.clone(),
        );
    }

    let mut t = vec![(did, ParticipantRole::File)];
    if let Some(u) = uid {
        t.push((u, ParticipantRole::User));
    }
    // Erstellen und letzte Änderung der Verknüpfung können zusammenfallen;
    // dann ist es ein Öffnen, nicht zwei.
    let gleich = matches!((&erstmals, &zuletzt), (Some(a), Some(z)) if a.utc == z.utc);
    for (z, zeitpunkt) in [
        (erstmals, "erstmals_geoeffnet"),
        (zuletzt, "zuletzt_geoeffnet"),
    ] {
        let Some(z) = z else { continue };
        if gleich && zeitpunkt == "zuletzt_geoeffnet" {
            continue;
        }
        ereignis(
            b,
            EventKind::FileAccessed,
            "file_accessed",
            &format!("{schluessel}:{zeitpunkt}"),
            z,
            json!({"quelle": art, "zeitpunkt": zeitpunkt}),
            DerivationKind::Derived,
            &t,
            prov.clone(),
        );
    }
    vollstaendig(ok)
}

/// ShellBags: vom Benutzer im Explorer geöffnete Ordner. Der Pfad ist ein
/// Shell-Namensraum (`This PC\F:`), kein Dateisystempfad.
fn shellbag(f: &RawFinding, b: &mut Baukasten<'_>) -> Abbildung {
    let wert = text(f, "wert");
    let schluessel = format!(
        "registry:{}:{}{}",
        f.source,
        wert.unwrap_or(&f.name),
        herkunft_zusatz(f)
    );
    let locator = registry(f, wert);
    let (aid, oid) = artefakt(
        b,
        f,
        ArtifactKind::ShellItem,
        locator.clone(),
        &schluessel,
        "shellbag",
    );
    let ok = zahl(f, "hive_offset").is_some();
    let zeit = zeit_unix(f, "zuletzt_verwendet_unix");
    let gesehen = zeit.as_ref().map(|z| z.utc);
    let mut e = Entity::new(
        b.k.case_id,
        EntityKind::Directory,
        // Nicht gedeutete Elemente heißen alle gleich; sie bleiben über ihre
        // Stelle im BagMRU-Baum getrennt.
        match text(f, "bagmru").filter(|_| f.name.starts_with("[unbekannt")) {
            Some(knoten) => format!("shell_bagmru:{}:{knoten}", ntuser(f).0.to_lowercase()),
            None => format!("shell:{}", f.name.to_lowercase()),
        },
        f.name.clone(),
        b.k.zeitpunkt,
    );
    e.attributes = json!({"shell_namensraum": true});
    let did = b.entity(e, gesehen);
    let uid = nutzer(b, f, gesehen);
    let prov = herkunft(b, f, aid, oid, locator);
    nutzt(
        b,
        uid,
        did,
        RelationshipKind::Uses,
        "shellbag",
        prov.clone(),
    );
    if let Some(z) = zeit {
        let mut t = vec![(did, ParticipantRole::Object)];
        if let Some(u) = uid {
            t.push((u, ParticipantRole::User));
        }
        ereignis(
            b,
            EventKind::FileAccessed,
            "folder_accessed",
            &schluessel,
            z,
            json!({"quelle": "shellbag", "zeitpunkt": "schluessel_letzte_aenderung_mru_position_0"}),
            DerivationKind::Derived,
            &t,
            prov,
        );
    }
    vollstaendig(ok)
}

fn db_locator(f: &RawFinding) -> (SourceLocator, bool) {
    match ntfs(f) {
        Some(l) => (l, true),
        None => (
            SourceLocator::Database {
                path: f.source.clone(),
                table: text(f, "tabelle").unwrap_or("?").to_string(),
                row_id: text(f, "rowid").map(str::to_string),
            },
            false,
        ),
    }
}

/// ActivitiesCache-Zeile: Aktivität einer Anwendung mit Startzeit.
fn aktivitaet(f: &RawFinding, b: &mut Baukasten<'_>) -> Abbildung {
    let schluessel = format!(
        "activities:{}:{}:{}{}",
        f.source.to_lowercase(),
        text(f, "tabelle").unwrap_or("?"),
        text(f, "rowid").unwrap_or("?"),
        herkunft_zusatz(f)
    );
    let (locator, ok) = db_locator(f);
    let (aid, oid) = artefakt(
        b,
        f,
        ArtifactKind::SqliteRow,
        locator.clone(),
        &schluessel,
        "activity",
    );
    let zeit = zeit_unix(f, "aktivitaet_start_unix");
    let gesehen = zeit.as_ref().map(|z| z.utc);
    let app = text(f, "anwendung").map(|a| programm(b, a, gesehen));
    let uid = nutzer(b, f, gesehen);
    let prov = herkunft(b, f, aid, oid, locator);
    if let Some(a) = app {
        nutzt(
            b,
            uid,
            a,
            RelationshipKind::Uses,
            "activities_cache",
            prov.clone(),
        );
    }
    if let Some(z) = zeit {
        let mut attribute = json!({"art": "user_activity", "quelle": "activities_cache"});
        for k in ["aktivitaet_typ", "aktivitaet_status", "tabelle"] {
            if let Some(v) = text(f, k) {
                attribute[k] = json!(v);
            }
        }
        let mut t = Vec::new();
        if let Some(a) = app {
            t.push((a, ParticipantRole::Executable));
        }
        if let Some(u) = uid {
            t.push((u, ParticipantRole::User));
        }
        ereignis(
            b,
            EventKind::Custom,
            "user_activity",
            &schluessel,
            z,
            attribute,
            GELESEN,
            &t,
            prov,
        );
    }
    vollstaendig(ok)
}

/// Geprüfte ActivitiesCache-Datenbank: die Datei selbst (Datenstrom) als
/// Artefakt mit Observation, ohne Entitäten.
fn datenbank(f: &RawFinding, b: &mut Baukasten<'_>) -> Abbildung {
    let schluessel = format!(
        "activities_db:{}{}",
        f.source.to_lowercase(),
        herkunft_zusatz(f)
    );
    let (locator, ok) = db_locator(f);
    artefakt(
        b,
        f,
        ArtifactKind::NtfsStream,
        locator,
        &schluessel,
        "activities_cache_db",
    );
    vollstaendig(ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_schema_und_host_klein() {
        assert_eq!(
            url_schluessel("HTTP://Beispiel.TLD/Pfad?A=B"),
            "url:http://beispiel.tld/Pfad?A=B"
        );
        assert_eq!(url_schluessel("about:blank"), "url:about:blank");
    }
}
