//! Persistenz: Dienste, geplante Aufgaben, Run-Schlüssel, Winlogon,
//! AppInit_DLLs, IFEO-Debugger und Autostart-Ordner.
//!
//! Jeder Autostart-Eintrag wird eine Entität (Dienst, Aufgabe oder
//! Registry-Wert) mit Befehl und Bewertung der Engine als Attribute. Ist der
//! Befehl ein absoluter Pfad mit Laufwerksbuchstabe, entsteht die Beziehung
//! „führt aus“ zur Datei. Pfade mit Umgebungsvariablen (`%windir%`,
//! `\SystemRoot`) werden nicht aufgelöst, weil die Werte dafür aus dem
//! untersuchten System stammen müssten; der Befehl bleibt als Attribut.
//!
//! Zeiten: nur die Erstellzeit der Aufgabendatei ergibt ein Ereignis
//! (Aufgabe angelegt, abgeleitet). Die letzte Änderung eines Registry-
//! Schlüssels gilt für alle seine Werte und bleibt deshalb in der
//! Observation.

use serde_json::json;
use stratum_analysis::RawFinding;
use stratum_model::{
    ArtifactKind, DerivationKind, Entity, EntityId, EntityKind, Event, EventId, EventKind,
    EventParticipant, ForensicTime, ParticipantRole, ProvenanceRef, Relationship, RelationshipKind,
    SourceLocator, TimeSemantics,
};

use crate::hilfen::{
    artefakt, benutzer, datei, dienst, herkunft, herkunft_zusatz, host, ntfs, text, zahl,
};
use crate::{Abbildung, Baukasten, GELESEN};

/// Bewertungsfelder der Engine, die an die Entität übernommen werden.
const BEWERTUNG: &[&str] = &[
    "befehl",
    "weitere_befehle",
    "aktion",
    "com_handler",
    "start_typ",
    "auffaellig",
    "auffaellig_grund",
    "pfad_status",
    "systemwerkzeug",
    "unquotierter_pfad",
    "autor",
    "bewertung",
    "ort",
];

pub fn abbilden(f: &RawFinding, b: &mut Baukasten<'_>) -> Abbildung {
    match text(f, "ort") {
        Some("Dienst") => dienst_eintrag(f, b),
        Some("Aufgabe") => aufgabe(f, b),
        Some("Autostart-Ordner") => autostart_ordner(f, b),
        Some(_) => registry_eintrag(f, b),
        None => {
            b.hinweis(format!("Persistenz ohne Ort: {}", f.name));
            Abbildung::FundstelleUnvollstaendig
        }
    }
}

fn vollstaendig(ok: bool) -> Abbildung {
    if ok {
        Abbildung::Vollstaendig
    } else {
        Abbildung::FundstelleUnvollstaendig
    }
}

fn attribute(f: &RawFinding) -> serde_json::Value {
    let mut a = json!({});
    for k in BEWERTUNG {
        if let Some(v) = text(f, k) {
            a[*k] = json!(v);
        }
    }
    a
}

/// Hive und Schlüsselpfad aus der Quelle (`HKLM SOFTWARE\…`, `SYSTEM\…`,
/// `HKCU ich\…`).
fn registry_teile(f: &RawFinding) -> (String, String) {
    let (hive, pfad) = if let Some(r) = f.source.strip_prefix("HKLM SOFTWARE\\") {
        ("SOFTWARE".to_string(), r)
    } else if let Some(r) = f.source.strip_prefix("SYSTEM\\") {
        ("SYSTEM".to_string(), r)
    } else if let Some((nutzer, r)) = f
        .source
        .strip_prefix("HKCU ")
        .and_then(|r| r.split_once('\\'))
    {
        (format!("NTUSER.DAT {nutzer}"), r)
    } else {
        ("?".to_string(), f.source.as_str())
    };
    (hive, pfad.to_string())
}

fn registry(f: &RawFinding) -> SourceLocator {
    let (hive, key_path) = registry_teile(f);
    SourceLocator::Registry {
        hive,
        key_path,
        value_name: text(f, "wert").map(str::to_string),
        cell_offset: zahl(f, "hive_offset"),
    }
}

/// Programmpfad aus einem Befehl, nur wenn er absolut mit
/// Laufwerksbuchstabe angegeben ist. Anführungszeichen umschließen den Pfad;
/// ohne sie endet er nach der ersten bekannten Programmendung.
pub(crate) fn programmpfad(befehl: &str) -> Option<String> {
    let b = befehl.trim();
    let pfad = if let Some(r) = b.strip_prefix('"') {
        r.split('"').next()?.to_string()
    } else {
        let klein = b.to_ascii_lowercase();
        let ende = [
            ".exe", ".dll", ".sys", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js",
        ]
        .iter()
        .filter_map(|e| klein.find(e).map(|i| i + e.len()))
        .min()
        .unwrap_or(b.len());
        b[..ende].to_string()
    };
    let p = pfad.as_bytes();
    (p.len() > 3 && p[0].is_ascii_alphabetic() && p[1] == b':' && p[2] == b'\\').then_some(pfad)
}

/// „Führt aus“ vom Autostart-Eintrag zur Datei, falls der Befehl einen
/// absoluten Pfad nennt.
fn fuehrt_aus(b: &mut Baukasten<'_>, f: &RawFinding, quelle: EntityId, prov: &ProvenanceRef) {
    let Some(p) = text(f, "befehl").and_then(programmpfad) else {
        return;
    };
    let did = datei(b, &p, None);
    b.relationship(
        Relationship::new(
            b.k.case_id,
            RelationshipKind::Executes,
            quelle,
            did,
            DerivationKind::Derived,
        ),
        prov.clone(),
    );
}

/// Auf dem Rechner installiert.
fn auf_host(b: &mut Baukasten<'_>, id: EntityId, prov: &ProvenanceRef) {
    if let Some(h) = host(b) {
        b.relationship(
            Relationship::new(b.k.case_id, RelationshipKind::InstalledOn, id, h, GELESEN),
            prov.clone(),
        );
    }
}

/// Dienst: dieselbe Entität wie bei Ereignis 7045 (Dienst installiert).
fn dienst_eintrag(f: &RawFinding, b: &mut Baukasten<'_>) -> Abbildung {
    let schluessel = format!("registry:{}{}", f.source, herkunft_zusatz(f));
    let locator = registry(f);
    let (aid, oid) = artefakt(
        b,
        f,
        ArtifactKind::RegistryValue,
        locator.clone(),
        &schluessel,
        "service_entry",
    );
    let sid = dienst(b, &f.name, None, None);
    b.entity_attribute(sid, attribute(f));
    let prov = herkunft(b, f, aid, oid, locator);
    auf_host(b, sid, &prov);
    fuehrt_aus(b, f, sid, &prov);
    vollstaendig(zahl(f, "hive_offset").is_some())
}

/// Konto aus dem Principal einer Aufgabe: SID oder `DOMÄNE\Name`.
fn principal(b: &mut Baukasten<'_>, wert: &str) -> Option<EntityId> {
    if wert.starts_with("S-1-") {
        return benutzer(b, None, Some(wert), None, None);
    }
    match wert.split_once('\\') {
        Some((d, n)) => benutzer(b, Some(n), None, Some(d), None),
        None => benutzer(b, Some(wert), None, None, None),
    }
}

/// Geplante Aufgabe: Datei unter `System32\Tasks`. Die Erstellzeit der Datei
/// ist der Zeitpunkt der Registrierung.
fn aufgabe(f: &RawFinding, b: &mut Baukasten<'_>) -> Abbildung {
    let schluessel = format!(
        "aufgabe:{}:{}{}",
        text(f, "volume_offset").unwrap_or("?"),
        text(f, "mft_record")
            .map(str::to_string)
            .unwrap_or_else(|| f.source.to_lowercase()),
        herkunft_zusatz(f)
    );
    let (locator, ok) = match ntfs(f) {
        Some(l) => (l, zahl(f, "mft_record_offset").is_some()),
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
        ArtifactKind::NtfsStream,
        locator.clone(),
        &schluessel,
        "scheduled_task",
    );
    let erstellt = zahl(f, "datei_erstellt_filetime")
        .and_then(|ft| ForensicTime::from_filetime(ft, TimeSemantics::EventTime));
    let mut e = Entity::new(
        b.k.case_id,
        EntityKind::ScheduledTask,
        format!(
            "aufgabe:{}:{}",
            b.k.host.as_deref().unwrap_or("?").to_lowercase(),
            f.name.to_lowercase()
        ),
        f.name.clone(),
        b.k.zeitpunkt,
    );
    let mut attr = attribute(f);
    if let Some(d) = text(f, "registrierung_xml") {
        attr["registrierung_xml"] = json!(d);
    }
    e.attributes = attr;
    let tid = b.entity(e, erstellt.as_ref().map(|z| z.utc));
    let prov = herkunft(b, f, aid, oid, locator);
    auf_host(b, tid, &prov);
    fuehrt_aus(b, f, tid, &prov);
    let konto = text(f, "benutzer").and_then(|u| principal(b, u));
    if let Some(u) = konto {
        let mut r = Relationship::new(b.k.case_id, RelationshipKind::BelongsTo, tid, u, GELESEN);
        r.attributes = json!({"grundlage": "Principal der Aufgabe (läuft als)"});
        b.relationship(r, prov.clone());
    }
    if let Some(zeit) = erstellt {
        let eid = EventId::derive(b.k.case_id, "scheduled_task_created", &schluessel);
        let mut t = vec![EventParticipant {
            event_id: eid,
            entity_id: tid,
            role: ParticipantRole::Object,
        }];
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
                kind: EventKind::ScheduledTaskCreated,
                occurred_at: Some(zeit),
                ended_at: None,
                attributes: json!({"quelle": "aufgabendatei", "zeitpunkt": "datei_erstellt"}),
                derivation: DerivationKind::Derived,
                created_at: b.k.zeitpunkt,
            },
            t,
            prov,
        );
    }
    vollstaendig(ok)
}

/// Run-Schlüssel, Winlogon, AppInit_DLLs, IFEO-Debugger: der Wert selbst ist
/// der Autostart-Eintrag.
fn registry_eintrag(f: &RawFinding, b: &mut Baukasten<'_>) -> Abbildung {
    let locator = registry(f);
    let wert = text(f, "wert").unwrap_or(&f.name);
    let schluessel = format!("registry:{}:{wert}{}", f.source, herkunft_zusatz(f));
    let (aid, oid) = artefakt(
        b,
        f,
        ArtifactKind::RegistryValue,
        locator.clone(),
        &schluessel,
        "autostart_entry",
    );
    let (hive, key_path) = registry_teile(f);
    let mut e = Entity::new(
        b.k.case_id,
        EntityKind::RegistryValue,
        format!(
            "registry:{}:{}:{}\\{}",
            b.k.host.as_deref().unwrap_or("?").to_lowercase(),
            hive.to_lowercase(),
            key_path.to_lowercase(),
            wert.to_lowercase()
        ),
        format!("{key_path}\\{wert}"),
        b.k.zeitpunkt,
    );
    e.attributes = attribute(f);
    let rid = b.entity(e, None);
    let prov = herkunft(b, f, aid, oid, locator.clone());
    fuehrt_aus(b, f, rid, &prov);
    // HKCU: startet bei Anmeldung dieses Benutzers; HKLM: auf dem Rechner.
    match text(f, "benutzer") {
        Some(n) => {
            if let Some(u) = benutzer(b, Some(n), None, None, None) {
                b.relationship(
                    Relationship::new(b.k.case_id, RelationshipKind::BelongsTo, rid, u, GELESEN),
                    prov,
                );
            }
        }
        None => auf_host(b, rid, &prov),
    }
    vollstaendig(zahl(f, "hive_offset").is_some())
}

/// Datei in einem Autostart-Ordner; der Pfad ist relativ zum Volume.
fn autostart_ordner(f: &RawFinding, b: &mut Baukasten<'_>) -> Abbildung {
    let schluessel = format!(
        "autostart:{}:{}{}",
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
                byte_offset: None,
            },
            false,
        ),
    };
    let (aid, oid) = artefakt(
        b,
        f,
        ArtifactKind::NtfsMftRecord,
        locator.clone(),
        &schluessel,
        "autostart_folder_entry",
    );
    let did = datei(b, &f.source, None);
    let prov = herkunft(b, f, aid, oid, locator);
    auf_host(b, did, &prov);
    vollstaendig(ok)
}

#[cfg(test)]
mod tests {
    use super::programmpfad;

    #[test]
    fn programmpfad_nur_absolut() {
        assert_eq!(
            programmpfad("\"C:\\Program Files\\X\\x.exe\" /background").as_deref(),
            Some("C:\\Program Files\\X\\x.exe")
        );
        assert_eq!(
            programmpfad(
                "C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe /c"
            )
            .as_deref(),
            Some("C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe")
        );
        assert_eq!(
            programmpfad("C:\\WINDOWS\\system32\\userinit.exe,").as_deref(),
            Some("C:\\WINDOWS\\system32\\userinit.exe")
        );
        assert_eq!(
            programmpfad("%windir%\\system32\\SecurityHealthSystray.exe"),
            None
        );
        assert_eq!(
            programmpfad("\\SystemRoot\\System32\\drivers\\1394ohci.sys"),
            None
        );
        assert_eq!(programmpfad("explorer.exe"), None);
    }
}
