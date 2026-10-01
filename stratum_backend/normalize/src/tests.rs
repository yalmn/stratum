//! Abbildung synthetischer Rohfunde, wie sie die Engine liefert.

use chrono::DateTime;
use stratum_analysis::RawFinding;
use stratum_model::*;
use uuid::Uuid;

use crate::{normalisieren, Kontext, Modell};

fn kontext() -> Kontext {
    Kontext {
        case_id: CaseId(Uuid::from_u128(1)),
        evidence_id: EvidenceId(Uuid::from_u128(2)),
        evidence_sha256: "e633f0be".into(),
        host: Some("DESKTOP-G2LNLED".into()),
        stratum_version: "test".into(),
        zeitpunkt: DateTime::from_timestamp(0, 0).unwrap(),
    }
}

fn fund(domain: &str, name: &str, source: &str, attr: &[(&str, &str)]) -> RawFinding {
    let mut f = RawFinding::new(domain, name, source);
    for (k, v) in attr {
        f = f.with(*k, *v);
    }
    f
}

fn funde() -> Vec<RawFinding> {
    let ntfs = [
        ("volume_offset", "122683392"),
        ("mft_record", "39938"),
        ("mft_record_offset", "3384805376"),
    ];
    let mut anmeldung = fund(
        "eventlog",
        "Anmeldung erfolgreich",
        "Windows\\System32\\winevt\\Logs\\Security.evtx",
        &[
            ("event_id", "4624"),
            ("event_record_id", "42812"),
            ("filetime", "134209790846680107"),
            ("datei_offset", "69632"),
            ("kanal", "Security"),
            ("anbieter", "Microsoft-Windows-Security-Auditing"),
            ("benutzer", "ich"),
            ("benutzer_sid", "S-1-5-21-1-2-3-1001"),
            ("benutzer_domaene", "DESKTOP-G2LNLED"),
            ("ausfuehrender", "SYSTEM"),
            ("ausfuehrender_sid", "S-1-5-18"),
            ("anmeldetyp", "2"),
            ("quell_ip", "127.0.0.1"),
        ],
    );
    let mut gruppe = fund(
        "eventlog",
        "Zu privilegierter Gruppe hinzugefügt",
        "Windows\\System32\\winevt\\Logs\\Security.evtx",
        &[
            ("event_id", "4732"),
            ("event_record_id", "42813"),
            ("filetime", "134209790846680108"),
            ("datei_offset", "70000"),
            ("gruppe", "Administratoren"),
            ("gruppe_sid", "S-1-5-32-544"),
            ("benutzer_sid", "S-1-5-21-1-2-3-1001"),
            ("ausfuehrender", "ich"),
            ("ausfuehrender_sid", "S-1-5-21-1-2-3-1001"),
        ],
    );
    for (k, v) in ntfs {
        anmeldung = anmeldung.with(k, v);
        gruppe = gruppe.with(k, v);
    }
    vec![
        anmeldung,
        gruppe,
        fund("prefetch", "CMD.EXE", "Windows\\Prefetch\\CMD.EXE-0BD30981.pf", &[
            ("prefetch_datei", "CMD.EXE-0BD30981.pf"), ("interner_name", "CMD.EXE"),
            ("letzte_ausfuehrung_unix", "1776505000"), ("ausfuehrungszaehler", "4"),
            ("mft_record", "1234"), ("volume_offset", "122683392"),
        ]),
        fund("usb", "General UDisk USB Device", "SYSTEM\\ControlSet001\\Enum\\USBSTOR\\Disk&Ven_General&Prod_UDisk&Rev_5.00\\6&1526ad36&0&_&0", &[
            ("seriennummer", "6&1526ad36&0&_&0"), ("hive_offset", "11294128"),
            ("letzte_verbindung_filetime", "134209802612756023"), ("letzte_verbindung_hive_offset", "10053500"),
            ("letzte_verbindung_quelle", "SYSTEM\\...\\0066\\(Standard)"),
        ]),
        fund("usb", "\\??\\Volume{fff43352-3b0a-11f1-b1a1-806e6f6e6963}", "SYSTEM\\MountedDevices", &[
            ("art", "mounted_device"), ("hive_offset", "4096"),
            ("geraet", "_??_USBSTOR#Disk&Ven_General&Prod_UDisk&Rev_5.00#6&1526ad36&0&_&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}"),
        ]),
        // Ohne SID: wird über den Namen „ich“ dem Konto mit SID zugeordnet.
        fund("usb", "{fff43352-3b0a-11f1-b1a1-806e6f6e6963}", "HKCU ich\\MountPoints2", &[
            ("art", "mount_point"), ("benutzer", "ich"), ("letzter_zugriff_unix", "1776505454"),
        ]),
        fund("tor", "torrc", "Users\\ich\\torrc", &[]),
    ]
}

fn entitaet<'m>(m: &'m Modell, kind: EntityKind, anzeige: &str) -> &'m Entity {
    m.entities
        .iter()
        .find(|e| e.kind == kind && e.display_name == anzeige)
        .unwrap_or_else(|| panic!("{kind:?} {anzeige} fehlt"))
}

#[test]
fn abbildung_und_statistik() {
    let m = normalisieren(&funde(), &kontext());
    assert_eq!(m.statistik.abgebildet.get("eventlog"), Some(&2));
    assert_eq!(m.statistik.abgebildet.get("usb"), Some(&3));
    assert_eq!(m.statistik.ohne_mapper.get("tor"), Some(&1));
    // MountPoints2 ohne Zellposition (ältere Reports), MountedDevices mit.
    assert_eq!(m.statistik.fundstelle_unvollstaendig.get("usb"), Some(&1));
    assert_eq!(m.statistik.fundstelle_unvollstaendig.get("eventlog"), None);
    assert_eq!(m.artifacts.len(), 6);
    assert_eq!(m.observations.len(), 6);
    // Jedes Ereignis hat genau eine primäre Herkunft.
    for e in &m.events {
        let n = m
            .provenance
            .iter()
            .filter(|p| p.object == ObjectRef::Event(e.id))
            .count();
        assert_eq!(n, 1, "{:?}", e.kind);
    }
}

#[test]
fn identitaet_ueber_sid_und_namen() {
    let m = normalisieren(&funde(), &kontext());
    let ich = entitaet(&m, EntityKind::UserAccount, "ich");
    assert_eq!(ich.canonical_key, "sid:S-1-5-21-1-2-3-1001");
    // Die Gruppe ist eine Gruppe, kein Konto; das Mitglied nur per SID genannt
    // und dennoch dieselbe Entität wie „ich“.
    let admins = entitaet(&m, EntityKind::UserGroup, "Administratoren");
    assert!(m
        .relationships
        .iter()
        .any(|r| r.kind == RelationshipKind::MemberOf
            && r.source_entity_id == ich.id
            && r.target_entity_id == admins.id));
    assert_eq!(
        m.entities
            .iter()
            .filter(|e| e.kind == EntityKind::UserAccount)
            .count(),
        2
    );
    let erstes = ich.first_seen.unwrap().to_rfc3339();
    assert_eq!(erstes, "2026-04-18T09:44:44.668010700+00:00");
}

#[test]
fn usb_kette_benutzer_volume_geraet() {
    let m = normalisieren(&funde(), &kontext());
    let ich = entitaet(&m, EntityKind::UserAccount, "ich");
    let vol = entitaet(
        &m,
        EntityKind::Volume,
        "Volume{fff43352-3b0a-11f1-b1a1-806e6f6e6963}",
    );
    let usb = entitaet(&m, EntityKind::UsbDevice, "General UDisk USB Device");
    let hat = |k, a: EntityId, b: EntityId| {
        m.relationships
            .iter()
            .any(|r| r.kind == k && r.source_entity_id == a && r.target_entity_id == b)
    };
    assert!(hat(RelationshipKind::Uses, ich.id, vol.id));
    assert!(hat(RelationshipKind::LocatedOn, vol.id, usb.id));
    let verbunden = m
        .events
        .iter()
        .find(|e| e.kind == EventKind::UsbConnected)
        .unwrap();
    assert!(m
        .participants
        .iter()
        .any(|p| p.event_id == verbunden.id && p.entity_id == usb.id));
}

#[test]
fn ereignisse_mit_zeit_und_ableitung() {
    let m = normalisieren(&funde(), &kontext());
    let logon = m
        .events
        .iter()
        .find(|e| e.kind == EventKind::UserLogon)
        .unwrap();
    let t = logon.occurred_at.as_ref().unwrap();
    assert_eq!(t.precision, TimePrecision::HundredNanoseconds);
    assert_eq!(t.semantics, TimeSemantics::EventTime);
    assert_eq!(logon.derivation, DerivationKind::Parsed);
    assert_eq!(
        logon.attributes["anbieter"],
        "Microsoft-Windows-Security-Auditing"
    );
    let rollen: Vec<_> = m
        .participants
        .iter()
        .filter(|p| p.event_id == logon.id)
        .map(|p| p.role)
        .collect();
    for r in [
        ParticipantRole::User,
        ParticipantRole::Actor,
        ParticipantRole::Host,
        ParticipantRole::SourceIp,
    ] {
        assert!(rollen.contains(&r), "{r:?} fehlt");
    }
    let start = m
        .events
        .iter()
        .find(|e| e.kind == EventKind::ProcessStart)
        .unwrap();
    assert_eq!(start.attributes["quelle"], "prefetch");
    // Fundstelle des Logons bis zum Datei-Offset.
    let p = m
        .provenance
        .iter()
        .find(|p| p.object == ObjectRef::Event(logon.id))
        .unwrap();
    match &p.provenance.source_locator {
        Some(SourceLocator::Ntfs {
            byte_offset,
            mft_record,
            ..
        }) => {
            assert_eq!((*byte_offset, *mft_record), (Some(69_632), 39_938));
        }
        x => panic!("{x:?}"),
    }
}

#[test]
fn zweiter_lauf_gleiche_ids() {
    let a = normalisieren(&funde(), &kontext());
    let b = normalisieren(&funde(), &kontext());
    let ids = |m: &Modell| {
        (
            m.artifacts.iter().map(|x| x.id).collect::<Vec<_>>(),
            m.entities.iter().map(|x| x.id).collect::<Vec<_>>(),
            m.events.iter().map(|x| x.id).collect::<Vec<_>>(),
            m.relationships.iter().map(|x| x.id).collect::<Vec<_>>(),
        )
    };
    assert_eq!(ids(&a), ids(&b));
    let mut anders = kontext();
    anders.case_id = CaseId(Uuid::from_u128(9));
    assert_ne!(ids(&a).0, ids(&normalisieren(&funde(), &anders)).0);
}

#[test]
fn platzhalter_aus_aelteren_reports() {
    let alt = fund(
        "eventlog",
        "Prozess erstellt",
        "x.evtx",
        &[
            ("event_id", "4688"),
            ("event_record_id", "1"),
            ("benutzer", "-"),
            ("prozess", "C:\\Windows\\System32\\cmd.exe"),
        ],
    );
    let m = normalisieren(&[alt], &kontext());
    assert!(
        m.entities.iter().all(|e| e.display_name != "-"),
        "{:?}",
        m.entities
            .iter()
            .map(|e| (&e.kind, &e.display_name, &e.canonical_key))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        m.statistik.fundstelle_unvollstaendig.get("eventlog"),
        Some(&1)
    );
}

#[test]
fn spaeterer_name_ergaenzt_sid_entitaet() {
    let nur_sid = fund(
        "eventlog",
        "Prozess erstellt",
        "Security.evtx",
        &[
            ("event_id", "4688"),
            ("event_record_id", "1"),
            ("benutzer_sid", "S-1-5-18"),
        ],
    );
    let mit_name = fund(
        "eventlog",
        "Anmeldung erfolgreich",
        "Security.evtx",
        &[
            ("event_id", "4624"),
            ("event_record_id", "2"),
            ("benutzer", "SYSTEM"),
            ("benutzer_sid", "S-1-5-18"),
            ("benutzer_domaene", "NT-AUTORITÄT"),
        ],
    );
    let m = normalisieren(&[nur_sid, mit_name], &kontext());
    let konten: Vec<_> = m
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::UserAccount)
        .collect();
    assert_eq!(konten.len(), 1);
    assert_eq!(konten[0].display_name, "SYSTEM");
    assert_eq!(konten[0].attributes["domaene"], "NT-AUTORITÄT");
}
