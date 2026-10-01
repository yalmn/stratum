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

fn programmfunde() -> Vec<RawFinding> {
    vec![
        fund(
            "programmausfuehrung",
            "c:\\tools\\x.exe",
            "Amcache.hve\\Root\\InventoryApplicationFile\\x.exe|1a2b",
            &[
                ("quelle", "amcache"),
                ("pfad", "c:\\tools\\x.exe"),
                ("hive_offset", "4096"),
                ("registriert_filetime", "134209790846680107"),
                ("sha1", "0033ab10bb6747e1e2671ea044e0f3fac684e398"),
            ],
        ),
        fund(
            "programmausfuehrung",
            "C:\\Tools\\x.exe",
            "SYSTEM\\ControlSet001\\Control\\Session Manager\\AppCompatCache\\AppCompatCache",
            &[
                ("quelle", "shimcache"),
                ("pfad", "C:\\Tools\\x.exe"),
                ("hive_offset", "8192"),
                ("eintrag", "3"),
                ("eintrag_offset", "512"),
                ("letzte_aenderung_filetime", "134209790846680107"),
            ],
        ),
        fund(
            "programmausfuehrung",
            "\\Device\\HarddiskVolume3\\Tools\\x.exe",
            "SYSTEM\\ControlSet001\\Services\\bam\\State\\UserSettings\\S-1-5-21-1-2-3-1001",
            &[
                ("art", "bam"),
                ("sid", "S-1-5-21-1-2-3-1001"),
                ("hive_offset", "12288"),
                ("letzte_ausfuehrung_filetime", "134209790846680107"),
            ],
        ),
    ]
}

#[test]
fn programmausfuehrung_drei_quellen() {
    let m = normalisieren(&programmfunde(), &kontext());
    assert_eq!(m.statistik.abgebildet.get("programmausfuehrung"), Some(&3));
    assert!(m.statistik.fundstelle_unvollstaendig.is_empty());

    // Amcache und Shimcache nennen dieselbe Datei (Groß/klein egal).
    let dateien: Vec<_> = m
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::File)
        .collect();
    assert_eq!(dateien.len(), 2, "c:\\tools\\x.exe und harddiskvolume3");
    let c = dateien
        .iter()
        .find(|e| e.canonical_key == "pfad:c:\\tools\\x.exe")
        .expect("Laufwerksschlüssel");
    let hash = m
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Hash)
        .expect("SHA-1");
    assert_eq!(
        hash.canonical_key,
        "sha1:0033ab10bb6747e1e2671ea044e0f3fac684e398"
    );
    assert!(m
        .relationships
        .iter()
        .any(|r| r.kind == RelationshipKind::HasHash
            && r.source_entity_id == c.id
            && r.target_entity_id == hash.id));

    // Nur BAM belegt eine Ausführung, mit Benutzer.
    let starts: Vec<_> = m
        .events
        .iter()
        .filter(|e| e.kind == EventKind::ProcessStart)
        .collect();
    assert_eq!(starts.len(), 1);
    let rollen: Vec<_> = m
        .participants
        .iter()
        .filter(|p| p.event_id == starts[0].id)
        .map(|p| p.role)
        .collect();
    assert!(rollen.contains(&ParticipantRole::User));
    assert!(rollen.contains(&ParticipantRole::Executable));
    let shim = m
        .events
        .iter()
        .find(|e| e.kind == EventKind::FileModified)
        .expect("Shimcache-Zeit");
    assert_eq!(shim.derivation, DerivationKind::Derived);
    let amc = m
        .events
        .iter()
        .find(|e| e.kind == EventKind::Custom)
        .expect("Amcache-Zeit");
    assert_eq!(
        amc.occurred_at.as_ref().map(|t| t.semantics),
        Some(TimeSemantics::ArtifactTime)
    );

    // Fundstelle der Shimcache: Schlüssel, Wert und Zelle.
    let a = m
        .artifacts
        .iter()
        .find(|a| {
            a.kind == ArtifactKind::RegistryValue
                && a.raw_metadata["attributes"]["quelle"] == "shimcache"
        })
        .expect("Shimcache-Artefakt");
    match &a.source_locator {
        SourceLocator::Registry {
            hive,
            key_path,
            value_name,
            cell_offset,
        } => {
            assert_eq!(hive, "SYSTEM");
            assert_eq!(
                key_path,
                "ControlSet001\\Control\\Session Manager\\AppCompatCache"
            );
            assert_eq!(value_name.as_deref(), Some("AppCompatCache"));
            assert_eq!(*cell_offset, Some(8192));
        }
        l => panic!("{l:?}"),
    }
}

#[test]
fn gleicher_pfad_auf_buchstabe_und_geraet_korreliert() {
    let m = normalisieren(&programmfunde(), &kontext());
    let r: Vec<_> = m
        .relationships
        .iter()
        .filter(|r| r.kind == RelationshipKind::PossiblySameAs)
        .collect();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].derivation, DerivationKind::Correlated);
    let p: Vec<_> = m
        .provenance
        .iter()
        .filter(|p| p.object == ObjectRef::Relationship(r[0].id))
        .collect();
    assert_eq!(p.len(), 1);
    assert!(p[0].provenance.artifact_id.is_none());

    // Zwei Laufwerksbuchstaben sind kein Hinweis auf dieselbe Datei.
    let mut zwei = programmfunde();
    zwei.truncate(1);
    zwei.push(fund(
        "programmausfuehrung",
        "d:\\tools\\x.exe",
        "Amcache.hve\\Root\\InventoryApplicationFile\\x.exe|9",
        &[("quelle", "amcache"), ("pfad", "d:\\tools\\x.exe")],
    ));
    let m = normalisieren(&zwei, &kontext());
    assert!(m
        .relationships
        .iter()
        .all(|r| r.kind != RelationshipKind::PossiblySameAs));
}

fn aktivitaetsfunde() -> Vec<RawFinding> {
    let ntuser = "HKCU ich\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer";
    vec![
        fund(
            "useraktivitaet",
            "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\cmd.exe",
            &format!("{ntuser}\\UserAssist\\{{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}}\\Count"),
            &[
                ("art", "userassist"),
                ("benutzer", "ich"),
                ("wertname_roh", "{1NP14R77}\\pzq.rkr"),
                ("hive_offset", "549600"),
                ("ausfuehrungen", "3"),
                ("letzte_ausfuehrung_filetime", "134209792309810000"),
                ("pfad_aufgeloest", "C:\\WINDOWS\\system32\\cmd.exe"),
            ],
        ),
        fund(
            "useraktivitaet",
            "UEME_CTLSESSION",
            &format!("{ntuser}\\UserAssist\\{{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}}\\Count"),
            &[
                ("art", "userassist"),
                ("benutzer", "ich"),
                ("hive_offset", "444680"),
            ],
        ),
        fund(
            "useraktivitaet",
            "neu.txt",
            &format!("{ntuser}\\RecentDocs\\.txt"),
            &[
                ("art", "recent_doc"),
                ("benutzer", "ich"),
                ("wert", "1"),
                ("hive_offset", "100"),
                ("mru_position", "0"),
                ("key_letzte_aenderung_filetime", "134209790846680107"),
            ],
        ),
        fund(
            "useraktivitaet",
            "alt.txt",
            &format!("{ntuser}\\RecentDocs\\.txt"),
            &[
                ("art", "recent_doc"),
                ("benutzer", "ich"),
                ("wert", "0"),
                ("hive_offset", "200"),
                ("mru_position", "1"),
                ("key_letzte_aenderung_filetime", "134209790846680107"),
            ],
        ),
        fund(
            "useraktivitaet",
            "F:\\Bericht.txt",
            "Users\\ich\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\Bericht.lnk",
            &[
                ("art", "lnk"),
                ("benutzer", "ich"),
                ("zielpfad", "F:\\Bericht.txt"),
                ("laufwerk_seriennummer", "deb00001"),
                ("volume_offset", "122683392"),
                ("mft_record", "5000"),
                ("mft_record_offset", "3000000000"),
                ("lnk_erstellt_filetime", "134209790000000000"),
                ("lnk_geaendert_filetime", "134209790846680107"),
            ],
        ),
        fund(
            "useraktivitaet",
            "[unbekannt 0x1f]",
            "HKCU ich UsrClass.dat\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
            &[
                ("art", "shellbag"),
                ("benutzer", "ich"),
                ("bagmru", "1"),
                ("wert", "1"),
                ("hive_offset", "1297288"),
            ],
        ),
        fund(
            "useraktivitaet",
            "[unbekannt 0x1f]",
            "HKCU ich UsrClass.dat\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
            &[
                ("art", "shellbag"),
                ("benutzer", "ich"),
                ("bagmru", "3"),
                ("wert", "3"),
                ("hive_offset", "1297400"),
                ("zuletzt_verwendet_unix", "1776505481"),
            ],
        ),
    ]
}

#[test]
fn benutzeraktivitaet_zeiten_nur_wo_belegt() {
    let m = normalisieren(&aktivitaetsfunde(), &kontext());
    assert_eq!(m.statistik.abgebildet.get("useraktivitaet"), Some(&7));
    assert!(m.statistik.fundstelle_unvollstaendig.is_empty());
    let quelle = |e: &&Event| e.attributes["quelle"].as_str().map(str::to_string);

    // UserAssist: Prozessstart mit Benutzer; UEME_CTL ohne Ereignis.
    let ua: Vec<_> = m
        .events
        .iter()
        .filter(|e| quelle(e).as_deref() == Some("userassist"))
        .collect();
    assert_eq!(ua.len(), 1);
    assert_eq!(ua[0].kind, EventKind::ProcessStart);

    // RecentDocs: nur Position 0 bekommt die Schlüsselzeit, abgeleitet.
    let rd: Vec<_> = m
        .events
        .iter()
        .filter(|e| quelle(e).as_deref() == Some("recent_doc"))
        .collect();
    assert_eq!(rd.len(), 1);
    assert_eq!(rd[0].derivation, DerivationKind::Derived);
    let teil: Vec<_> = m
        .participants
        .iter()
        .filter(|p| p.event_id == rd[0].id && p.role == ParticipantRole::File)
        .collect();
    let datei = m
        .entities
        .iter()
        .find(|e| e.id == teil[0].entity_id)
        .unwrap();
    assert_eq!(datei.display_name, "neu.txt");
    assert!(
        m.relationships
            .iter()
            .filter(|r| r.kind == RelationshipKind::UsesFile)
            .count()
            >= 3
    );

    // LNK: erstes und letztes Öffnen, Ziel liegt auf dem Volume mit der
    // Seriennummer.
    let lnk: Vec<_> = m
        .events
        .iter()
        .filter(|e| quelle(e).as_deref() == Some("lnk"))
        .collect();
    assert_eq!(lnk.len(), 2);
    let vol = entitaet(&m, EntityKind::Volume, "Volume-Seriennummer deb00001");
    let ziel = entitaet(&m, EntityKind::File, "F:\\Bericht.txt");
    assert!(m
        .relationships
        .iter()
        .any(|r| r.kind == RelationshipKind::LocatedOn
            && r.source_entity_id == ziel.id
            && r.target_entity_id == vol.id));

    // ShellBags: unbekannte Elemente fallen nicht zusammen, Zeit nur beim
    // Eintrag mit zuletzt_verwendet.
    let unbekannt = m
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Directory && e.display_name == "[unbekannt 0x1f]")
        .count();
    assert_eq!(unbekannt, 2);
    assert_eq!(
        m.events
            .iter()
            .filter(|e| quelle(e).as_deref() == Some("shellbag"))
            .count(),
        1
    );

    // Fundstelle: Hive des Benutzers und echter Schlüsselpfad.
    let a = m
        .artifacts
        .iter()
        .find(|a| a.raw_metadata["name"] == "neu.txt")
        .unwrap();
    match &a.source_locator {
        SourceLocator::Registry {
            hive,
            key_path,
            value_name,
            cell_offset,
        } => {
            assert_eq!(hive, "NTUSER.DAT ich");
            assert!(key_path.starts_with("Software\\"), "{key_path}");
            assert_eq!(value_name.as_deref(), Some("1"));
            assert_eq!(*cell_offset, Some(100));
        }
        l => panic!("{l:?}"),
    }
    let sb = m
        .artifacts
        .iter()
        .find(|a| a.kind == ArtifactKind::ShellItem)
        .unwrap();
    assert!(
        matches!(&sb.source_locator, SourceLocator::Registry { hive, .. } if hive == "UsrClass.dat ich")
    );
}
