//! USB: Geräte mit ihren Zeitpunkten, zugeordnete Volumes und
//! Laufwerksbuchstaben (`MountedDevices`) und die Nutzung von Volumes durch
//! Benutzer (`MountPoints2`). Daraus entsteht die Kette Benutzer nutzt
//! Volume, Volume liegt auf Gerät.

use serde_json::json;
use stratum_analysis::RawFinding;
use stratum_model::{
    ArtifactKind, DerivationKind, Entity, EntityId, EntityKind, Event, EventId, EventKind,
    EventParticipant, ParticipantRole, Relationship, RelationshipKind, SourceLocator,
};

use crate::hilfen::{
    artefakt, benutzer, herkunft, herkunft_zusatz, host, text, zahl, zeit_filetime,
};
use crate::{Abbildung, Baukasten, GELESEN};

/// Gerät über seine Instanzkennung (Seriennummer im Sinn von USBSTOR).
fn geraet(b: &mut Baukasten<'_>, seriennummer: &str, anzeige: &str) -> EntityId {
    let e = Entity::new(
        b.k.case_id,
        EntityKind::UsbDevice,
        format!("usb:{}", seriennummer.to_lowercase()),
        anzeige.to_string(),
        b.k.zeitpunkt,
    );
    b.entity(e, None)
}

/// Seriennummer aus einem MountedDevices-Wert wie
/// `_??_USBSTOR#Disk&Ven_X&Prod_Y#<Seriennummer>#{GUID}`.
fn seriennummer_aus_geraet(geraet: &str) -> Option<&str> {
    if !geraet.to_ascii_uppercase().contains("USBSTOR#") {
        return None;
    }
    geraet.split('#').nth(2).filter(|s| !s.is_empty())
}

/// GUID in geschweiften Klammern aus einem Namen wie `\??\Volume{...}`.
fn guid(name: &str) -> Option<String> {
    let a = name.find('{')?;
    let e = name[a..].find('}')? + a;
    Some(name[a..=e].to_lowercase())
}

fn vollstaendig(f: &RawFinding) -> Abbildung {
    if zahl(f, "hive_offset").is_some() {
        Abbildung::Vollstaendig
    } else {
        Abbildung::FundstelleUnvollstaendig
    }
}

fn volume(b: &mut Baukasten<'_>, key: String, anzeige: String) -> EntityId {
    let e = Entity::new(b.k.case_id, EntityKind::Volume, key, anzeige, b.k.zeitpunkt);
    b.entity(e, None)
}

fn registry(f: &RawFinding, hive: &str, wert: Option<&str>) -> SourceLocator {
    SourceLocator::Registry {
        hive: hive.to_string(),
        key_path: f.source.clone(),
        value_name: wert.map(str::to_string),
        cell_offset: zahl(f, "hive_offset"),
    }
}

pub fn abbilden(f: &RawFinding, b: &mut Baukasten<'_>) -> Abbildung {
    match text(f, "art") {
        None if text(f, "seriennummer").is_some() => geraet_mit_zeiten(f, b),
        Some("mounted_device") => zugeordnet(f, b),
        Some("mount_point") => genutzt(f, b),
        _ => {
            b.hinweis(format!("USB-Fund ohne bekannte Art: {}", f.name));
            Abbildung::FundstelleUnvollstaendig
        }
    }
}

/// USBSTOR-Gerät: Ereignisse aus den Zeitpunkten der Property-Werte, jedes
/// mit der Fundstelle seines Werts.
fn geraet_mit_zeiten(f: &RawFinding, b: &mut Baukasten<'_>) -> Abbildung {
    let sn = text(f, "seriennummer").unwrap_or_default().to_string();
    let schluessel = format!("registry:SYSTEM:{}{}", f.source, herkunft_zusatz(f));
    let locator = registry(f, "SYSTEM", None);
    let (aid, oid) = artefakt(
        b,
        f,
        ArtifactKind::RegistryKey,
        locator,
        &schluessel,
        "usb_device",
    );
    let gid = geraet(b, &sn, &f.name);
    for (feld, kind, eigen) in [
        (
            "erste_installation",
            EventKind::Custom,
            Some("usb_first_install"),
        ),
        ("installation", EventKind::Custom, Some("usb_install")),
        ("letzte_verbindung", EventKind::UsbConnected, None),
        ("letztes_trennen", EventKind::UsbRemoved, None),
    ] {
        let Some(zeit) = zeit_filetime(f, &format!("{feld}_filetime")) else {
            continue;
        };
        let gesehen = Some(zeit.utc);
        b.entity(
            Entity::new(
                b.k.case_id,
                EntityKind::UsbDevice,
                format!("usb:{}", sn.to_lowercase()),
                f.name.clone(),
                b.k.zeitpunkt,
            ),
            gesehen,
        );
        let kind_name = eigen.unwrap_or(match kind {
            EventKind::UsbConnected => "usb_connected",
            _ => "usb_removed",
        });
        let eid = EventId::derive(b.k.case_id, kind_name, &format!("{schluessel}:{feld}"));
        let mut teilnehmer = vec![EventParticipant {
            event_id: eid,
            entity_id: gid,
            role: ParticipantRole::Device,
        }];
        if let Some(h) = host(b) {
            teilnehmer.push(EventParticipant {
                event_id: eid,
                entity_id: h,
                role: ParticipantRole::Host,
            });
        }
        // Fundstelle ist der Property-Wert selbst.
        let wert = SourceLocator::Registry {
            hive: "SYSTEM".into(),
            key_path: text(f, &format!("{feld}_quelle"))
                .unwrap_or(&f.source)
                .to_string(),
            value_name: Some("(Standard)".into()),
            cell_offset: zahl(f, &format!("{feld}_hive_offset")),
        };
        let mut attribute = json!({"zeitpunkt": feld});
        if eigen.is_some() {
            attribute["art"] = json!(kind_name);
        }
        let prov = herkunft(b, f, aid, oid, wert);
        b.event(
            Event {
                id: eid,
                case_id: b.k.case_id,
                kind,
                occurred_at: Some(zeit),
                ended_at: None,
                attributes: attribute,
                derivation: GELESEN,
                created_at: b.k.zeitpunkt,
            },
            teilnehmer,
            prov,
        );
    }
    if zahl(f, "hive_offset").is_some() {
        Abbildung::Vollstaendig
    } else {
        Abbildung::FundstelleUnvollstaendig
    }
}

/// MountedDevices: Volume-GUID oder Laufwerksbuchstabe liegt auf einem
/// USB-Gerät.
fn zugeordnet(f: &RawFinding, b: &mut Baukasten<'_>) -> Abbildung {
    let schluessel = format!(
        "registry:SYSTEM\\MountedDevices:{}{}",
        f.name,
        herkunft_zusatz(f)
    );
    let locator = registry(f, "SYSTEM", Some(&f.name));
    let (aid, oid) = artefakt(
        b,
        f,
        ArtifactKind::RegistryValue,
        locator.clone(),
        &schluessel,
        "mounted_device",
    );
    let ziel = if let Some(g) = guid(&f.name) {
        Some((format!("volume:{g}"), format!("Volume{g}")))
    } else {
        f.name
            .strip_prefix("\\DosDevices\\")
            .map(|l| (format!("laufwerk:{}", l.to_lowercase()), l.to_string()))
    };
    let sn = text(f, "geraet").and_then(seriennummer_aus_geraet);
    if let (Some((key, anzeige)), Some(sn)) = (ziel, sn) {
        let vid = volume(b, key, anzeige);
        let gid = geraet(b, sn, sn);
        let prov = herkunft(b, f, aid, oid, locator);
        b.relationship(
            Relationship::new(
                b.k.case_id,
                RelationshipKind::LocatedOn,
                vid,
                gid,
                DerivationKind::Derived,
            ),
            prov,
        );
    }
    vollstaendig(f)
}

/// MountPoints2: der Benutzer hat das Volume oder die Freigabe genutzt. Die
/// Zeit ist die letzte Änderung des Schlüssels, keine Nutzungszeit.
fn genutzt(f: &RawFinding, b: &mut Baukasten<'_>) -> Abbildung {
    let nutzer = text(f, "benutzer");
    let schluessel = format!(
        "registry:NTUSER:{}:{}{}",
        nutzer.unwrap_or("?"),
        f.name,
        herkunft_zusatz(f)
    );
    let locator = registry(f, &format!("NTUSER.DAT {}", nutzer.unwrap_or("?")), None);
    let (aid, oid) = artefakt(
        b,
        f,
        ArtifactKind::RegistryKey,
        locator.clone(),
        &schluessel,
        "mount_point",
    );
    let ziel = if let Some(g) = guid(&f.name) {
        volume(b, format!("volume:{g}"), format!("Volume{g}"))
    } else {
        // Netzwerkfreigabe: `##Server#Freigabe` steht für `\\Server\Freigabe`.
        let unc = format!("\\\\{}", f.name.trim_start_matches('#').replace('#', "\\"));
        let e = Entity::new(
            b.k.case_id,
            EntityKind::NetworkShare,
            format!("freigabe:{}", unc.to_lowercase()),
            unc,
            b.k.zeitpunkt,
        );
        b.entity(e, None)
    };
    if let Some(uid) = benutzer(b, nutzer, None, None, None) {
        let mut r = Relationship::new(
            b.k.case_id,
            RelationshipKind::Uses,
            uid,
            ziel,
            DerivationKind::Derived,
        );
        if let Some(t) = text(f, "letzter_zugriff_unix").and_then(|s| s.parse::<i64>().ok()) {
            if let Some(utc) = chrono::DateTime::from_timestamp(t, 0) {
                r.attributes = json!({"schluessel_letzte_aenderung_utc": utc.to_rfc3339()});
            }
        }
        let prov = herkunft(b, f, aid, oid, locator);
        b.relationship(r, prov);
    }
    vollstaendig(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seriennummer_und_guid() {
        assert_eq!(
            seriennummer_aus_geraet("_??_USBSTOR#Disk&Ven_General&Prod_UDisk&Rev_5.00#6&1526ad36&0&_&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}"),
            Some("6&1526ad36&0&_&0")
        );
        assert_eq!(seriennummer_aus_geraet("_??_SCSI#Disk#123#{x}"), None);
        assert_eq!(
            guid("\\??\\Volume{FFF43352-3b0a-11f1-b1a1-806e6f6e6963}").as_deref(),
            Some("{fff43352-3b0a-11f1-b1a1-806e6f6e6963}")
        );
        assert_eq!(guid("\\DosDevices\\F:"), None);
    }
}
