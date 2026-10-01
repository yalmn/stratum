//! Browser: Verlauf aus Chromium und Firefox, WebCache von Edge und Internet
//! Explorer.
//!
//! - Verlaufseinträge (Chromium, Firefox, WebCache-Container `History` und
//!   `MSHist…`) ergeben einen Besuch. Die Zeit ist der Zugriff laut Quelle.
//!   Die `ModifiedTime` der MSHist-Container ist vermutlich Ortszeit und
//!   bleibt unverändert in der Observation.
//! - Cache-, DOMStore- und Cookie-Einträge belegen nur, dass der Benutzer
//!   die URL genutzt hat; sie ergeben kein Ereignis.
//! - `file:///`-URLs verweisen auf die Datei mit demselben Pfad.
//! - Datenbanken, Tabellen und die Bestandsaufnahme gespeicherter
//!   Zugangsdaten (nur Anzahl) werden Artefakte ohne Entitäten. Entschlüsselte
//!   Logins bildet [`crate::zugangsdaten`] ab.

use serde_json::json;
use stratum_analysis::RawFinding;
use stratum_model::{
    ArtifactKind, DerivationKind, EntityId, Event, EventId, EventKind, EventParticipant,
    ForensicTime, ParticipantRole, Relationship, RelationshipKind, SourceLocator, TimeSemantics,
};

use crate::aktivitaet::url;
use crate::hilfen::{
    artefakt, benutzer, datei, herkunft, herkunft_zusatz, host, ntfs, text, zahl, zeit_unix,
};
use crate::{Abbildung, Baukasten, GELESEN};

pub fn abbilden(f: &RawFinding, b: &mut Baukasten<'_>) -> Abbildung {
    match text(f, "art") {
        Some("verlauf") => verlauf(f, b),
        Some("webcache_eintrag") => webcache(f, b),
        Some(art @ ("verlauf_db" | "passwoerter" | "webcache_db")) => {
            nur_artefakt(f, b, ArtifactKind::NtfsStream, art)
        }
        Some("webcache_tabelle") => nur_artefakt(f, b, ArtifactKind::EseRecord, "webcache_tabelle"),
        _ => {
            b.hinweis(format!("Browserfund ohne bekannte Art: {}", f.name));
            Abbildung::FundstelleUnvollstaendig
        }
    }
}

/// Fundstelle in einer Datei: NTFS mit Byte-Offset, falls bekannt.
fn fundstelle(f: &RawFinding) -> (SourceLocator, bool) {
    match ntfs(f) {
        Some(l) => (l, true),
        None => (
            SourceLocator::FileLine {
                path: f.source.clone(),
                line: 0,
                byte_offset: zahl(f, "datei_offset"),
            },
            false,
        ),
    }
}

fn vollstaendig(ok: bool) -> Abbildung {
    if ok {
        Abbildung::Vollstaendig
    } else {
        Abbildung::FundstelleUnvollstaendig
    }
}

/// Benutzer aus einem Pfad unter `Users\<Name>\`.
fn benutzer_aus_pfad(pfad: &str) -> Option<&str> {
    let mut teile = pfad.trim_start_matches('\\').split('\\');
    let erstes = teile.next()?;
    if !erstes.eq_ignore_ascii_case("Users") {
        return None;
    }
    teile.next().filter(|n| !n.is_empty())
}

fn nutzer(
    b: &mut Baukasten<'_>,
    f: &RawFinding,
    gesehen: Option<chrono::DateTime<chrono::Utc>>,
) -> Option<EntityId> {
    let name = text(f, "url_konto")
        .or(text(f, "benutzer"))
        .or_else(|| benutzer_aus_pfad(&f.source));
    benutzer(b, name, None, None, gesehen)
}

/// Dekodiert `%XX` als UTF-8; ungültige Folgen bleiben, wie sie sind.
fn prozent_dekodieren(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hex = std::str::from_utf8(&b[i + 1..i + 3]).ok();
            if let Some(v) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| s.to_string())
}

/// Lokaler Pfad aus einer `file:///`-URL (`file:///F:/a%20b.txt` ergibt
/// `F:\a b.txt`). Nur Laufwerkspfade; UNC-Pfade (`file://server/…`) nicht.
pub(crate) fn datei_aus_url(u: &str) -> Option<String> {
    let rest = u.strip_prefix("file:///")?;
    let pfad = prozent_dekodieren(rest).replace('/', "\\");
    let p = pfad.as_bytes();
    (p.len() > 2 && p[0].is_ascii_alphabetic() && p[1] == b':').then_some(pfad)
}

/// URL-Entität, Nutzung durch den Benutzer und bei `file:///` der Verweis
/// auf die Datei.
fn url_mit_bezug(
    b: &mut Baukasten<'_>,
    adresse: &str,
    uid: Option<EntityId>,
    gesehen: Option<chrono::DateTime<chrono::Utc>>,
    prov: &stratum_model::ProvenanceRef,
    quelle: &str,
) -> EntityId {
    let url_id = url(b, adresse, gesehen);
    if let Some(u) = uid {
        let mut r = Relationship::new(b.k.case_id, RelationshipKind::Uses, u, url_id, GELESEN);
        r.attributes = json!({"quelle": quelle});
        b.relationship(r, prov.clone());
    }
    if let Some(p) = datei_aus_url(adresse) {
        let did = datei(b, &p, gesehen);
        b.relationship(
            Relationship::new(
                b.k.case_id,
                RelationshipKind::References,
                url_id,
                did,
                DerivationKind::Derived,
            ),
            prov.clone(),
        );
    }
    url_id
}

fn besuch(
    b: &mut Baukasten<'_>,
    schluessel: &str,
    zeit: ForensicTime,
    teilnehmer: &[(EntityId, ParticipantRole)],
    attribute: serde_json::Value,
    prov: stratum_model::ProvenanceRef,
) {
    let eid = EventId::derive(b.k.case_id, "browser_visit", schluessel);
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
            kind: EventKind::BrowserVisit,
            occurred_at: Some(zeit),
            ended_at: None,
            attributes: attribute,
            derivation: GELESEN,
            created_at: b.k.zeitpunkt,
        },
        t,
        prov,
    );
}

/// Verlaufszeile aus Chromium oder Firefox.
fn verlauf(f: &RawFinding, b: &mut Baukasten<'_>) -> Abbildung {
    let browser = text(f, "browser").unwrap_or("?");
    let zeit = zeit_unix(f, "besucht_unix");
    let schluessel = format!(
        "verlauf:{}:{}:{}:{}{}",
        f.source.to_lowercase(),
        f.name,
        text(f, "besucht_unix").unwrap_or("?"),
        browser,
        herkunft_zusatz(f)
    );
    let (locator, ok) = fundstelle(f);
    let (aid, oid) = artefakt(
        b,
        f,
        ArtifactKind::BrowserHistoryRow,
        locator.clone(),
        &schluessel,
        "browser_history",
    );
    let gesehen = zeit.as_ref().map(|z| z.utc);
    let uid = nutzer(b, f, gesehen);
    let prov = herkunft(b, f, aid, oid, locator);
    let ziel = url_mit_bezug(b, &f.name, uid, gesehen, &prov, browser);
    if let Some(titel) = text(f, "titel") {
        b.entity_attribute(ziel, json!({"titel": titel}));
    }
    if let Some(z) = zeit {
        let mut t = vec![(ziel, ParticipantRole::Object)];
        if let Some(u) = uid {
            t.push((u, ParticipantRole::User));
        }
        besuch(
            b,
            &schluessel,
            z,
            &t,
            json!({"quelle": browser, "zeitpunkt": "besucht"}),
            prov,
        );
    }
    vollstaendig(ok)
}

/// WebCache-Eintrag. Verlaufscontainer tragen `url` (ohne `Visited:` und
/// Konto) und `url_konto`.
fn webcache(f: &RawFinding, b: &mut Baukasten<'_>) -> Abbildung {
    let container = text(f, "container").unwrap_or("?");
    let schluessel = format!(
        "webcache:{}:{}:{}:{}{}",
        text(f, "mft_record").unwrap_or("?"),
        text(f, "tabelle").unwrap_or("?"),
        text(f, "EntryId").unwrap_or("?"),
        text(f, "seite").unwrap_or("?"),
        herkunft_zusatz(f)
    );
    let (locator, ok) = fundstelle(f);
    let (aid, oid) = artefakt(
        b,
        f,
        ArtifactKind::EseRecord,
        locator.clone(),
        &schluessel,
        "webcache_entry",
    );
    // Gruppierungseinträge im Tagesverlauf (`:Host: …`) sind keine URL.
    if f.name.starts_with(":Host:") {
        return vollstaendig(ok);
    }
    let verlauf = text(f, "url").is_some();
    let adresse = text(f, "url").or(text(f, "Url")).unwrap_or(&f.name);
    let zeit = zahl(f, "AccessedTime")
        .and_then(|ft| ForensicTime::from_filetime(ft, TimeSemantics::EventTime));
    let gesehen = zeit.as_ref().map(|z| z.utc);
    let uid = nutzer(b, f, gesehen);
    let prov = herkunft(b, f, aid, oid, locator);
    let ziel = url_mit_bezug(b, adresse, uid, gesehen, &prov, "webcache");
    if let (true, Some(z)) = (verlauf, zeit) {
        let mut t = vec![(ziel, ParticipantRole::Object)];
        if let Some(u) = uid {
            t.push((u, ParticipantRole::User));
        }
        let mut attribute = json!({
            "quelle": "webcache",
            "container": container,
            "zeitpunkt": "letzter_zugriff",
        });
        for k in ["AccessCount", "zeitraum"] {
            if let Some(v) = text(f, k) {
                attribute[k] = json!(v);
            }
        }
        besuch(b, &schluessel, z, &t, attribute, prov);
    }
    vollstaendig(ok)
}

/// Datenbank, Tabelle oder Bestandsaufnahme: nur Artefakt und Observation.
fn nur_artefakt(f: &RawFinding, b: &mut Baukasten<'_>, kind: ArtifactKind, art: &str) -> Abbildung {
    let schluessel = format!(
        "browser:{art}:{}:{}:{}:{}{}",
        f.source.to_lowercase(),
        text(f, "tabelle").unwrap_or(""),
        text(f, "seite").unwrap_or(""),
        text(f, "datei_offset").unwrap_or(""),
        herkunft_zusatz(f)
    );
    let (locator, ok) = fundstelle(f);
    artefakt(b, f, kind, locator, &schluessel, art);
    vollstaendig(ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datei_aus_file_url() {
        assert_eq!(
            datei_aus_url("file:///F:/BitLocker-Wiederherstellungsschl%C3%BCssel%2023E0.TXT")
                .as_deref(),
            Some("F:\\BitLocker-Wiederherstellungsschlüssel 23E0.TXT")
        );
        assert_eq!(
            datei_aus_url("file:///F:/Bitlocker-Wiederherstellungsschlüssel%2023E0.TXT").as_deref(),
            Some("F:\\Bitlocker-Wiederherstellungsschlüssel 23E0.TXT")
        );
        assert_eq!(datei_aus_url("file://server/share/x"), None);
        assert_eq!(datei_aus_url("https://x.tld/"), None);
        // Unvollständige Folge am Ende bleibt stehen.
        assert_eq!(prozent_dekodieren("a%2"), "a%2");
        assert_eq!(prozent_dekodieren("a%zz"), "a%zz");
    }

    #[test]
    fn benutzer_nur_unter_users() {
        assert_eq!(
            benutzer_aus_pfad("Users\\ich\\AppData\\Local\\x\\History"),
            Some("ich")
        );
        assert_eq!(benutzer_aus_pfad("Windows\\x"), None);
    }
}
