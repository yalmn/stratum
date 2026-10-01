//! Zugangsdaten: LSA-Secrets, gecachte Domänenanmeldungen (DCC2),
//! DPAPI-System-Masterkeys und entschlüsselte Browser-Logins.
//!
//! Auf Wunsch des Nutzers (2026-10-01) gehen auch die Geheimwerte ins Modell:
//! Passwörter, Hashes, Secret-Inhalte und Schlüssel, wie im Report. Sie
//! stehen in der Observation und an der Credential-Entität, die dazu
//! `sensibel: true` trägt. Das Ansehen soll später über die Rechte- und
//! Auditprüfung laufen (CREDENTIAL_VIEW in der Zielarchitektur).
//!
//! Status wie im Projekt vereinbart: `entschluesselt` oder `schluessel_fehlt`.

use serde_json::json;
use stratum_analysis::RawFinding;
use stratum_model::{
    ArtifactKind, Entity, EntityId, EntityKind, Relationship, RelationshipKind, SourceLocator,
};

use crate::aktivitaet::url;
use crate::hilfen::{
    artefakt, benutzer, dienst, herkunft, herkunft_zusatz, host, ntfs, text, zahl,
};
use crate::{Abbildung, Baukasten, GELESEN};

/// Felder mit Geheimwerten, die an die Credential-Entität übernommen werden.
const GEHEIM: &[&str] = &[
    "passwort",
    "dcc2_hash",
    "wert",
    "dpapi_machinekey",
    "dpapi_userkey",
    "masterkey_hex",
];

pub fn abbilden(f: &RawFinding, b: &mut Baukasten<'_>) -> Abbildung {
    match (f.domain.as_str(), text(f, "art")) {
        ("lsa", Some("dcc2")) => dcc2(f, b),
        ("lsa", _) => lsa_secret(f, b),
        ("dpapi", _) => masterkey(f, b),
        ("browser", Some("passwort_klartext")) => browser_login(f, b),
        _ => {
            b.hinweis(format!("Zugangsdaten ohne bekannte Art: {}", f.name));
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

fn host_teil(b: &Baukasten<'_>) -> String {
    b.k.host.as_deref().unwrap_or("?").to_lowercase()
}

fn credential(
    b: &mut Baukasten<'_>,
    f: &RawFinding,
    schluessel: String,
    anzeige: String,
    mut attribute: serde_json::Value,
) -> EntityId {
    attribute["sensibel"] = json!(true);
    for k in GEHEIM {
        if let Some(v) = text(f, k) {
            attribute[*k] = json!(v);
        }
    }
    let mut e = Entity::new(
        b.k.case_id,
        EntityKind::Credential,
        schluessel,
        anzeige,
        b.k.zeitpunkt,
    );
    e.attributes = attribute;
    b.entity(e, None)
}

fn gehoert_zu(
    b: &mut Baukasten<'_>,
    von: EntityId,
    zu: EntityId,
    prov: &stratum_model::ProvenanceRef,
) {
    b.relationship(
        Relationship::new(b.k.case_id, RelationshipKind::BelongsTo, von, zu, GELESEN),
        prov.clone(),
    );
}

fn security(f: &RawFinding, wert: Option<&str>) -> SourceLocator {
    SourceLocator::Registry {
        hive: "SECURITY".into(),
        key_path: f
            .source
            .strip_prefix("SECURITY\\")
            .unwrap_or(&f.source)
            .to_string(),
        value_name: wert.map(str::to_string),
        cell_offset: zahl(f, "hive_offset"),
    }
}

/// LSA-Secret. `_SC_<Dienst>` ist das Kennwort eines Dienstkontos und gehört
/// zum Dienst, alle anderen zum Rechner.
fn lsa_secret(f: &RawFinding, b: &mut Baukasten<'_>) -> Abbildung {
    let schluessel = format!("lsa:{}{}", f.name, herkunft_zusatz(f));
    let locator = security(f, Some("(Standard)"));
    let (aid, oid) = artefakt(
        b,
        f,
        ArtifactKind::RegistryValue,
        locator.clone(),
        &schluessel,
        "lsa_secret",
    );
    let mut attr = json!({"art": "lsa_secret", "status": "entschluesselt"});
    if let Some(l) = text(f, "laenge") {
        attr["laenge"] = json!(l);
    }
    let cid = credential(
        b,
        f,
        format!("credential:{}:lsa:{}", host_teil(b), f.name.to_lowercase()),
        format!("LSA-Secret {}", f.name),
        attr,
    );
    let prov = herkunft(b, f, aid, oid, locator);
    let besitzer = match f.name.strip_prefix("_SC_") {
        Some(d) => Some(dienst(b, d, None, None)),
        None => host(b),
    };
    if let Some(z) = besitzer {
        gehoert_zu(b, cid, z, &prov);
    }
    vollstaendig(zahl(f, "hive_offset").is_some())
}

/// Gecachte Domänenanmeldung: der Hash bleibt im Report, das Modell weiß
/// nur, dass für das Konto ein Cache-Eintrag besteht.
fn dcc2(f: &RawFinding, b: &mut Baukasten<'_>) -> Abbildung {
    let wert = text(f, "wertname");
    let schluessel = format!(
        "dcc2:{}:{}{}",
        wert.unwrap_or("?"),
        f.name,
        herkunft_zusatz(f)
    );
    let locator = security(f, wert);
    let (aid, oid) = artefakt(
        b,
        f,
        ArtifactKind::RegistryValue,
        locator.clone(),
        &schluessel,
        "cached_logon",
    );
    let cid = credential(
        b,
        f,
        format!("credential:{}:dcc2:{}", host_teil(b), f.name.to_lowercase()),
        format!("Gecachte Anmeldung {}", f.name),
        json!({"art": "dcc2", "status": "entschluesselt"}),
    );
    let prov = herkunft(b, f, aid, oid, locator);
    let (domaene, name) = match f.name.split_once('\\') {
        Some((d, n)) => (Some(d), n),
        None => (None, f.name.as_str()),
    };
    if let Some(u) = benutzer(b, Some(name), None, domaene, None) {
        gehoert_zu(b, cid, u, &prov);
    }
    vollstaendig(zahl(f, "hive_offset").is_some())
}

/// DPAPI-System-Masterkey: gehört zum Konto aus dem Pfad
/// (`…\Protect\S-1-5-18\…`).
fn masterkey(f: &RawFinding, b: &mut Baukasten<'_>) -> Abbildung {
    let guid = text(f, "guid").unwrap_or(&f.name);
    let schluessel = format!("dpapi:{}{}", f.source.to_lowercase(), herkunft_zusatz(f));
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
        ArtifactKind::NtfsStream,
        locator.clone(),
        &schluessel,
        "dpapi_masterkey",
    );
    let status = if text(f, "entschluesselt") == Some("ja") {
        "entschluesselt"
    } else {
        "schluessel_fehlt"
    };
    let cid = credential(
        b,
        f,
        format!(
            "credential:{}:dpapi_masterkey:{}",
            host_teil(b),
            guid.to_lowercase()
        ),
        format!("DPAPI-Masterkey {guid}"),
        json!({"art": "dpapi_masterkey", "status": status}),
    );
    let prov = herkunft(b, f, aid, oid, locator);
    let sid = f.source.split('\\').find(|t| t.starts_with("S-1-"));
    if let Some(u) = sid.and_then(|s| benutzer(b, None, Some(s), None, None)) {
        gehoert_zu(b, cid, u, &prov);
    }
    // Entschlüsselt mit einem Teil von DPAPI_SYSTEM: dieselbe Entität wie beim
    // LSA-Secret, damit der Weg zum Schlüssel im Modell sichtbar ist.
    if status == "entschluesselt" {
        // Ohne Werte des Masterkey-Funds anlegen; die Werte von DPAPI_SYSTEM
        // kommen aus dessen eigenem LSA-Fund.
        let mut e = Entity::new(
            b.k.case_id,
            EntityKind::Credential,
            format!("credential:{}:lsa:dpapi_system", host_teil(b)),
            "LSA-Secret DPAPI_SYSTEM".into(),
            b.k.zeitpunkt,
        );
        e.attributes = json!({"art": "lsa_secret", "sensibel": true});
        let lsa = b.entity(e, None);
        let mut r = Relationship::new(
            b.k.case_id,
            RelationshipKind::DerivedFrom,
            cid,
            lsa,
            GELESEN,
        );
        r.attributes = json!({
            "grundlage": "entschluesselt mit",
            "schluessel": text(f, "schluessel"),
            "entschluesselt_mit": text(f, "entschluesselt_mit"),
        });
        b.relationship(r, prov.clone());
    }
    vollstaendig(ok)
}

/// Entschlüsseltes Browser-Login: Konto des Profils, URL und Benutzername,
/// ohne Passwort.
fn browser_login(f: &RawFinding, b: &mut Baukasten<'_>) -> Abbildung {
    let browser = text(f, "browser").unwrap_or("?");
    let adresse = text(f, "url").unwrap_or("?");
    let login = text(f, "benutzername").unwrap_or("");
    let schluessel = format!(
        "login:{}:{adresse}:{login}{}",
        f.source.to_lowercase(),
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
        ArtifactKind::BrowserLoginRow,
        locator.clone(),
        &schluessel,
        "browser_login",
    );
    let mut attr = json!({"art": "browser_login", "status": "entschluesselt", "browser": browser});
    if !login.is_empty() {
        attr["benutzername"] = json!(login);
    }
    let cid = credential(
        b,
        f,
        format!(
            "credential:{}:browser:{}:{}:{}",
            host_teil(b),
            browser,
            adresse.to_lowercase(),
            login.to_lowercase()
        ),
        format!("Login {adresse}"),
        attr,
    );
    let prov = herkunft(b, f, aid, oid, locator);
    let uid = url(b, adresse, None);
    b.relationship(
        Relationship::new(b.k.case_id, RelationshipKind::References, cid, uid, GELESEN),
        prov.clone(),
    );
    let konto = f
        .source
        .trim_start_matches('\\')
        .split('\\')
        .nth(1)
        .filter(|_| {
            f.source
                .trim_start_matches('\\')
                .to_ascii_lowercase()
                .starts_with("users\\")
        });
    if let Some(k) = konto.and_then(|n| benutzer(b, Some(n), None, None, None)) {
        gehoert_zu(b, cid, k, &prov);
    }
    vollstaendig(ok)
}
