//! Gemeinsame Hilfen: Fundstellen, Zeiten, Artefakte und Personen.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Map, Value};
use stratum_analysis::RawFinding;
use stratum_model::{
    canonical, Artifact, ArtifactId, ArtifactKind, Entity, EntityId, EntityKind, ForensicTime,
    Observation, ObservationId, ObservationKind, ProvenanceRef, ShadowCopyRef, SourceLocator,
    TimeSemantics,
};

use crate::Baukasten;

/// Attribut als Zahl.
pub fn zahl(f: &RawFinding, key: &str) -> Option<u64> {
    f.attributes.get(key)?.parse().ok()
}

/// Attribut als Text, ohne leere Werte und Platzhalter wie „-“ (ältere
/// Reports enthalten sie noch).
pub fn text<'f>(f: &'f RawFinding, key: &str) -> Option<&'f str> {
    f.attributes
        .get(key)
        .map(String::as_str)
        .filter(|s| !s.is_empty() && *s != "-" && *s != "S-1-0-0")
}

/// Schattenkopie aus `herkunft` (`VSS#n`), falls der Fund nicht live ist.
pub fn schattenkopie(f: &RawFinding) -> Option<ShadowCopyRef> {
    let n: usize = text(f, "herkunft")?.strip_prefix("VSS#")?.parse().ok()?;
    Some(ShadowCopyRef {
        store: n.checked_sub(1)?,
        store_id: None,
    })
}

/// Zusatz für Schlüssel, damit Live-Stand und Schattenkopie getrennt bleiben.
pub fn herkunft_zusatz(f: &RawFinding) -> String {
    text(f, "herkunft")
        .map(|h| format!(":{h}"))
        .unwrap_or_default()
}

/// NTFS-Fundstelle aus den Herkunftsattributen eines Rohfunds. `None`, wenn
/// Volume-Offset oder MFT-Nummer fehlen.
pub fn ntfs(f: &RawFinding) -> Option<SourceLocator> {
    Some(SourceLocator::Ntfs {
        volume_offset: zahl(f, "volume_offset")?,
        mft_record: zahl(f, "mft_record")?,
        sequence: None,
        stream: None,
        record_offset: zahl(f, "mft_record_offset"),
        byte_offset: zahl(f, "datei_offset"),
        image_offset: f.offset,
        shadow_copy: schattenkopie(f),
    })
}

/// Artefakt und Observation für einen Rohfund anlegen. Die Observation
/// enthält die Attribute ohne reine Herkunftsangaben.
pub fn artefakt(
    b: &mut Baukasten<'_>,
    f: &RawFinding,
    kind: ArtifactKind,
    locator: SourceLocator,
    schluessel: &str,
    beobachtung: &str,
) -> (ArtifactId, ObservationId) {
    let k = b.k;
    let id = ArtifactId::derive(k.case_id, &k.evidence_sha256, schluessel);
    let parser = b.parser(&f.domain);
    b.artifact(Artifact {
        id,
        case_id: k.case_id,
        evidence_id: k.evidence_id,
        kind,
        source_locator: locator,
        parser: parser.clone(),
        raw_metadata: serde_json::to_value(f).unwrap_or(Value::Null),
        created_at: k.zeitpunkt,
    });
    const HERKUNFT: &[&str] = &[
        "volume_offset",
        "mft_record",
        "mft_record_offset",
        "datei_offset",
        "image_offset_fehlt",
        "hive_offset",
    ];
    let felder: Map<String, Value> = f
        .attributes
        .iter()
        .filter(|(k, _)| !HERKUNFT.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), Value::String(v.clone())))
        .collect();
    let oid = ObservationId::derive(id, beobachtung);
    b.observation(Observation {
        id: oid,
        case_id: k.case_id,
        artifact_id: id,
        kind: ObservationKind(beobachtung.into()),
        fields: Value::Object(felder),
        parser,
        observed_at: k.zeitpunkt,
    });
    (id, oid)
}

/// Herkunftsangabe zu einem Artefakt.
pub fn herkunft(
    b: &Baukasten<'_>,
    f: &RawFinding,
    artifact: ArtifactId,
    observation: ObservationId,
    locator: SourceLocator,
) -> ProvenanceRef {
    ProvenanceRef {
        evidence_id: b.k.evidence_id,
        artifact_id: Some(artifact),
        observation_id: Some(observation),
        source_locator: Some(locator),
        parser: Some(b.parser(&f.domain)),
        analysis_run_id: None,
    }
}

/// Ereigniszeit aus einer FILETIME im Attribut `key`.
pub fn zeit_filetime(f: &RawFinding, key: &str) -> Option<ForensicTime> {
    ForensicTime::from_filetime(zahl(f, key)?, TimeSemantics::EventTime)
}

/// Ereigniszeit aus Unix-Sekunden im Attribut `key`.
pub fn zeit_unix(f: &RawFinding, key: &str) -> Option<ForensicTime> {
    let s: i64 = f.attributes.get(key)?.parse().ok()?;
    ForensicTime::from_unix(s, TimeSemantics::EventTime)
}

/// Zeit aus `{stamm}_filetime`, bei älteren Reports ohne dieses Feld aus
/// `{stamm}_unix` (nur Sekunden).
pub fn zeit(f: &RawFinding, stamm: &str, semantik: TimeSemantics) -> Option<ForensicTime> {
    if let Some(ft) = zahl(f, &format!("{stamm}_filetime")) {
        return ForensicTime::from_filetime(ft, semantik);
    }
    let s: i64 = f.attributes.get(&format!("{stamm}_unix"))?.parse().ok()?;
    ForensicTime::from_unix(s, semantik)
}

/// Rechner des untersuchten Systems als Entität.
pub fn host(b: &mut Baukasten<'_>) -> Option<EntityId> {
    let name = b.k.host.clone()?;
    let e = Entity::new(
        b.k.case_id,
        EntityKind::Host,
        format!("host:{}", name.to_lowercase()),
        name,
        b.k.zeitpunkt,
    );
    Some(b.entity(e, None))
}

/// Zuordnung Benutzername zu SID aus allen Rohfunden, die beides nennen.
/// Ein Name gilt nur als eindeutig, wenn er genau einer SID zugeordnet ist.
pub struct Personen {
    sid_zu_name: BTreeMap<String, BTreeSet<String>>,
}

impl Personen {
    pub fn aus_funden(funde: &[RawFinding]) -> Self {
        let mut sid_zu_name: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for f in funde.iter().filter(|f| f.domain == "eventlog") {
            for (n, s) in [
                ("benutzer", "benutzer_sid"),
                ("ausfuehrender", "ausfuehrender_sid"),
            ] {
                if let (Some(n), Some(s)) = (text(f, n), text(f, s)) {
                    sid_zu_name
                        .entry(n.to_lowercase())
                        .or_default()
                        .insert(s.to_ascii_uppercase());
                }
            }
        }
        Self { sid_zu_name }
    }

    /// Eindeutige SID zu einem Namen.
    fn sid(&self, name: &str) -> Option<&str> {
        let s = self.sid_zu_name.get(&name.to_lowercase())?;
        (s.len() == 1).then(|| s.iter().next().map(String::as_str))?
    }
}

/// Windows-Benutzer als Entität: SID vor Domäne\Name vor Name. Fehlt die SID,
/// wird sie über den Namen ergänzt, wenn er in diesem Fall eindeutig einer
/// SID zugeordnet ist; das steht dann in den Attributen.
pub fn benutzer(
    b: &mut Baukasten<'_>,
    name: Option<&str>,
    sid: Option<&str>,
    domaene: Option<&str>,
    gesehen: Option<chrono::DateTime<chrono::Utc>>,
) -> Option<EntityId> {
    let ermittelt = match sid {
        Some(_) => None,
        None => name.and_then(|n| b.personen.sid(n)).map(str::to_string),
    };
    let sid_wert = sid.map(str::to_string).or(ermittelt.clone());
    let key = canonical::windows_user(sid_wert.as_deref(), domaene, name)?;
    let anzeige = name.or(sid_wert.as_deref()).unwrap_or_default().to_string();
    let mut e = Entity::new(
        b.k.case_id,
        EntityKind::UserAccount,
        key,
        anzeige,
        b.k.zeitpunkt,
    );
    let mut attr = json!({});
    if let Some(n) = name {
        attr["name"] = json!(n);
    }
    if let Some(s) = &sid_wert {
        attr["sid"] = json!(s);
    }
    if let Some(d) = domaene {
        attr["domaene"] = json!(d);
    }
    if ermittelt.is_some() {
        attr["sid_ueber_namen_ermittelt"] = json!(true);
    }
    e.attributes = attr;
    Some(b.entity(e, gesehen))
}

/// Volume-Kennung und Rest eines Pfads: `C:\x` ergibt `c:` und `\x`,
/// `\Device\HarddiskVolume3\x` ergibt `harddiskvolume3` und `\x`. Welcher
/// Laufwerksbuchstabe zu welchem Gerätepfad gehört, steht nicht sicher im
/// Image; beide bleiben deshalb getrennt.
pub fn pfad_teile(pfad: &str) -> (String, String) {
    let p = pfad.trim().replace('/', "\\");
    let klein = p.to_lowercase();
    if let Some(rest) = klein.strip_prefix("\\device\\") {
        if let Some(i) = rest.find('\\') {
            return (rest[..i].to_string(), rest[i..].to_string());
        }
    }
    let b = klein.as_bytes();
    if b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic() {
        return (klein[..2].to_string(), klein[2..].to_string());
    }
    (String::new(), klein)
}

/// Schlüssel einer Datei ohne MFT-Identität: `pfad:c:\x` bei
/// Laufwerksbuchstaben, `pfad:harddiskvolume3:\x` bei Gerätepfaden.
fn datei_schluessel(volume: &str, rest: &str) -> String {
    if volume.is_empty() || volume.ends_with(':') {
        format!("pfad:{volume}{rest}")
    } else {
        format!("pfad:{volume}:{rest}")
    }
}

/// Datei als Entität über ihren Pfad (ohne MFT-Identität). Der Schlüssel
/// enthält Volume-Kennung und Rest getrennt; gleiche Reste auf verschiedenen
/// Volume-Kennungen verbindet [`crate::normalisieren`] als `POSSIBLY_SAME_AS`.
pub fn datei(
    b: &mut Baukasten<'_>,
    pfad: &str,
    gesehen: Option<chrono::DateTime<chrono::Utc>>,
) -> EntityId {
    let (volume, rest) = pfad_teile(pfad);
    let mut e = Entity::new(
        b.k.case_id,
        EntityKind::File,
        datei_schluessel(&volume, &rest),
        pfad.to_string(),
        b.k.zeitpunkt,
    );
    e.attributes = json!({"volume": volume, "pfad_ohne_volume": rest});
    b.entity(e, gesehen)
}
