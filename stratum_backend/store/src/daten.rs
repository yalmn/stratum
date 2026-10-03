//! Ergebnisse lesen: Timeline, Entitäten, eine Entität mit Beziehungen und
//! Ereignissen.
//!
//! Lesen braucht `case.view` und `file.view` („Dateien und Ergebnisse
//! ansehen“) und steht als `DATA_VIEW` im Audit. Geheimwerte an sensiblen
//! Entitäten (Passwörter, Hashes, Schlüssel) sind maskiert; im Klartext nur
//! auf ausdrückliche Anforderung mit `credential.view_sensitive`, und jedes
//! Aufdecken steht als `CREDENTIAL_VIEW` im Audit.

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::types::Json;
use stratum_model::{
    ActorId, AnalysisRunId, ArtifactId, AuditAction, AuditResult, CaseId, EntityId, EventId,
    EvidenceId, Permission,
};

use crate::audit::AuditEintrag;
use crate::{Datenbank, StoreError};

/// Ersatz für einen maskierten Geheimwert.
pub const MASKIERT: &str = "[maskiert]";

/// Ersetzt in einem Objekt mit `sensibel: true` die Geheimwerte durch
/// [`MASKIERT`]. Liefert, ob etwas maskiert wurde.
pub fn maskieren(v: &mut Value) -> bool {
    if v.get("sensibel") != Some(&Value::Bool(true)) {
        return false;
    }
    let mut etwas = false;
    if let Value::Object(o) = v {
        for k in stratum_normalize::GEHEIME_FELDER {
            if let Some(w) = o.get_mut(*k) {
                if !w.is_null() {
                    *w = json!(MASKIERT);
                    etwas = true;
                }
            }
        }
    }
    etwas
}

/// Ersetzt in einem Rohfund (wie im Report) die Geheimwerte, wenn er zu
/// den Zugangsdaten gehört. Liefert, ob etwas maskiert wurde.
pub fn rohfund_maskieren(f: &mut Value) -> bool {
    let domain = f.get("domain").and_then(Value::as_str).unwrap_or_default();
    let art = f.pointer("/attributes/art").and_then(Value::as_str);
    if !stratum_normalize::rohfund_sensibel(domain, art) {
        return false;
    }
    let mut etwas = false;
    if let Some(Value::Object(o)) = f.get_mut("attributes") {
        for k in stratum_normalize::GEHEIME_FELDER {
            if let Some(w) = o.get_mut(*k) {
                *w = json!(MASKIERT);
                etwas = true;
            }
        }
    }
    etwas
}

/// Wo der Rohfund zu einem Artefakt steht, nach geprüften Rechten.
#[derive(Debug, Clone)]
pub struct RohfundQuelle {
    /// Fall des Artefakts.
    pub fall: CaseId,
    /// Das Artefakt.
    pub artefakt: ArtifactId,
    /// Kennung des Rohfunds im Report.
    pub rohfund_id: Option<String>,
    /// Fund vollständig im Artefakt (ohne Report erzeugt).
    pub eingebettet: Option<Value>,
    /// Abgeschlossene Läufe der Evidence mit Report, neueste zuerst:
    /// Lauf, Pfad, SHA-256.
    pub berichte: Vec<(AnalysisRunId, String, String)>,
    /// Klartext angefordert (und erlaubt).
    pub klartext: bool,
    audit: AuditEintrag,
}

/// Ereignis: id, kind, occurred_utc, occurred_at, ended_at, attributes,
/// derivation, participants.
type EreignisZeile = (
    uuid::Uuid,
    String,
    DateTime<Utc>,
    Option<Json<Value>>,
    Option<Json<Value>>,
    Json<Value>,
    String,
    Json<Value>,
);

/// Entität in Listen: id, kind, canonical_key, display_name, attributes,
/// first_seen, last_seen, Anzahl Ereignisse, Anzahl Beziehungen.
type EntitaetZeile = (
    uuid::Uuid,
    String,
    String,
    String,
    Json<Value>,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
    i64,
    i64,
);

/// Entität: case_id, kind, canonical_key, display_name, attributes,
/// first_seen, last_seen.
type EntitaetDetail = (
    uuid::Uuid,
    String,
    String,
    String,
    Json<Value>,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
);

/// Auswahl für die Timeline.
#[derive(Debug, Clone, Default)]
pub struct Zeitfenster {
    /// Ab diesem Zeitpunkt (einschließlich).
    pub von: Option<DateTime<Utc>>,
    /// Bis vor diesen Zeitpunkt.
    pub bis: Option<DateTime<Utc>>,
    /// Nur diese Ereignisarten (leer: alle).
    pub arten: Vec<String>,
    /// Nur Ereignisse mit dieser beteiligten Entität.
    pub entitaet: Option<EntityId>,
    /// Nur Ereignisse aus dieser Evidence (über die Herkunftsangaben).
    pub evidence: Option<EvidenceId>,
    /// Text in Art oder Attributen (ohne Groß- und Kleinschreibung).
    pub suche: Option<String>,
    /// Weiter nach diesem Eintrag (aus `naechste` der vorigen Seite).
    pub nach: Option<String>,
    /// Höchstens so viele Einträge (1 bis 1000).
    pub anzahl: i64,
}

/// Eine Seite der Timeline.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Seite {
    /// Einträge.
    pub eintraege: Vec<Value>,
    /// Marke für die nächste Seite, falls es weitere gibt.
    pub naechste: Option<String>,
}

/// Suchtext als Literal für ILIKE, nicht als Muster: `%` und `_` maskieren.
fn muster(s: &str) -> String {
    format!(
        "%{}%",
        s.replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_")
    )
}

/// Marke `zeit|id` in ihre Teile.
fn marke_lesen(m: &str) -> Result<(DateTime<Utc>, uuid::Uuid), StoreError> {
    let (t, id) = m
        .split_once('|')
        .ok_or_else(|| StoreError::Eingabe("Seitenmarke ungültig".into()))?;
    let t = DateTime::parse_from_rfc3339(t)
        .map_err(|_| StoreError::Eingabe("Seitenmarke ungültig".into()))?
        .with_timezone(&Utc);
    let id = id
        .parse()
        .map_err(|_| StoreError::Eingabe("Seitenmarke ungültig".into()))?;
    Ok((t, id))
}

impl Datenbank {
    async fn lesen_erlaubt(
        &self,
        akteur: ActorId,
        fall: Option<CaseId>,
        details: Value,
    ) -> Result<AuditEintrag, StoreError> {
        let e = AuditEintrag {
            akteur,
            case_id: fall,
            aktion: AuditAction::DataView,
            objekt_typ: "daten",
            objekt_id: None,
            ergebnis: AuditResult::Success,
            details,
        };
        self.verlangen(akteur, Permission::CaseView, e.clone())
            .await?;
        self.verlangen(akteur, Permission::FileView, e.clone())
            .await?;
        Ok(e)
    }

    /// Timeline eines Falls nach Zeit und ID, seitenweise. Ereignisse ohne
    /// Zeitpunkt erscheinen hier nicht.
    pub async fn zeitachse(
        &self,
        akteur: ActorId,
        fall: CaseId,
        f: &Zeitfenster,
    ) -> Result<Seite, StoreError> {
        let e = self
            .lesen_erlaubt(
                akteur,
                Some(fall),
                json!({"art": "zeitachse", "von": f.von, "bis": f.bis, "arten": f.arten,
                       "entitaet": f.entitaet}),
            )
            .await?;
        let anzahl = f.anzahl.clamp(1, 1000);
        let nach = f.nach.as_deref().map(marke_lesen).transpose()?;
        let zeilen: Vec<EreignisZeile> = sqlx::query_as(
            "SELECT e.id, e.kind, e.occurred_utc, e.occurred_at, e.ended_at, e.attributes, \
                 e.derivation, COALESCE((SELECT jsonb_agg(jsonb_build_object( \
                   'entity_id', p.entity_id, 'role', p.role, 'kind', n.kind, \
                   'name', n.display_name) ORDER BY p.role, n.display_name) \
                   FROM event_participant p JOIN entity n ON n.id = p.entity_id \
                   WHERE p.event_id = e.id), '[]') \
                 FROM event e \
                 WHERE e.case_id = $1 AND e.occurred_utc IS NOT NULL \
                 AND ($2::timestamptz IS NULL OR e.occurred_utc >= $2) \
                 AND ($3::timestamptz IS NULL OR e.occurred_utc < $3) \
                 AND (cardinality($4::text[]) = 0 OR e.kind = ANY($4)) \
                 AND ($5::uuid IS NULL OR EXISTS (SELECT 1 FROM event_participant p \
                   WHERE p.event_id = e.id AND p.entity_id = $5)) \
                 AND ($6::timestamptz IS NULL OR (e.occurred_utc, e.id) > ($6, $7)) \
                 AND ($9::uuid IS NULL OR EXISTS (SELECT 1 FROM provenance v \
                   WHERE v.evidence_id = $9 AND v.object_type = 'event' AND v.object_id = e.id)) \
                 AND ($10::text IS NULL OR e.kind ILIKE $10 OR e.attributes::text ILIKE $10) \
                 ORDER BY e.occurred_utc, e.id LIMIT $8",
        )
        .bind(fall.0)
        .bind(f.von)
        .bind(f.bis)
        .bind(&f.arten)
        .bind(f.entitaet.map(|x| x.0))
        .bind(nach.map(|n| n.0))
        .bind(nach.map(|n| n.1))
        .bind(anzahl + 1)
        .bind(f.evidence.map(|x| x.0))
        .bind(f.suche.as_deref().map(muster))
        .fetch_all(&self.pool)
        .await?;
        let mehr = zeilen.len() as i64 > anzahl;
        let mut eintraege = Vec::with_capacity(zeilen.len());
        let mut naechste = None;
        for (i, z) in zeilen.into_iter().enumerate() {
            if i as i64 == anzahl {
                break;
            }
            if mehr && i as i64 == anzahl - 1 {
                naechste = Some(format!(
                    "{}|{}",
                    z.2.to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
                    z.0
                ));
            }
            let mut attribute = z.5 .0;
            maskieren(&mut attribute);
            eintraege.push(json!({
                "id": z.0, "kind": z.1, "occurred_utc": z.2,
                "occurred_at": z.3.map(|j| j.0), "ended_at": z.4.map(|j| j.0),
                "attributes": attribute, "derivation": z.6, "participants": z.7 .0,
            }));
        }
        self.audit(&AuditEintrag {
            details: json!({"art": "zeitachse", "anzahl": eintraege.len(),
                            "arten": f.arten, "von": f.von, "bis": f.bis}),
            ..e
        })
        .await?;
        Ok(Seite {
            eintraege,
            naechste,
        })
    }

    /// Ereignisarten eines Falls mit Anzahl (für Filter).
    pub async fn zeitachse_arten(
        &self,
        akteur: ActorId,
        fall: CaseId,
    ) -> Result<Vec<(String, i64)>, StoreError> {
        let e = self
            .lesen_erlaubt(akteur, Some(fall), json!({"art": "zeitachse_arten"}))
            .await?;
        let arten: Vec<(String, i64)> = sqlx::query_as(
            "SELECT kind, count(*) FROM event WHERE case_id = $1 GROUP BY kind ORDER BY kind",
        )
        .bind(fall.0)
        .fetch_all(&self.pool)
        .await?;
        self.audit(&e).await?;
        Ok(arten)
    }

    /// Entitäten eines Falls nach Anzeigename, wahlweise einer Art und mit
    /// Suchtext (in Anzeigename und kanonischem Schlüssel), seitenweise.
    pub async fn entitaeten(
        &self,
        akteur: ActorId,
        fall: CaseId,
        art: Option<&str>,
        suche: Option<&str>,
        nach: Option<&str>,
        anzahl: i64,
    ) -> Result<Seite, StoreError> {
        let e = self
            .lesen_erlaubt(
                akteur,
                Some(fall),
                json!({"art": "entitaeten", "entitaetsart": art, "suche": suche}),
            )
            .await?;
        let anzahl = anzahl.clamp(1, 1000);
        // Marke: Anzeigename und ID des letzten Eintrags.
        let nach = match nach {
            Some(m) => {
                let (n, id) = m
                    .rsplit_once('|')
                    .ok_or_else(|| StoreError::Eingabe("Seitenmarke ungültig".into()))?;
                let id: uuid::Uuid = id
                    .parse()
                    .map_err(|_| StoreError::Eingabe("Seitenmarke ungültig".into()))?;
                Some((n.to_string(), id))
            }
            None => None,
        };
        let muster = suche.map(muster);
        let zeilen: Vec<EntitaetZeile> = sqlx::query_as(
            "SELECT n.id, n.kind, n.canonical_key, n.display_name, n.attributes, \
                 n.first_seen, n.last_seen, \
                 (SELECT count(*) FROM event_participant p WHERE p.entity_id = n.id), \
                 (SELECT count(*) FROM relationship r \
                   WHERE r.source_entity_id = n.id OR r.target_entity_id = n.id) \
                 FROM entity n WHERE n.case_id = $1 \
                 AND ($2::text IS NULL OR n.kind = $2) \
                 AND ($3::text IS NULL OR n.display_name ILIKE $3 OR n.canonical_key ILIKE $3) \
                 AND ($4::text IS NULL OR (n.display_name, n.id) > ($4, $5)) \
                 ORDER BY n.display_name, n.id LIMIT $6",
        )
        .bind(fall.0)
        .bind(art)
        .bind(muster)
        .bind(nach.as_ref().map(|n| n.0.clone()))
        .bind(nach.as_ref().map(|n| n.1))
        .bind(anzahl + 1)
        .fetch_all(&self.pool)
        .await?;
        let mehr = zeilen.len() as i64 > anzahl;
        let mut eintraege = Vec::new();
        let mut naechste = None;
        for (i, z) in zeilen.into_iter().enumerate() {
            if i as i64 == anzahl {
                break;
            }
            if mehr && i as i64 == anzahl - 1 {
                naechste = Some(format!("{}|{}", z.3, z.0));
            }
            let mut attribute = z.4 .0;
            maskieren(&mut attribute);
            eintraege.push(json!({
                "id": z.0, "kind": z.1, "canonical_key": z.2, "display_name": z.3,
                "attributes": attribute, "first_seen": z.5, "last_seen": z.6,
                "ereignisse": z.7, "beziehungen": z.8,
            }));
        }
        self.audit(&AuditEintrag {
            details: json!({"art": "entitaeten", "anzahl": eintraege.len(), "suche": suche}),
            ..e
        })
        .await?;
        Ok(Seite {
            eintraege,
            naechste,
        })
    }

    /// Eine Entität mit ihren Beziehungen (beide Richtungen) und den
    /// letzten Ereignissen, an denen sie beteiligt ist. Mit `klartext`
    /// werden Geheimwerte gezeigt, wenn das Konto es darf.
    pub async fn entitaet(
        &self,
        akteur: ActorId,
        id: EntityId,
        klartext: bool,
    ) -> Result<Value, StoreError> {
        let zeile: Option<EntitaetDetail> = sqlx::query_as(
            "SELECT case_id, kind, canonical_key, display_name, attributes, first_seen, \
                 last_seen FROM entity WHERE id = $1",
        )
        .bind(id.0)
        .fetch_optional(&self.pool)
        .await?;
        let Some((fall, kind, schluessel, name, attribute, erst, zuletzt)) = zeile else {
            return Err(StoreError::NichtGefunden(format!("keine Entität {id}")));
        };
        let fall = CaseId(fall);
        let e = self
            .lesen_erlaubt(
                akteur,
                Some(fall),
                json!({"art": "entitaet", "entitaet": id}),
            )
            .await?;
        let mut attribute = attribute.0;
        let sensibel = attribute.get("sensibel") == Some(&Value::Bool(true));
        if klartext && sensibel {
            let cv = AuditEintrag {
                akteur,
                case_id: Some(fall),
                aktion: AuditAction::CredentialView,
                objekt_typ: "entity",
                objekt_id: Some(id.to_string()),
                ergebnis: AuditResult::Success,
                details: json!({"name": name}),
            };
            self.verlangen(akteur, Permission::CredentialViewSensitive, cv.clone())
                .await?;
            self.audit(&cv).await?;
        } else {
            maskieren(&mut attribute);
        }
        let beziehungen: Vec<Json<Value>> = sqlx::query_scalar(
            "SELECT jsonb_build_object('id', r.id, 'kind', r.kind, 'derivation', r.derivation, \
             'richtung', CASE WHEN r.source_entity_id = $1 THEN 'aus' ELSE 'ein' END, \
             'gegenueber', jsonb_build_object('id', o.id, 'kind', o.kind, 'name', o.display_name), \
             'valid_from', r.valid_from, 'valid_until', r.valid_until, 'attributes', r.attributes) \
             FROM relationship r JOIN entity o ON o.id = \
               CASE WHEN r.source_entity_id = $1 THEN r.target_entity_id ELSE r.source_entity_id END \
             WHERE r.source_entity_id = $1 OR r.target_entity_id = $1 \
             ORDER BY r.kind, o.display_name LIMIT 1000",
        )
        .bind(id.0)
        .fetch_all(&self.pool)
        .await?;
        let ereignisse: Vec<Json<Value>> = sqlx::query_scalar(
            "SELECT jsonb_build_object('id', e.id, 'kind', e.kind, 'occurred_utc', e.occurred_utc, \
             'role', p.role, 'derivation', e.derivation) \
             FROM event_participant p JOIN event e ON e.id = p.event_id \
             WHERE p.entity_id = $1 ORDER BY e.occurred_utc DESC NULLS LAST, e.id LIMIT 200",
        )
        .bind(id.0)
        .fetch_all(&self.pool)
        .await?;
        self.audit(&e).await?;
        Ok(json!({
            "entitaet": {
                "id": id, "case_id": fall, "kind": kind, "canonical_key": schluessel,
                "display_name": name, "attributes": attribute, "first_seen": erst,
                "last_seen": zuletzt, "klartext": klartext && sensibel,
            },
            "beziehungen": beziehungen.into_iter().map(|j| j.0).collect::<Vec<_>>(),
            "ereignisse": ereignisse.into_iter().map(|j| j.0).collect::<Vec<_>>(),
        }))
    }
}

impl Datenbank {
    /// Ein Ereignis mit Beteiligten und Herkunft: Evidence, Artefakt mit
    /// Fundstelle und Parser, Analyselauf und Kennung des Rohfunds.
    pub async fn ereignis(&self, akteur: ActorId, id: EventId) -> Result<Value, StoreError> {
        let zeile: Option<(uuid::Uuid, Json<Value>)> = sqlx::query_as(
            "SELECT e.case_id, jsonb_build_object('id', e.id, 'kind', e.kind, \
               'occurred_utc', e.occurred_utc, 'occurred_at', e.occurred_at, \
               'ended_at', e.ended_at, 'attributes', e.attributes, 'derivation', e.derivation, \
               'participants', COALESCE((SELECT jsonb_agg(jsonb_build_object( \
                 'entity_id', p.entity_id, 'role', p.role, 'kind', n.kind, \
                 'name', n.display_name) ORDER BY p.role, n.display_name) \
                 FROM event_participant p JOIN entity n ON n.id = p.entity_id \
                 WHERE p.event_id = e.id), '[]')) \
             FROM event e WHERE e.id = $1",
        )
        .bind(id.0)
        .fetch_optional(&self.pool)
        .await?;
        let Some((fall, ereignis)) = zeile else {
            return Err(StoreError::NichtGefunden(format!("kein Ereignis {id}")));
        };
        let e = self
            .lesen_erlaubt(
                akteur,
                Some(CaseId(fall)),
                json!({"art": "ereignis", "ereignis": id}),
            )
            .await?;
        let herkunft: Vec<Json<Value>> = sqlx::query_scalar(
            "SELECT jsonb_build_object('role', p.role, 'evidence_id', p.evidence_id, \
               'evidence_name', v.name, 'artifact_id', p.artifact_id, 'artifact_kind', a.kind, \
               'source_locator', COALESCE(p.source_locator, a.source_locator), \
               'parser', COALESCE(p.parser, a.parser), 'analysis_run_id', p.analysis_run_id, \
               'rohfund_id', a.raw_metadata->>'rohfund_id') \
             FROM provenance p LEFT JOIN artifact a ON a.id = p.artifact_id \
             LEFT JOIN evidence v ON v.id = p.evidence_id \
             WHERE p.object_type = 'event' AND p.object_id = $1 \
             ORDER BY p.role LIMIT 50",
        )
        .bind(id.0)
        .fetch_all(&self.pool)
        .await?;
        let mut ereignis = ereignis.0;
        if let Some(a) = ereignis.get_mut("attributes") {
            maskieren(a);
        }
        self.audit(&e).await?;
        Ok(json!({
            "ereignis": ereignis,
            "herkunft": herkunft.into_iter().map(|j| j.0).collect::<Vec<_>>(),
        }))
    }
}

impl Datenbank {
    /// Fundstelle des Rohfunds zu einem Artefakt. Prüft `case.view` und
    /// `file.view`, mit `klartext` zusätzlich `credential.view_sensitive`
    /// (abgelehnt als `CREDENTIAL_VIEW` im Audit). Den Erfolg trägt danach
    /// [`rohfund_protokollieren`](Self::rohfund_protokollieren) ein.
    pub async fn rohfund_quelle(
        &self,
        akteur: ActorId,
        artefakt: ArtifactId,
        klartext: bool,
    ) -> Result<RohfundQuelle, StoreError> {
        let zeile: Option<(uuid::Uuid, uuid::Uuid, Json<Value>)> =
            sqlx::query_as("SELECT case_id, evidence_id, raw_metadata FROM artifact WHERE id = $1")
                .bind(artefakt.0)
                .fetch_optional(&self.pool)
                .await?;
        let Some((fall, evidence, roh)) = zeile else {
            return Err(StoreError::NichtGefunden(format!(
                "kein Artefakt {artefakt}"
            )));
        };
        let fall = CaseId(fall);
        let mut audit = self
            .lesen_erlaubt(
                akteur,
                Some(fall),
                json!({"art": "rohfund", "artefakt": artefakt}),
            )
            .await?;
        audit.objekt_typ = "artifact";
        audit.objekt_id = Some(artefakt.to_string());
        if klartext {
            self.verlangen(
                akteur,
                Permission::CredentialViewSensitive,
                AuditEintrag {
                    aktion: AuditAction::CredentialView,
                    ..audit.clone()
                },
            )
            .await?;
        }
        let rohfund_id = roh
            .0
            .get("rohfund_id")
            .and_then(Value::as_str)
            .map(String::from);
        let berichte: Vec<(uuid::Uuid, String, String)> = if rohfund_id.is_some() {
            sqlx::query_as(
                "SELECT id, report_path, report_sha256 FROM analysis_run \
                 WHERE evidence_id = $1 AND status = 'completed' \
                   AND report_path IS NOT NULL AND report_sha256 IS NOT NULL \
                 ORDER BY finished_at DESC LIMIT 10",
            )
            .bind(evidence)
            .fetch_all(&self.pool)
            .await?
        } else {
            Vec::new()
        };
        Ok(RohfundQuelle {
            fall,
            artefakt,
            eingebettet: rohfund_id.is_none().then_some(roh.0),
            rohfund_id,
            berichte: berichte
                .into_iter()
                .map(|(l, p, h)| (AnalysisRunId(l), p, h))
                .collect(),
            klartext,
            audit,
        })
    }

    /// Trägt den Abruf eines Rohfunds ins Audit ein: `DATA_VIEW` mit Erfolg
    /// oder Fehlschlag, bei Klartext zusätzlich `CREDENTIAL_VIEW`.
    pub async fn rohfund_protokollieren(
        &self,
        q: &RohfundQuelle,
        erfolg: bool,
        details: Value,
    ) -> Result<(), StoreError> {
        let mut d = q.audit.details.clone();
        if let (Value::Object(d), Value::Object(n)) = (&mut d, details) {
            d.extend(n);
        }
        let e = AuditEintrag {
            ergebnis: if erfolg {
                AuditResult::Success
            } else {
                AuditResult::Failure
            },
            details: d,
            ..q.audit.clone()
        };
        self.audit(&e).await?;
        if erfolg && q.klartext {
            self.audit(&AuditEintrag {
                aktion: AuditAction::CredentialView,
                ..e
            })
            .await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rohfund_nur_bei_zugangsdaten_maskiert() {
        let mut lsa = json!({"domain": "lsa", "attributes": {"art": "lsa_secret", "wert": "x"}});
        assert!(rohfund_maskieren(&mut lsa));
        assert_eq!(lsa["attributes"]["wert"], MASKIERT);
        let mut browser = json!({"domain": "browser",
            "attributes": {"art": "passwort_klartext", "passwort": "x", "url": "u"}});
        assert!(rohfund_maskieren(&mut browser));
        assert_eq!(browser["attributes"]["url"], "u");
        // Registry-Werte heißen auch „wert“, sind aber keine Geheimnisse.
        let mut reg = json!({"domain": "persistence", "attributes": {"wert": "Updater"}});
        assert!(!rohfund_maskieren(&mut reg));
        assert_eq!(reg["attributes"]["wert"], "Updater");
        let mut verlauf = json!({"domain": "browser", "attributes": {"art": "verlauf"}});
        assert!(!rohfund_maskieren(&mut verlauf));
    }

    #[test]
    fn nur_sensible_objekte_werden_maskiert() {
        let mut a = json!({"sensibel": true, "passwort": "geheim", "url": "https://x"});
        assert!(maskieren(&mut a));
        assert_eq!(a["passwort"], MASKIERT);
        assert_eq!(a["url"], "https://x");
        // Ohne Kennzeichen bleibt alles, auch Felder gleichen Namens.
        let mut b = json!({"wert": "C:\\\\run.exe"});
        assert!(!maskieren(&mut b));
        assert_eq!(b["wert"], "C:\\\\run.exe");
    }

    #[test]
    fn seitenmarke() {
        let (t, id) =
            marke_lesen("2026-04-18T09:44:44.668011Z|01a0fdd9-8410-7011-a689-f51d5bd3b3a5")
                .unwrap();
        assert_eq!(t.timestamp_subsec_micros(), 668_011);
        assert_eq!(id.to_string(), "01a0fdd9-8410-7011-a689-f51d5bd3b3a5");
        assert!(marke_lesen("kaputt").is_err());
    }
}
