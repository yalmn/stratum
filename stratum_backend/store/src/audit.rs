//! Audit-Protokoll: Schreiben in derselben Transaktion wie die Aktion und
//! unabhängiges Nachrechnen der Hash-Kette.
//!
//! Nummer, Vorgänger-Hash und Hash vergibt ein Trigger in der Datenbank
//! (Migration 0004), damit auch gleichzeitige Schreiber eine lückenlose
//! Kette ergeben. Gehasht wird der gespeicherte Text `payload`; so hängt das
//! Nachrechnen nicht davon ab, wie PostgreSQL JSON intern ablegt.

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::postgres::PgConnection;
use sqlx::types::Json;
use sqlx::PgPool;
use stratum_model::{ActorId, AuditAction, AuditEventId, AuditResult, CaseId};

use crate::StoreError;

/// Hash vor dem ersten Ereignis.
pub const KETTENANFANG: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Ein zu protokollierendes Ereignis.
#[derive(Debug, Clone)]
pub struct AuditEintrag {
    /// Handelnder Benutzer oder Dienst.
    pub akteur: ActorId,
    /// Betroffener Fall.
    pub case_id: Option<CaseId>,
    /// Aktion.
    pub aktion: AuditAction,
    /// Art des Objekts (z. B. `evidence`).
    pub objekt_typ: &'static str,
    /// Objekt.
    pub objekt_id: Option<String>,
    /// Ausgang.
    pub ergebnis: AuditResult,
    /// Weitere Angaben.
    pub details: Value,
}

/// Inhalt, der in den Hash eingeht. Die Feldreihenfolge ist fest.
#[derive(Serialize, serde::Deserialize, PartialEq, Debug)]
struct Payload {
    id: AuditEventId,
    actor_id: ActorId,
    case_id: Option<CaseId>,
    timestamp: String,
    action: AuditAction,
    object_type: String,
    object_id: Option<String>,
    result: AuditResult,
    details: Value,
}

/// Zeit auf Mikrosekunden (Genauigkeit von timestamptz), damit Spalte und
/// Payload genau übereinstimmen.
fn zeitstempel(t: DateTime<Utc>) -> (DateTime<Utc>, String) {
    let t = DateTime::from_timestamp_micros(t.timestamp_micros()).unwrap_or(t);
    (t, t.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string())
}

/// Schreibt ein Ereignis über die gegebene Verbindung, also in deren
/// laufender Transaktion. Scheitert die Transaktion, verschwindet auch das
/// Ereignis; Fehlschläge deshalb in eigener Transaktion protokollieren.
pub(crate) async fn schreiben(
    conn: &mut PgConnection,
    e: &AuditEintrag,
) -> Result<AuditEventId, StoreError> {
    let id = AuditEventId::new();
    let (zeit, zeit_text) = zeitstempel(Utc::now());
    let payload = serde_json::to_string(&Payload {
        id,
        actor_id: e.akteur,
        case_id: e.case_id,
        timestamp: zeit_text,
        action: e.aktion,
        object_type: e.objekt_typ.to_string(),
        object_id: e.objekt_id.clone(),
        result: e.ergebnis,
        details: e.details.clone(),
    })?;
    sqlx::query(
        "INSERT INTO audit_event (id, actor_id, case_id, occurred_at, action, object_type, \
         object_id, result, details, payload) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(id.0)
    .bind(e.akteur.0)
    .bind(e.case_id.map(|c| c.0))
    .bind(zeit)
    .bind(text(&e.aktion)?)
    .bind(e.objekt_typ)
    .bind(e.objekt_id.as_deref())
    .bind(text(&e.ergebnis)?)
    .bind(Json(&e.details))
    .bind(&payload)
    .execute(conn)
    .await?;
    Ok(id)
}

/// Name einer Aufzählung, wie serde ihn schreibt.
fn text<T: Serialize>(v: &T) -> Result<String, StoreError> {
    match serde_json::to_value(v)? {
        Value::String(s) => Ok(s),
        _ => Err(StoreError::Wert("Aufzählung ohne Textform")),
    }
}

/// Hash eines Kettenglieds.
pub fn kettenhash(vorher: &str, nummer: u64, payload: &str) -> String {
    let mut h = Sha256::new();
    h.update(vorher.as_bytes());
    h.update(b"\n");
    h.update(nummer.to_string().as_bytes());
    h.update(b"\n");
    h.update(payload.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Ergebnis des Nachrechnens.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct AuditPruefung {
    /// Geprüfte Ereignisse.
    pub ereignisse: u64,
    /// Hash des letzten Ereignisses.
    pub letzter_hash: String,
    /// Gefundene Fehler (höchstens 100 einzeln, danach nur gezählt).
    pub fehler: Vec<String>,
    /// Anzahl aller Fehler.
    pub fehler_gesamt: u64,
}

impl AuditPruefung {
    /// `true`, wenn die Kette vollständig und unverändert ist.
    pub fn intakt(&self) -> bool {
        self.fehler_gesamt == 0
    }

    fn fehler(&mut self, f: String) {
        self.fehler_gesamt += 1;
        if self.fehler.len() < 100 {
            self.fehler.push(f);
        }
    }
}

type Zeile = (
    i64,
    uuid::Uuid,
    uuid::Uuid,
    Option<uuid::Uuid>,
    DateTime<Utc>,
    String,
    String,
    Option<String>,
    String,
    Json<Value>,
    String,
    String,
    String,
);

/// Liest die letzten Ereignisse als Modellobjekte.
pub(crate) async fn liste(
    pool: &PgPool,
    case_id: Option<CaseId>,
    anzahl: i64,
    vor: Option<i64>,
) -> Result<Vec<stratum_model::AuditEvent>, StoreError> {
    let zeilen: Vec<Zeile> = sqlx::query_as(
        "SELECT sequence, id, actor_id, case_id, occurred_at, action, object_type, \
         object_id, result, details, payload, previous_hash, hash FROM audit_event \
         WHERE ($1::uuid IS NULL OR case_id = $1) \
         AND ($3::bigint IS NULL OR sequence < $3) ORDER BY sequence DESC LIMIT $2",
    )
    .bind(case_id.map(|c| c.0))
    .bind(anzahl.clamp(0, 100_000))
    .bind(vor)
    .fetch_all(pool)
    .await?;
    zeilen
        .into_iter()
        .map(|z| {
            Ok(stratum_model::AuditEvent {
                id: AuditEventId(z.1),
                sequence: z.0 as u64,
                actor_id: ActorId(z.2),
                case_id: z.3.map(CaseId),
                timestamp: z.4,
                action: serde_json::from_value(Value::String(z.5))?,
                object_type: z.6,
                object_id: z.7,
                result: serde_json::from_value(Value::String(z.8))?,
                details: z.9 .0,
                previous_hash: Some(z.11),
                hash: z.12,
            })
        })
        .collect()
}

/// Rechnet die ganze Kette nach: lückenlose Nummern, Vorgänger-Hash, Hash
/// über den gespeicherten Inhalt, Spalten gleich Inhalt, Kopf gleich letztem
/// Ereignis. Liest in Blöcken, nie die ganze Tabelle auf einmal.
pub(crate) async fn pruefen(pool: &PgPool) -> Result<AuditPruefung, StoreError> {
    let mut p = AuditPruefung {
        letzter_hash: KETTENANFANG.to_string(),
        ..Default::default()
    };
    let mut nummer: i64 = 0;
    loop {
        let zeilen: Vec<Zeile> = sqlx::query_as(
            "SELECT sequence, id, actor_id, case_id, occurred_at, action, object_type, \
             object_id, result, details, payload, previous_hash, hash FROM audit_event \
             WHERE sequence > $1 ORDER BY sequence LIMIT 10000",
        )
        .bind(nummer)
        .fetch_all(pool)
        .await?;
        if zeilen.is_empty() {
            break;
        }
        for z in zeilen {
            let (seq, id, akteur, fall, zeit, aktion, typ, objekt, ergebnis, details) =
                (z.0, z.1, z.2, z.3, z.4, z.5, z.6, z.7, z.8, z.9 .0);
            let (payload, vorher, hash) = (z.10, z.11, z.12);
            if seq != nummer + 1 {
                p.fehler(format!("Nummer {seq} folgt auf {nummer} (Lücke)"));
            }
            if vorher != p.letzter_hash {
                p.fehler(format!("Nummer {seq}: Vorgänger-Hash passt nicht"));
            }
            let erwartet = kettenhash(&vorher, seq as u64, &payload);
            if erwartet != hash {
                p.fehler(format!("Nummer {seq}: Hash passt nicht zum Inhalt"));
            }
            match serde_json::from_str::<Payload>(&payload) {
                Ok(pl) => {
                    let gleich = pl.id.0 == id
                        && pl.actor_id.0 == akteur
                        && pl.case_id.map(|c| c.0) == fall
                        && pl.timestamp == zeitstempel(zeit).1
                        && text(&pl.action)? == aktion
                        && pl.object_type == typ
                        && pl.object_id == objekt
                        && text(&pl.result)? == ergebnis
                        && pl.details == details;
                    if !gleich {
                        p.fehler(format!("Nummer {seq}: Spalten weichen vom Inhalt ab"));
                    }
                }
                Err(e) => p.fehler(format!("Nummer {seq}: Inhalt nicht lesbar: {e}")),
            }
            nummer = seq;
            p.letzter_hash = hash;
            p.ereignisse += 1;
        }
    }
    let (kopf_nummer, kopf_hash): (i64, String) =
        sqlx::query_as("SELECT sequence, hash FROM audit_head")
            .fetch_one(pool)
            .await?;
    if kopf_nummer != nummer || kopf_hash != p.letzter_hash {
        p.fehler(format!(
            "Kopf der Kette (Nummer {kopf_nummer}) passt nicht zum letzten Ereignis \
             (Nummer {nummer}): Ereignisse fehlen am Ende"
        ));
    }
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kettenhash_wie_sha256_der_verkettung() {
        // sha256("0…0\n1\n{}") unabhängig mit `printf … | shasum -a 256` bestimmt.
        assert_eq!(
            kettenhash(KETTENANFANG, 1, "{}"),
            "857ee6299d26533d1f5f46c02209ae8bc34dc4898a8a9545493946b4ea59d6f3"
        );
    }

    #[test]
    fn zeitstempel_auf_mikrosekunden() {
        let t = DateTime::from_timestamp(1_700_000_000, 123_456_789).unwrap();
        let (k, s) = zeitstempel(t);
        assert_eq!(s, "2023-11-14T22:13:20.123456Z");
        assert_eq!(k.timestamp_subsec_nanos(), 123_456_000);
    }
}
