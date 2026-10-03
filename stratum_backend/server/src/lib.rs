//! HTTP-API von stratum unter `/api/v1`.
//!
//! Jede Anfrage außer der Anmeldung braucht eine Sitzung: das Token aus
//! `POST /api/v1/sitzung` im Header `Authorization: Bearer …` oder im
//! Cookie `stratum_sitzung`. Rechte prüft der Store, der auch jede fachliche
//! Aktion und jeden Lesezugriff ins Audit schreibt; der Server reicht nur
//! weiter. Antworten sind JSON, Fehler `{"fehler": "…"}`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::convert::Infallible;
use std::time::Duration;

use axum::extract::{FromRequest, FromRequestParts, Path, Query, Request, State};
use axum::http::request::Parts;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::stream::{self, Stream};
use serde::Deserialize;
use serde_json::{json, Value};
use stratum_model::{
    Case, CaseClassification, CaseId, CaseStatus, JobId, JobStatus, Permission, User,
};
use stratum_store::{Datenbank, StoreError};

/// Name des Sitzungs-Cookies.
pub const COOKIE: &str = "stratum_sitzung";

/// Gemeinsamer Zustand aller Anfragen.
#[derive(Clone)]
pub struct Zustand {
    db: Datenbank,
}

/// Fehler einer Anfrage.
#[derive(Debug, thiserror::Error)]
pub enum ApiFehler {
    /// Nicht angemeldet oder Sitzung abgelaufen.
    #[error("nicht angemeldet")]
    NichtAngemeldet,
    /// Aus dem Store.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// Anfrage ungültig.
    #[error("{0}")]
    Anfrage(String),
    /// Angefragtes ist nicht (mehr) lesbar, etwa ein Report ohne Datei.
    #[error("{0}")]
    NichtVerfuegbar(String),
    /// Gespeichertes passt nicht mehr zu seinem Hash.
    #[error("{0}")]
    Integritaet(String),
}

impl IntoResponse for ApiFehler {
    fn into_response(self) -> Response {
        let status = match &self {
            ApiFehler::NichtAngemeldet => StatusCode::UNAUTHORIZED,
            ApiFehler::Anfrage(_) => StatusCode::BAD_REQUEST,
            ApiFehler::NichtVerfuegbar(_) => StatusCode::NOT_FOUND,
            ApiFehler::Integritaet(_) => StatusCode::CONFLICT,
            ApiFehler::Store(s) => match s {
                StoreError::Verweigert(_) => StatusCode::FORBIDDEN,
                StoreError::NichtGefunden(_) => StatusCode::NOT_FOUND,
                StoreError::Eingabe(_) | StoreError::Passwort(_) => StatusCode::BAD_REQUEST,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            },
        };
        // Innere Fehler nicht im Detail nach außen geben.
        let text = if status == StatusCode::INTERNAL_SERVER_ERROR {
            "interner Fehler".to_string()
        } else {
            self.to_string()
        };
        (status, Json(json!({ "fehler": text }))).into_response()
    }
}

type Antwort<T> = Result<T, ApiFehler>;

/// Token aus `Authorization: Bearer …` oder dem Cookie.
fn token(h: &HeaderMap) -> Option<String> {
    if let Some(t) = h
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        return Some(t.trim().to_string());
    }
    h.get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|c| {
            let (n, w) = c.trim().split_once('=')?;
            (n == COOKIE).then(|| w.to_string())
        })
}

/// JSON-Körper einer Anfrage; ungültiges JSON wird ein Fehler im
/// gewohnten Format statt der Textmeldung von Axum.
pub struct Koerper<T>(pub T);

impl<T: serde::de::DeserializeOwned, S: Send + Sync> FromRequest<S> for Koerper<T> {
    type Rejection = ApiFehler;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(t)) => Ok(Koerper(t)),
            Err(e) => Err(ApiFehler::Anfrage(format!(
                "Anfrage ungültig: {}",
                e.body_text()
            ))),
        }
    }
}

/// Name und Passwort aus `Authorization: Basic …` (RFC 7617).
fn basic(h: &HeaderMap) -> Option<(String, String)> {
    use base64ct::Encoding;
    let wert = h
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Basic ")?;
    let roh = base64ct::Base64::decode_vec(wert.trim()).ok()?;
    let text = String::from_utf8(roh).ok()?;
    let (n, p) = text.split_once(':')?;
    Some((n.to_string(), p.to_string()))
}

/// Angemeldetes Konto einer Anfrage.
pub struct Angemeldet(pub User);

impl FromRequestParts<Zustand> for Angemeldet {
    type Rejection = ApiFehler;

    async fn from_request_parts(parts: &mut Parts, z: &Zustand) -> Result<Self, Self::Rejection> {
        let t = token(&parts.headers).ok_or(ApiFehler::NichtAngemeldet)?;
        z.db.sitzung_pruefen(&t)
            .await?
            .map(Angemeldet)
            .ok_or(ApiFehler::NichtAngemeldet)
    }
}

/// Router mit allen Endpunkten.
pub fn router(db: Datenbank) -> Router {
    Router::new()
        .route("/api/v1/sitzung", post(anmelden).delete(abmelden))
        .route("/api/v1/ich", get(ich))
        .route("/api/v1/rechte", get(rechte))
        .route("/api/v1/faelle", get(faelle).post(fall_neu))
        .route("/api/v1/faelle/{nummer}", get(fall_zeigen))
        .route("/api/v1/faelle/{nummer}/analysen", post(analyse))
        .route("/api/v1/jobs", get(jobs))
        .route("/api/v1/jobs/{id}", get(job).delete(job_abbrechen))
        .route("/api/v1/jobs/{id}/fortschritt", get(job_fortschritt))
        .route(
            "/api/v1/faelle/{nummer}/evidence",
            post(evidence_importieren),
        )
        .route("/api/v1/faelle/{nummer}/zeitachse", get(zeitachse))
        .route(
            "/api/v1/faelle/{nummer}/zeitachse/arten",
            get(zeitachse_arten),
        )
        .route("/api/v1/faelle/{nummer}/entitaeten", get(entitaeten))
        .route("/api/v1/entitaeten/{id}", get(entitaet))
        .route("/api/v1/evidence/{id}/volumes", get(volumes))
        .route("/api/v1/evidence/{id}/dateien", get(dateien))
        .route("/api/v1/artefakte/{id}/rohfund", get(rohfund))
        .route("/api/v1/audit", get(audit))
        .route("/api/v1/audit/pruefen", post(audit_pruefen))
        .with_state(Zustand { db })
}

/// Startet den Server und läuft, bis `stopp` endet.
pub async fn starten(
    db: Datenbank,
    adresse: std::net::SocketAddr,
    stopp: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(adresse).await?;
    axum::serve(listener, router(db))
        .with_graceful_shutdown(stopp)
        .await
}

#[derive(Deserialize)]
struct Anmeldung {
    name: String,
    passwort: String,
}

/// Anmeldung: JSON `{"name", "passwort"}` oder HTTP-Basic (damit etwa
/// `curl -u NAME` das Passwort verdeckt abfragt).
async fn anmelden(
    State(z): State<Zustand>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Antwort<Response> {
    let a = match basic(&headers) {
        Some((name, passwort)) if body.is_empty() => Anmeldung { name, passwort },
        _ => serde_json::from_slice::<Anmeldung>(&body).map_err(|e| {
            ApiFehler::Anfrage(format!(
                "Anmeldung als JSON {{\"name\", \"passwort\"}} oder per HTTP-Basic: {e}"
            ))
        })?,
    };
    let client = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.chars().take(200).collect::<String>());
    let (token, konto) =
        z.db.sitzung_anlegen(&a.name, &a.passwort, client.as_deref())
            .await
            .map_err(|e| match e {
                StoreError::Verweigert(_) => ApiFehler::NichtAngemeldet,
                e => e.into(),
            })?;
    let rechte = z.db.rechte(konto.id).await?;
    let cookie = format!(
        "{COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/api; Max-Age={}",
        stratum_store::sitzung::SITZUNG_STUNDEN * 3600
    );
    let mut r = Json(json!({ "token": token, "konto": konto, "rechte": rechte })).into_response();
    if let Ok(v) = HeaderValue::from_str(&cookie) {
        r.headers_mut().insert(header::SET_COOKIE, v);
    }
    Ok(r)
}

async fn abmelden(State(z): State<Zustand>, headers: HeaderMap) -> Antwort<Response> {
    if let Some(t) = token(&headers) {
        z.db.sitzung_beenden(&t).await?;
    }
    let mut r = StatusCode::NO_CONTENT.into_response();
    r.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static(
            "stratum_sitzung=; HttpOnly; SameSite=Strict; Path=/api; Max-Age=0",
        ),
    );
    Ok(r)
}

async fn ich(State(z): State<Zustand>, Angemeldet(u): Angemeldet) -> Antwort<Json<Value>> {
    let rechte = z.db.rechte(u.id).await?;
    Ok(Json(json!({ "konto": u, "rechte": rechte })))
}

async fn rechte(_: Angemeldet) -> Json<Value> {
    Json(Value::Array(
        Permission::ALL
            .iter()
            .map(|p| json!({ "name": p.name(), "beschreibung": p.description() }))
            .collect(),
    ))
}

async fn fall_id(z: &Zustand, nummer: &str) -> Antwort<CaseId> {
    z.db.fall_id(nummer)
        .await?
        .ok_or_else(|| StoreError::NichtGefunden(format!("kein Fall {nummer}")).into())
}

async fn faelle(State(z): State<Zustand>, Angemeldet(u): Angemeldet) -> Antwort<Json<Value>> {
    Ok(Json(
        serde_json::to_value(z.db.faelle(u.id).await?).map_err(StoreError::from)?,
    ))
}

#[derive(Deserialize)]
struct NeuerFall {
    nummer: String,
    titel: String,
    ordner: Option<String>,
    beschreibung: Option<String>,
    einstufung: Option<CaseClassification>,
    zeitzone: Option<String>,
}

async fn fall_neu(
    State(z): State<Zustand>,
    Angemeldet(u): Angemeldet,
    Koerper(n): Koerper<NeuerFall>,
) -> Antwort<(StatusCode, Json<Case>)> {
    if z.db.fall_id(&n.nummer).await?.is_some() {
        return Err(ApiFehler::Anfrage(format!(
            "Fallnummer {} ist schon vergeben",
            n.nummer
        )));
    }
    let jetzt = chrono::Utc::now();
    let c = Case {
        id: CaseId::new(),
        case_number: n.nummer,
        title: n.titel,
        description: n.beschreibung,
        status: CaseStatus::Active,
        classification: n.einstufung.unwrap_or(CaseClassification::Internal),
        created_at: jetzt,
        created_by: u.id,
        opened_at: Some(jetzt),
        closed_at: None,
        timezone: n.zeitzone,
        case_folder: n.ordner,
        tags: Vec::new(),
    };
    z.db.fall_anlegen(u.id, &c).await?;
    Ok((StatusCode::CREATED, Json(c)))
}

async fn fall_zeigen(
    State(z): State<Zustand>,
    Angemeldet(u): Angemeldet,
    Path(nummer): Path<String>,
) -> Antwort<Json<Value>> {
    let id = fall_id(&z, &nummer).await?;
    let (fall, evidence) = z.db.fall_oeffnen(u.id, id).await?;
    Ok(Json(json!({ "fall": fall, "evidence": evidence })))
}

#[derive(Deserialize)]
struct NeueAnalyse {
    /// Name oder ID der Evidence im Fall.
    evidence: String,
    #[serde(default)]
    optionen: stratum_jobs::AnalyseOptionen,
}

async fn analyse(
    State(z): State<Zustand>,
    Angemeldet(u): Angemeldet,
    Path(nummer): Path<String>,
    Koerper(a): Koerper<NeueAnalyse>,
) -> Antwort<(StatusCode, Json<Value>)> {
    let fall = fall_id(&z, &nummer).await?;
    let ev = z.db.evidence_id(fall, &a.evidence).await?.ok_or_else(|| {
        StoreError::NichtGefunden(format!("keine Evidence {} im Fall {nummer}", a.evidence))
    })?;
    let optionen = serde_json::to_value(&a.optionen).map_err(StoreError::from)?;
    let job = z.db.analyse_einreihen(u.id, fall, ev, optionen).await?;
    Ok((StatusCode::ACCEPTED, Json(json!({ "job": job }))))
}

#[derive(Deserialize)]
struct Auswahl {
    fall: Option<String>,
    anzahl: Option<i64>,
}

async fn jobs(
    State(z): State<Zustand>,
    Angemeldet(u): Angemeldet,
    Query(q): Query<Auswahl>,
) -> Antwort<Json<Value>> {
    let fall = match &q.fall {
        Some(n) => Some(fall_id(&z, n).await?),
        None => None,
    };
    let liste = z.db.jobs(u.id, fall, q.anzahl.unwrap_or(50)).await?;
    Ok(Json(serde_json::to_value(liste).map_err(StoreError::from)?))
}

async fn job(
    State(z): State<Zustand>,
    Angemeldet(u): Angemeldet,
    Path(id): Path<uuid::Uuid>,
) -> Antwort<Json<Value>> {
    let j = z.db.job_ansehen(u.id, JobId(id)).await?;
    Ok(Json(serde_json::to_value(j).map_err(StoreError::from)?))
}

async fn job_abbrechen(
    State(z): State<Zustand>,
    Angemeldet(u): Angemeldet,
    Path(id): Path<uuid::Uuid>,
) -> Antwort<Json<Value>> {
    let stand = z.db.job_abbrechen(u.id, JobId(id)).await?;
    Ok(Json(json!({ "status": stand })))
}

fn beendet(s: JobStatus) -> bool {
    matches!(
        s,
        JobStatus::Completed | JobStatus::Failed | JobStatus::Cancelled
    )
}

/// Fortschritt als Server-Sent Events: einmal je Sekunde ein Ereignis
/// `stand` mit Stand und Fortschritt, solange sich etwas ändert; endet mit
/// dem Job. Das Ansehen wird einmal beim Öffnen protokolliert.
async fn job_fortschritt(
    State(z): State<Zustand>,
    Angemeldet(u): Angemeldet,
    Path(id): Path<uuid::Uuid>,
) -> Antwort<Sse<impl Stream<Item = Result<Event, Infallible>>>> {
    let id = JobId(id);
    z.db.job_ansehen(u.id, id).await?;
    let db = z.db.clone();
    // Zustand des Stroms: zuletzt gesendeter Inhalt und ob Schluss ist.
    let strom = stream::unfold((None::<Value>, false, true), move |(alt, ende, erstes)| {
        let db = db.clone();
        async move {
            if ende {
                return None;
            }
            // Vor dem ersten Lesen nicht warten, danach je Runde eine
            // Sekunde, damit die Schleife nie ohne Pause kreist.
            let mut warten = !erstes;
            loop {
                if warten {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                warten = true;
                let j = match db.job_lesen(id).await {
                    Ok(j) => j,
                    Err(e) => {
                        let ev = Event::default()
                            .event("fehler")
                            .data(json!({ "fehler": e.to_string() }).to_string());
                        return Some((Ok(ev), (alt, true, false)));
                    }
                };
                let neu = json!({
                    "status": j.status,
                    "progress": j.progress,
                    "error": j.error,
                    "result": j.result,
                    "analysis_run_id": j.analysis_run_id,
                });
                let fertig = beendet(j.status);
                if alt.as_ref() != Some(&neu) || fertig {
                    let ev = Event::default().event("stand").data(neu.to_string());
                    return Some((Ok(ev), (Some(neu), fertig, false)));
                }
                // Unverändert: weiter warten, ohne zu senden.
            }
        }
    });
    Ok(Sse::new(strom).keep_alive(KeepAlive::default()))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportAnfrage {
    /// Datei im Fallordner, relativ zu ihm oder absolut.
    datei: String,
    name: Option<String>,
    rolle: Option<String>,
    art: Option<stratum_model::EvidenceKind>,
}

/// Evidence aus dem Fallordner importieren: als Job, weil der Hash über
/// ein großes Image lange dauert. Antwort 202 mit der Job-ID.
async fn evidence_importieren(
    State(z): State<Zustand>,
    Angemeldet(u): Angemeldet,
    Path(nummer): Path<String>,
    Koerper(a): Koerper<ImportAnfrage>,
) -> Antwort<(StatusCode, Json<Value>)> {
    let fall = fall_id(&z, &nummer).await?;
    let id =
        z.db.import_einreihen(u.id, fall, |ordner| {
            let datei = stratum_lauf::import::im_ordner(&ordner.join(&a.datei), ordner)
                .map_err(|e| e.to_string())?;
            serde_json::to_value(stratum_jobs::ImportParameter {
                datei,
                name: a.name,
                rolle: a.rolle,
                art: a.art,
            })
            .map_err(|e| e.to_string())
        })
        .await?;
    Ok((StatusCode::ACCEPTED, Json(json!({ "job": id }))))
}

#[derive(Deserialize)]
struct ZeitachseAnfrage {
    von: Option<chrono::DateTime<chrono::Utc>>,
    bis: Option<chrono::DateTime<chrono::Utc>>,
    /// Ereignisarten, durch Komma getrennt.
    art: Option<String>,
    entitaet: Option<uuid::Uuid>,
    nach: Option<String>,
    anzahl: Option<i64>,
}

async fn zeitachse(
    State(z): State<Zustand>,
    Angemeldet(u): Angemeldet,
    Path(nummer): Path<String>,
    Query(q): Query<ZeitachseAnfrage>,
) -> Antwort<Json<Value>> {
    let fall = fall_id(&z, &nummer).await?;
    let f = stratum_store::daten::Zeitfenster {
        von: q.von,
        bis: q.bis,
        arten: q
            .art
            .map(|a| {
                a.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default(),
        entitaet: q.entitaet.map(stratum_model::EntityId),
        nach: q.nach,
        anzahl: q.anzahl.unwrap_or(200),
    };
    let seite = z.db.zeitachse(u.id, fall, &f).await?;
    Ok(Json(serde_json::to_value(seite).map_err(StoreError::from)?))
}

async fn zeitachse_arten(
    State(z): State<Zustand>,
    Angemeldet(u): Angemeldet,
    Path(nummer): Path<String>,
) -> Antwort<Json<Value>> {
    let fall = fall_id(&z, &nummer).await?;
    let arten = z.db.zeitachse_arten(u.id, fall).await?;
    Ok(Json(Value::Array(
        arten
            .into_iter()
            .map(|(art, anzahl)| json!({ "art": art, "anzahl": anzahl }))
            .collect(),
    )))
}

#[derive(Deserialize)]
struct EntitaetenAnfrage {
    art: Option<String>,
    suche: Option<String>,
    nach: Option<String>,
    anzahl: Option<i64>,
}

async fn entitaeten(
    State(z): State<Zustand>,
    Angemeldet(u): Angemeldet,
    Path(nummer): Path<String>,
    Query(q): Query<EntitaetenAnfrage>,
) -> Antwort<Json<Value>> {
    let fall = fall_id(&z, &nummer).await?;
    let seite =
        z.db.entitaeten(
            u.id,
            fall,
            q.art.as_deref(),
            q.suche.as_deref().filter(|s| !s.is_empty()),
            q.nach.as_deref(),
            q.anzahl.unwrap_or(200),
        )
        .await?;
    Ok(Json(serde_json::to_value(seite).map_err(StoreError::from)?))
}

#[derive(Deserialize)]
struct KlartextAnfrage {
    #[serde(default)]
    klartext: bool,
}

async fn entitaet(
    State(z): State<Zustand>,
    Angemeldet(u): Angemeldet,
    Path(id): Path<uuid::Uuid>,
    Query(q): Query<KlartextAnfrage>,
) -> Antwort<Json<Value>> {
    let v =
        z.db.entitaet(u.id, stratum_model::EntityId(id), q.klartext)
            .await?;
    Ok(Json(v))
}

async fn volumes(
    State(z): State<Zustand>,
    Angemeldet(u): Angemeldet,
    Path(id): Path<uuid::Uuid>,
) -> Antwort<Json<Value>> {
    let v = z.db.volumes(u.id, stratum_model::EvidenceId(id)).await?;
    Ok(Json(Value::Array(v)))
}

#[derive(Deserialize)]
struct DateienAnfrage {
    volume: i64,
    /// MFT-Datensatz des Verzeichnisses, ohne Angabe die Wurzel.
    verzeichnis: Option<i64>,
    nach: Option<String>,
    anzahl: Option<i64>,
}

async fn dateien(
    State(z): State<Zustand>,
    Angemeldet(u): Angemeldet,
    Path(id): Path<uuid::Uuid>,
    Query(q): Query<DateienAnfrage>,
) -> Antwort<Json<Value>> {
    let v = stratum_store::dateien::Verzeichnis {
        volume_offset: q.volume,
        mft_record: q.verzeichnis.unwrap_or(stratum_store::dateien::WURZEL),
        nach: q.nach,
        anzahl: q.anzahl.unwrap_or(500),
    };
    let seite =
        z.db.verzeichnis(u.id, stratum_model::EvidenceId(id), &v)
            .await?;
    Ok(Json(serde_json::to_value(seite).map_err(StoreError::from)?))
}

/// Rohfund zu einem Artefakt aus dem Report des Laufs. Der Report wird vor
/// dem Lesen gegen seinen SHA-256 aus der Datenbank geprüft, die
/// Fundkennung gegen den Inhalt nachgerechnet.
async fn rohfund(
    State(z): State<Zustand>,
    Angemeldet(u): Angemeldet,
    Path(id): Path<uuid::Uuid>,
    Query(q): Query<KlartextAnfrage>,
) -> Antwort<Json<Value>> {
    use stratum_lauf::rohfund::RohfundFehler;
    let quelle =
        z.db.rohfund_quelle(u.id, stratum_model::ArtifactId(id), q.klartext)
            .await?;
    let (mut fund, report) = match &quelle.rohfund_id {
        // Ohne Kennung steht der Fund vollständig im Artefakt.
        None => (quelle.eingebettet.clone().unwrap_or_default(), Value::Null),
        Some(rid) => {
            let rid = rid.clone();
            let berichte = quelle.berichte.clone();
            let gelesen = tokio::task::spawn_blocking(move || {
                // Ein Integritätsfehler wiegt schwerer als ein Report, in dem
                // der Fund nur nicht steht, und wird deshalb gemeldet.
                let mut letzter: Option<RohfundFehler> = None;
                for (lauf, pfad, sha) in &berichte {
                    match stratum_lauf::rohfund::lesen(std::path::Path::new(pfad), &rid, Some(sha))
                    {
                        Ok(r) => return Ok((r, *lauf, pfad.clone())),
                        Err(e) => {
                            if !letzter.as_ref().is_some_and(RohfundFehler::integritaet) {
                                letzter = Some(e);
                            }
                        }
                    }
                }
                Err(letzter)
            })
            .await
            .map_err(|_| StoreError::Eingabe("Lesen des Reports abgebrochen".into()))?;
            match gelesen {
                Ok((r, lauf, pfad)) => {
                    let report = json!({"analysis_run_id": lauf, "pfad": pfad,
                                        "sha256": r.report_sha256, "geprueft": true});
                    let fund = serde_json::to_value(&r.fund).map_err(StoreError::from)?;
                    (fund, report)
                }
                Err(f) => {
                    let grund = f.as_ref().map_or_else(
                        || "kein Report zu einem abgeschlossenen Lauf gespeichert".to_string(),
                        ToString::to_string,
                    );
                    z.db.rohfund_protokollieren(&quelle, false, json!({"fehler": grund}))
                        .await?;
                    return Err(if f.as_ref().is_some_and(RohfundFehler::integritaet) {
                        ApiFehler::Integritaet(grund)
                    } else {
                        ApiFehler::NichtVerfuegbar(grund)
                    });
                }
            }
        }
    };
    let maskiert = !quelle.klartext && stratum_store::daten::rohfund_maskieren(&mut fund);
    z.db.rohfund_protokollieren(
        &quelle,
        true,
        json!({"report": report, "maskiert": maskiert}),
    )
    .await?;
    Ok(Json(json!({
        "artefakt": quelle.artefakt,
        "rohfund_id": quelle.rohfund_id,
        "fund": fund,
        "maskiert": maskiert,
        "klartext": quelle.klartext,
        "report": report,
    })))
}

async fn audit(
    State(z): State<Zustand>,
    Angemeldet(u): Angemeldet,
    Query(q): Query<Auswahl>,
) -> Antwort<Json<Value>> {
    let fall = match &q.fall {
        Some(n) => Some(fall_id(&z, n).await?),
        None => None,
    };
    let liste =
        z.db.audit_liste(u.id, fall, q.anzahl.unwrap_or(100))
            .await?;
    Ok(Json(serde_json::to_value(liste).map_err(StoreError::from)?))
}

async fn audit_pruefen(
    State(z): State<Zustand>,
    Angemeldet(u): Angemeldet,
) -> Antwort<Json<Value>> {
    let p = z.db.audit_pruefen(u.id).await?;
    Ok(Json(serde_json::to_value(p).map_err(StoreError::from)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_auth() {
        let mut h = HeaderMap::new();
        // "mia:pass:wort" (Doppelpunkt im Passwort erlaubt)
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic bWlhOnBhc3M6d29ydA=="),
        );
        assert_eq!(basic(&h), Some(("mia".into(), "pass:wort".into())));
        h.insert(header::AUTHORIZATION, HeaderValue::from_static("Basic !!!"));
        assert_eq!(basic(&h), None);
    }

    #[test]
    fn token_aus_header_und_cookie() {
        let mut h = HeaderMap::new();
        assert_eq!(token(&h), None);
        h.insert(
            header::COOKIE,
            HeaderValue::from_static("a=1; stratum_sitzung=abc; b=2"),
        );
        assert_eq!(token(&h).as_deref(), Some("abc"));
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer xyz"),
        );
        assert_eq!(token(&h).as_deref(), Some("xyz"));
    }
}
