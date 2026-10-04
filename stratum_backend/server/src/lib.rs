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
use axum::routing::{any, get, post, put};
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
    /// Das Konto muss zuerst sein Passwort ändern.
    #[error("Passwort muss zuerst geändert werden")]
    PasswortAendern,
}

impl IntoResponse for ApiFehler {
    fn into_response(self) -> Response {
        let status = match &self {
            ApiFehler::NichtAngemeldet => StatusCode::UNAUTHORIZED,
            ApiFehler::Anfrage(_) => StatusCode::BAD_REQUEST,
            ApiFehler::NichtVerfuegbar(_) => StatusCode::NOT_FOUND,
            ApiFehler::Integritaet(_) => StatusCode::CONFLICT,
            ApiFehler::PasswortAendern => StatusCode::FORBIDDEN,
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
        let AuchMitPasswortpflicht(u) =
            AuchMitPasswortpflicht::from_request_parts(parts, z).await?;
        if u.password_change_required {
            return Err(ApiFehler::PasswortAendern);
        }
        Ok(Angemeldet(u))
    }
}

/// Angemeldet, auch wenn das Konto zuerst sein Passwort ändern muss. Nur
/// für `/ich` und den Passwortwechsel.
pub struct AuchMitPasswortpflicht(pub User);

impl FromRequestParts<Zustand> for AuchMitPasswortpflicht {
    type Rejection = ApiFehler;

    async fn from_request_parts(parts: &mut Parts, z: &Zustand) -> Result<Self, Self::Rejection> {
        let t = token(&parts.headers).ok_or(ApiFehler::NichtAngemeldet)?;
        z.db.sitzung_pruefen(&t)
            .await?
            .map(AuchMitPasswortpflicht)
            .ok_or(ApiFehler::NichtAngemeldet)
    }
}

/// Router mit allen Endpunkten.
pub fn router(db: Datenbank) -> Router {
    Router::new()
        .route("/api/v1/sitzung", post(anmelden).delete(abmelden))
        .route("/api/v1/ich", get(ich))
        .route("/api/v1/ich/passwort", post(eigenes_passwort))
        .route("/api/v1/registrierung", post(registrieren))
        .route("/api/v1/konten", get(konten))
        .route("/api/v1/konten/{id}/freigeben", post(konto_freigeben))
        .route("/api/v1/konten/{id}/ablehnen", post(konto_ablehnen))
        .route("/api/v1/konten/{id}/sperren", post(konto_sperren))
        .route("/api/v1/konten/{id}/rollen", put(konto_rollen))
        .route("/api/v1/konten/{id}/passwort", post(konto_passwort))
        .route(
            "/api/v1/konten/{id}/superadmin",
            post(superadmin_uebertragen),
        )
        .route("/api/v1/rollen", get(rollen))
        .route("/api/v1/rechte", get(rechte))
        .route("/api/v1/faelle", get(faelle).post(fall_neu))
        .route(
            "/api/v1/faelle/{nummer}",
            get(fall_zeigen).put(fall_bearbeiten),
        )
        .route("/api/v1/faelle/{nummer}/analysen", post(analyse))
        .route("/api/v1/jobs", get(jobs))
        .route("/api/v1/jobs/{id}", get(job).delete(job_abbrechen))
        .route("/api/v1/jobs/{id}/fortschritt", get(job_fortschritt))
        .route(
            "/api/v1/faelle/{nummer}/evidence",
            post(evidence_importieren),
        )
        .route("/api/v1/faelle/{nummer}/ordner", get(fallordner))
        .route("/api/v1/faelle/{nummer}/zeitachse", get(zeitachse))
        .route(
            "/api/v1/faelle/{nummer}/zeitachse/arten",
            get(zeitachse_arten),
        )
        .route("/api/v1/faelle/{nummer}/entitaeten", get(entitaeten))
        .route("/api/v1/entitaeten/{id}", get(entitaet))
        .route("/api/v1/faelle/{nummer}/graph/{id}", get(graph))
        .route("/api/v1/faelle/{nummer}/beziehungen/{id}", get(beziehung))
        .route("/api/v1/ereignisse/{id}", get(ereignis))
        .route(
            "/api/v1/faelle/{nummer}/warroom",
            get(war_room).post(war_room_schreiben),
        )
        .route(
            "/api/v1/evidence/{id}/dateien/{volume}/{record}",
            get(datei_eintrag),
        )
        .route(
            "/api/v1/evidence/{id}/dateien/{volume}/{record}/inhalt",
            get(datei_inhalt),
        )
        .route(
            "/api/v1/evidence/{id}/dateien/{volume}/{record}/hash",
            post(datei_hash),
        )
        .route(
            "/api/v1/evidence/{id}/dateien/{volume}/{record}/export",
            get(datei_export),
        )
        .route(
            "/api/v1/evidence/{id}/dateien/{volume}/{record}/suche",
            post(datei_suche),
        )
        .route(
            "/api/v1/evidence/{id}/dateien/{volume}/{record}/ips",
            post(datei_ips),
        )
        .route(
            "/api/v1/evidence/{id}/dateien/{volume}/{record}/vorschau",
            get(datei_vorschau),
        )
        .route("/api/v1/evidence/{id}/volumes", get(volumes))
        .route("/api/v1/evidence/{id}/dateien", get(dateien))
        .route("/api/v1/evidence/{id}/dateisuche", get(dateisuche))
        .route("/api/v1/artefakte/{id}/rohfund", get(rohfund))
        .route(
            "/api/v1/evidence/{id}/dateien/{volume}/{record}/yara",
            post(datei_yara),
        )
        .route(
            "/api/v1/faelle/{nummer}/bookmarks/status",
            get(bookmark_status),
        )
        .route("/api/v1/faelle/{nummer}/netzwerk", post(netzwerk_job))
        .route("/api/v1/faelle/{nummer}/http-lab", post(http_replay_job))
        .route(
            "/api/v1/faelle/{nummer}/bookmarks",
            get(bookmarks).put(bookmark_schreiben),
        )
        .route("/api/v1/audit", get(audit))
        .route("/api/v1/audit/pruefen", post(audit_pruefen))
        .with_state(Zustand { db })
}

/// Wie [`router`], dazu die Weboberfläche aus `oberflaeche` (der gebaute
/// Ordner `stratum_frontend/dist`): Dateien von dort, alle übrigen Pfade
/// außerhalb von `/api` erhalten `index.html`, damit Adressen der
/// Oberfläche auch beim Neuladen funktionieren. Unbekannte API-Pfade
/// bleiben 404 im gewohnten Format. Jede Antwort trägt
/// Sicherheits-Kopfzeilen (CSP nur eigene Quellen, kein Einbetten).
pub fn router_mit_oberflaeche(db: Datenbank, oberflaeche: Option<&std::path::Path>) -> Router {
    let r = router(db).route("/api/{*rest}", any(api_unbekannt));
    let r = match oberflaeche {
        Some(d) => r.fallback_service(
            tower_http::services::ServeDir::new(d)
                .fallback(tower_http::services::ServeFile::new(d.join("index.html"))),
        ),
        None => r,
    };
    r.layer(axum::middleware::map_response(sicherheitskoepfe))
}

async fn api_unbekannt() -> ApiFehler {
    ApiFehler::Store(StoreError::NichtGefunden("unbekannter Pfad".into()))
}

async fn sicherheitskoepfe(mut r: Response) -> Response {
    let h = r.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; img-src 'self' data: blob:; object-src 'none'; \
             base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        ),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    r
}

/// Startet den Server auf einer schon gebundenen Adresse und läuft, bis
/// `stopp` endet. Erst binden, dann starten: so steht vor allem anderen
/// fest, ob die Adresse frei ist. Mit `oberflaeche` auch die Weboberfläche.
pub async fn starten(
    db: Datenbank,
    listener: tokio::net::TcpListener,
    oberflaeche: Option<&std::path::Path>,
    stopp: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    axum::serve(listener, router_mit_oberflaeche(db, oberflaeche))
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

async fn ich(
    State(z): State<Zustand>,
    AuchMitPasswortpflicht(u): AuchMitPasswortpflicht,
) -> Antwort<Json<Value>> {
    let rechte = z.db.rechte(u.id).await?;
    Ok(Json(json!({ "konto": u, "rechte": rechte })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Passwortwechsel {
    bisher: String,
    neu: String,
}

/// Eigenes Passwort ändern; auch mit Passwortpflicht erlaubt. Danach enden
/// alle Sitzungen des Kontos, auch die laufende.
async fn eigenes_passwort(
    State(z): State<Zustand>,
    AuchMitPasswortpflicht(u): AuchMitPasswortpflicht,
    Koerper(p): Koerper<Passwortwechsel>,
) -> Antwort<StatusCode> {
    if p.neu == p.bisher {
        return Err(ApiFehler::Anfrage(
            "das neue Passwort muss sich unterscheiden".into(),
        ));
    }
    z.db.passwort_aendern(u.id, &u.username, Some(&p.bisher), &p.neu)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Registrierung {
    name: String,
    anzeigename: String,
    passwort: String,
}

/// Selbstregistrierung ohne Anmeldung: das Konto wartet auf Freigabe durch
/// den Superadmin und hat bis dahin keine Rechte.
async fn registrieren(
    State(z): State<Zustand>,
    Koerper(r): Koerper<Registrierung>,
) -> Antwort<(StatusCode, Json<Value>)> {
    let anzeige = r.anzeigename.trim();
    if anzeige.is_empty() || anzeige.chars().count() > 120 {
        return Err(ApiFehler::Anfrage(
            "Anzeigename fehlt oder ist zu lang".into(),
        ));
    }
    let u =
        z.db.registrieren(r.name.trim(), anzeige, &r.passwort)
            .await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "username": u.username, "status": u.status })),
    ))
}

async fn konten(State(z): State<Zustand>, Angemeldet(u): Angemeldet) -> Antwort<Json<Value>> {
    Ok(Json(
        serde_json::to_value(z.db.konten(u.id).await?).map_err(StoreError::from)?,
    ))
}

/// Rollen mit Berechtigungen (für die Freigabe; nur Superadmin).
async fn rollen(State(z): State<Zustand>, Angemeldet(u): Angemeldet) -> Antwort<Json<Value>> {
    if !u.superadmin {
        return Err(StoreError::Verweigert("nur der Superadmin verwaltet Rollen".into()).into());
    }
    Ok(Json(
        serde_json::to_value(z.db.rollen().await?).map_err(StoreError::from)?,
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Rollenwahl {
    rollen: Vec<uuid::Uuid>,
}

async fn konto_freigeben(
    State(z): State<Zustand>,
    Angemeldet(u): Angemeldet,
    Path(id): Path<uuid::Uuid>,
    Koerper(r): Koerper<Rollenwahl>,
) -> Antwort<StatusCode> {
    let rollen: Vec<_> = r.rollen.into_iter().map(stratum_model::RoleId).collect();
    z.db.freigeben(u.id, stratum_model::ActorId(id), &rollen)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn konto_ablehnen(
    State(z): State<Zustand>,
    Angemeldet(u): Angemeldet,
    Path(id): Path<uuid::Uuid>,
) -> Antwort<StatusCode> {
    z.db.ablehnen(u.id, stratum_model::ActorId(id)).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn konto_sperren(
    State(z): State<Zustand>,
    Angemeldet(u): Angemeldet,
    Path(id): Path<uuid::Uuid>,
) -> Antwort<StatusCode> {
    z.db.sperren(u.id, stratum_model::ActorId(id)).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn konto_rollen(
    State(z): State<Zustand>,
    Angemeldet(u): Angemeldet,
    Path(id): Path<uuid::Uuid>,
    Koerper(r): Koerper<Rollenwahl>,
) -> Antwort<StatusCode> {
    let rollen: Vec<_> = r.rollen.into_iter().map(stratum_model::RoleId).collect();
    z.db.konto_rollen_setzen(u.id, stratum_model::ActorId(id), &rollen)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NeuesPasswort {
    neu: String,
}

/// Superadmin setzt ein Passwort; das Konto muss es bei der nächsten
/// Anmeldung selbst ersetzen.
async fn konto_passwort(
    State(z): State<Zustand>,
    Angemeldet(u): Angemeldet,
    Path(id): Path<uuid::Uuid>,
    Koerper(p): Koerper<NeuesPasswort>,
) -> Antwort<StatusCode> {
    let name =
        z.db.konten(u.id)
            .await?
            .into_iter()
            .find(|k| k.id.0 == id)
            .map(|k| k.username)
            .ok_or_else(|| StoreError::NichtGefunden(format!("kein Konto {id}")))?;
    z.db.passwort_aendern(u.id, &name, None, &p.neu).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn superadmin_uebertragen(
    State(z): State<Zustand>,
    Angemeldet(u): Angemeldet,
    Path(id): Path<uuid::Uuid>,
) -> Antwort<StatusCode> {
    z.db.superadmin_uebertragen(u.id, stratum_model::ActorId(id))
        .await?;
    Ok(StatusCode::NO_CONTENT)
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

async fn fall_bearbeiten(
    State(z): State<Zustand>,
    Angemeldet(u): Angemeldet,
    Path(nummer): Path<String>,
    Koerper(mut a): Koerper<stratum_store::faelle::FallAenderung>,
) -> Antwort<Json<Case>> {
    let id = fall_id(&z, &nummer).await?;
    let zugriff = stratum_store::AuditEintrag {
        akteur: u.id,
        case_id: Some(id),
        aktion: stratum_model::AuditAction::CaseEdit,
        objekt_typ: "case",
        objekt_id: Some(id.to_string()),
        ergebnis: stratum_model::AuditResult::Success,
        details: json!({}),
    };
    z.db.verlangen(u.id, Permission::CaseEdit, zugriff.clone())
        .await?;
    z.db.verlangen(u.id, Permission::CaseView, zugriff).await?;
    if let Some(ordner) = a.ordner.take().filter(|o| !o.trim().is_empty()) {
        let pfad = std::path::PathBuf::from(ordner.trim());
        if !pfad.is_absolute() {
            return Err(ApiFehler::Anfrage(
                "Fallordner muss ein absoluter Serverpfad sein".into(),
            ));
        }
        let pfad = tokio::task::spawn_blocking(move || {
            let p = std::fs::canonicalize(&pfad)?;
            if !p.is_dir() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "kein Verzeichnis",
                ));
            }
            std::fs::read_dir(&p)?;
            Ok(p)
        })
        .await
        .map_err(|_| ApiFehler::NichtVerfuegbar("Ordnerprüfung abgebrochen".into()))?
        .map_err(|e| ApiFehler::Anfrage(format!("Fallordner nicht lesbar: {e}")))?;
        a.ordner = Some(
            pfad.to_str()
                .ok_or_else(|| ApiFehler::Anfrage("Fallordner ist kein UTF-8-Pfad".into()))?
                .to_string(),
        );
    }
    Ok(Json(z.db.fall_bearbeiten(u.id, id, &a).await?))
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
                if j.kind == stratum_model::JobKind::HttpReplay {
                    let audit = stratum_store::AuditEintrag {
                        akteur: u.id,
                        case_id: Some(j.case_id),
                        aktion: stratum_model::AuditAction::JobList,
                        objekt_typ: "job",
                        objekt_id: Some(id.to_string()),
                        ergebnis: stratum_model::AuditResult::Success,
                        details: json!({"art":"http_replay_stream"}),
                    };
                    for permission in [
                        stratum_model::Permission::CaseView,
                        stratum_model::Permission::FileView,
                    ] {
                        if let Err(error) = db.verlangen(u.id, permission, audit.clone()).await {
                            let ev = Event::default()
                                .event("fehler")
                                .data(json!({"fehler":error.to_string()}).to_string());
                            return Some((Ok(ev), (alt, true, false)));
                        }
                    }
                }
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
struct OrdnerAnfrage {
    #[serde(default)]
    pfad: String,
}

/// Inhalt des Fallordners (oder eines Unterordners) zur Auswahl beim
/// Import; Dateien, die schon als Evidence registriert sind, sind markiert.
async fn fallordner(
    State(z): State<Zustand>,
    Angemeldet(u): Angemeldet,
    Path(nummer): Path<String>,
    Query(q): Query<OrdnerAnfrage>,
) -> Antwort<Json<Value>> {
    let fall = fall_id(&z, &nummer).await?;
    let (ordner, quellen) = z.db.fallordner_ansehen(u.id, fall, &q.pfad).await?;
    let o = ordner.clone();
    let (rel, liste) = tokio::task::spawn_blocking(move || {
        stratum_lauf::import::ordner_auflisten(std::path::Path::new(&o), &q.pfad)
    })
    .await
    .map_err(|_| ApiFehler::NichtVerfuegbar("Lesen abgebrochen".into()))?
    .map_err(|e| ApiFehler::Anfrage(e.to_string()))?;
    let eintraege: Vec<Value> = liste
        .into_iter()
        .map(|e| {
            let registriert = quellen.contains(&e.pfad);
            let mut v = serde_json::to_value(e).unwrap_or(Value::Null);
            v["registriert"] = json!(registriert);
            v
        })
        .collect();
    Ok(Json(
        json!({ "ordner": ordner, "pfad": rel, "eintraege": eintraege }),
    ))
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
    evidence: Option<uuid::Uuid>,
    suche: Option<String>,
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
        evidence: q.evidence.map(stratum_model::EvidenceId),
        suche: q.suche.filter(|s| !s.trim().is_empty()),
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

#[derive(Deserialize)]
struct GraphAnfrage {
    nach: Option<uuid::Uuid>,
    anzahl: Option<i64>,
}

async fn graph(
    State(z): State<Zustand>,
    Angemeldet(u): Angemeldet,
    Path((nummer, id)): Path<(String, uuid::Uuid)>,
    Query(q): Query<GraphAnfrage>,
) -> Antwort<Json<Value>> {
    let fall = fall_id(&z, &nummer).await?;
    Ok(Json(
        z.db.graph_umgebung(
            u.id,
            fall,
            stratum_model::EntityId(id),
            q.nach,
            q.anzahl.unwrap_or(30),
        )
        .await?,
    ))
}

async fn beziehung(
    State(z): State<Zustand>,
    Angemeldet(u): Angemeldet,
    Path((nummer, id)): Path<(String, uuid::Uuid)>,
) -> Antwort<Json<Value>> {
    let fall = fall_id(&z, &nummer).await?;
    Ok(Json(z.db.beziehung_detail(u.id, fall, id).await?))
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

async fn dateisuche(
    State(z): State<Zustand>,
    Angemeldet(u): Angemeldet,
    Path(id): Path<uuid::Uuid>,
    Query(q): Query<stratum_store::dateien::DateiFilter>,
) -> Antwort<Json<Value>> {
    let seite =
        z.db.dateien_suchen(u.id, stratum_model::EvidenceId(id), &q)
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

async fn ereignis(
    State(z): State<Zustand>,
    Angemeldet(u): Angemeldet,
    Path(id): Path<uuid::Uuid>,
) -> Antwort<Json<Value>> {
    Ok(Json(z.db.ereignis(u.id, stratum_model::EventId(id)).await?))
}

#[derive(Deserialize)]
struct WarRoomAnfrage {
    vor: Option<uuid::Uuid>,
    anzahl: Option<i64>,
}

async fn war_room(
    State(z): State<Zustand>,
    Angemeldet(u): Angemeldet,
    Path(nummer): Path<String>,
    Query(q): Query<WarRoomAnfrage>,
) -> Antwort<Json<Value>> {
    let fall = fall_id(&z, &nummer).await?;
    let (eintraege, naechste) =
        z.db.war_room(
            u.id,
            fall,
            q.vor.map(stratum_model::WarRoomEntryId),
            q.anzahl.unwrap_or(100),
        )
        .await?;
    let mut liste = Vec::with_capacity(eintraege.len());
    for (e, name) in eintraege {
        let mut v = serde_json::to_value(e).map_err(StoreError::from)?;
        v["actor_name"] = json!(name);
        liste.push(v);
    }
    Ok(Json(json!({ "eintraege": liste, "naechste": naechste })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WarRoomEintrag {
    text: String,
    #[serde(default = "notiz")]
    art: stratum_model::WarRoomEntryKind,
    #[serde(default)]
    refs: Vec<stratum_model::ObjectRef>,
    parent: Option<uuid::Uuid>,
}

fn notiz() -> stratum_model::WarRoomEntryKind {
    stratum_model::WarRoomEntryKind::AnalystNote
}

async fn war_room_schreiben(
    State(z): State<Zustand>,
    Angemeldet(u): Angemeldet,
    Path(nummer): Path<String>,
    Koerper(e): Koerper<WarRoomEintrag>,
) -> Antwort<(StatusCode, Json<Value>)> {
    let fall = fall_id(&z, &nummer).await?;
    let neu =
        z.db.war_room_schreiben(
            u.id,
            fall,
            e.art,
            &e.text,
            &e.refs,
            e.parent.map(stratum_model::WarRoomEntryId),
        )
        .await?;
    let mut v = serde_json::to_value(neu).map_err(StoreError::from)?;
    v["actor_name"] = json!(u.display_name);
    Ok((StatusCode::CREATED, Json(v)))
}

/// Datei im Katalog: Evidence, Volume-Offset, MFT-Datensatz.
type DateiPfad = Path<(uuid::Uuid, i64, i64)>;

fn ort<'a>(
    q: &'a stratum_store::dateien::DateiQuelle,
    volume: i64,
    record: i64,
) -> Antwort<stratum_lauf::datei::DateiOrt<'a>> {
    let falsch = || ApiFehler::Anfrage("Volume oder Datensatz negativ".into());
    Ok(stratum_lauf::datei::DateiOrt {
        image: std::path::Path::new(&q.image),
        bdp: q.bdp.as_deref().map(std::path::Path::new),
        volume_offset: u64::try_from(volume).map_err(|_| falsch())?,
        mft: u64::try_from(record).map_err(|_| falsch())?,
    })
}

#[derive(Deserialize)]
struct Ausschnitt {
    #[serde(default)]
    offset: u64,
    laenge: Option<u64>,
}

/// Katalogeintrag eines Datensatzes (bei Hardlinks mehrere Namen).
async fn datei_eintrag(
    State(z): State<Zustand>,
    Angemeldet(u): Angemeldet,
    Path((id, volume, record)): DateiPfad,
) -> Antwort<Json<Value>> {
    let v =
        z.db.datei_eintrag(u.id, stratum_model::EvidenceId(id), volume, record)
            .await?;
    Ok(Json(Value::Array(v)))
}

/// Bis zu 64 KiB des Inhalts ab `offset` als Bytes (Hex-Ansicht).
async fn datei_inhalt(
    State(z): State<Zustand>,
    Angemeldet(u): Angemeldet,
    Path((id, volume, record)): DateiPfad,
    Query(a): Query<Ausschnitt>,
) -> Antwort<Response> {
    use stratum_store::dateien::Zugriff;
    let q =
        z.db.datei_quelle(
            u.id,
            stratum_model::EvidenceId(id),
            volume,
            record,
            Zugriff::Ansehen,
        )
        .await?;
    let laenge = a.laenge.unwrap_or(4096);
    let groesse = q.groesse;
    let daten = tokio::task::spawn_blocking(move || {
        let o = ort(&q, volume, record)?;
        stratum_lauf::datei::ausschnitt(&o, a.offset, laenge)
            .map_err(|e| ApiFehler::NichtVerfuegbar(e.to_string()))
    })
    .await
    .map_err(|_| ApiFehler::NichtVerfuegbar("Lesen abgebrochen".into()))??;
    let mut r = daten.into_response();
    let h = r.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    h.insert("x-stratum-offset", HeaderValue::from(a.offset));
    if let Some(g) = groesse {
        h.insert("x-stratum-groesse", HeaderValue::from(g));
    }
    Ok(r)
}

#[derive(Deserialize)]
struct DateiSuchtext {
    wort: String,
}

async fn datei_suche(
    State(z): State<Zustand>,
    Angemeldet(u): Angemeldet,
    Path((id, volume, record)): DateiPfad,
    Koerper(a): Koerper<DateiSuchtext>,
) -> Antwort<Json<Value>> {
    if a.wort.is_empty() || a.wort.len() > 1024 {
        return Err(
            StoreError::Eingabe("Suchtext muss 1 bis 1024 UTF-8-Bytes lang sein".into()).into(),
        );
    }
    let q =
        z.db.datei_quelle(
            u.id,
            stratum_model::EvidenceId(id),
            volume,
            record,
            stratum_store::dateien::Zugriff::Suchen,
        )
        .await?;
    let quelle = q.clone();
    let wort = a.wort.clone();
    let v = tokio::task::spawn_blocking(move || {
        let o = ort(&q, volume, record)?;
        stratum_lauf::datei::wort_suchen(&o, &a.wort)
            .map_err(|e| ApiFehler::NichtVerfuegbar(e.to_string()))
    })
    .await
    .map_err(|_| ApiFehler::NichtVerfuegbar("Suche abgebrochen".into()))
    .and_then(|v| v);
    let details = match &v {
        Ok(v) => {
            json!({"treffer": v.treffer.len(), "gelesen": v.gelesen, "vollstaendig": v.vollstaendig})
        }
        Err(_) => json!({"status": "fehlgeschlagen"}),
    };
    z.db.dateisuche_protokollieren(u.id, &quelle, &wort, details, v.is_ok())
        .await?;
    Ok(Json(serde_json::to_value(v?).map_err(StoreError::from)?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct YaraAnfrage {
    regeln: String,
}

async fn datei_yara(
    State(z): State<Zustand>,
    Angemeldet(u): Angemeldet,
    Path((id, volume, record)): DateiPfad,
    Json(q): Json<YaraAnfrage>,
) -> Antwort<Json<Value>> {
    let quelle =
        z.db.datei_quelle(
            u.id,
            stratum_model::EvidenceId(id),
            volume,
            record,
            stratum_store::dateien::Zugriff::Suchen,
        )
        .await?;
    stratum_connectors::yara::regeln_pruefen(&q.regeln)
        .map_err(|e| ApiFehler::Anfrage(e.to_string()))?;
    if quelle.groesse.is_some_and(|size| size > 256 * 1024 * 1024) {
        return Err(ApiFehler::Anfrage(
            "Datei größer als YARA-Limit von 256 MiB".into(),
        ));
    }
    let hash = stratum_core::hash_bytes(q.regeln.as_bytes()).sha256;
    let job =
        z.db.yara_job(u.id, &quelle, volume, record, &q.regeln, &hash)
            .await?;
    Ok(Json(json!({"job_id":job, "regel_sha256":hash})))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NetzwerkAnfrage {
    ziel: String,
    dns: bool,
    whois: bool,
}

async fn netzwerk_job(
    State(z): State<Zustand>,
    Angemeldet(u): Angemeldet,
    Path(nummer): Path<String>,
    Json(q): Json<NetzwerkAnfrage>,
) -> Antwort<Json<Value>> {
    let fall = fall_id(&z, &nummer).await?;
    let host = stratum_connectors::netzwerk::host_eingabe(&q.ziel)
        .map_err(|e| ApiFehler::Anfrage(e.to_string()))?;
    if !q.dns && !q.whois {
        return Err(ApiFehler::Anfrage("DNS oder WHOIS auswählen".into()));
    }
    let job = z.db.netzwerk_job(u.id, fall, &host, q.dns, q.whois).await?;
    Ok(Json(json!({"job_id":job,"host":host})))
}

async fn datei_ips(
    State(z): State<Zustand>,
    Angemeldet(u): Angemeldet,
    Path((id, volume, record)): DateiPfad,
) -> Antwort<Json<Value>> {
    let q =
        z.db.datei_quelle(
            u.id,
            stratum_model::EvidenceId(id),
            volume,
            record,
            stratum_store::dateien::Zugriff::Suchen,
        )
        .await?;
    let quelle = q.clone();
    let v = tokio::task::spawn_blocking(move || {
        let o = ort(&q, volume, record)?;
        stratum_lauf::datei::ips_suchen(&o).map_err(|e| ApiFehler::NichtVerfuegbar(e.to_string()))
    })
    .await
    .map_err(|_| ApiFehler::NichtVerfuegbar("IP-Suche abgebrochen".into()))
    .and_then(|v| v);
    let details = match &v {
        Ok(v) => {
            json!({"modus":"ip-literal-v1", "treffer":v.treffer.len(), "gelesen":v.gelesen, "vollstaendig":v.vollstaendig, "volume":volume, "mft":record})
        }
        Err(_) => {
            json!({"modus":"ip-literal-v1", "status":"fehlgeschlagen", "volume":volume, "mft":record})
        }
    };
    z.db.dateisuche_protokollieren(u.id, &quelle, "ip-literal-v1", details, v.is_ok())
        .await?;
    Ok(Json(
        json!({"quelle":{"evidence":id,"volume":volume,"mft":record,"pfad":quelle.pfad,"offset_basis":"logical_file"},
            "ableitung":stratum_model::DerivationKind::Parsed,
            "parser":{"name":"ip-literal-v1","version":env!("CARGO_PKG_VERSION")},"ergebnis":v?}),
    ))
}

async fn datei_vorschau(
    State(z): State<Zustand>,
    Angemeldet(u): Angemeldet,
    Path((id, volume, record)): DateiPfad,
) -> Antwort<Response> {
    let q =
        z.db.datei_quelle(
            u.id,
            stratum_model::EvidenceId(id),
            volume,
            record,
            stratum_store::dateien::Zugriff::Ansehen,
        )
        .await?;
    let groesse = q
        .groesse
        .and_then(|g| u64::try_from(g).ok())
        .ok_or_else(|| StoreError::Eingabe("Dateigröße unbekannt".into()))?;
    if groesse > 8 * 1024 * 1024 {
        return Err(StoreError::Eingabe("Vorschau auf 8 MiB begrenzt".into()).into());
    }
    let daten = tokio::task::spawn_blocking(move || {
        let o = ort(&q, volume, record)?;
        stratum_lauf::datei::vorschau(&o, groesse)
            .map_err(|e| ApiFehler::NichtVerfuegbar(e.to_string()))
    })
    .await
    .map_err(|_| ApiFehler::NichtVerfuegbar("Lesen abgebrochen".into()))??;
    if daten.len() as u64 != groesse {
        return Err(ApiFehler::NichtVerfuegbar(
            "Dateigröße weicht vom Katalog ab".into(),
        ));
    }
    let mut r = daten.into_response();
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    Ok(r)
}

/// Liest die Datei vollständig, liefert SHA-256 und BLAKE3 und vermerkt
/// den SHA-256 im Katalog.
async fn datei_hash(
    State(z): State<Zustand>,
    Angemeldet(u): Angemeldet,
    Path((id, volume, record)): DateiPfad,
) -> Antwort<Json<Value>> {
    use stratum_store::dateien::Zugriff;
    let ev = stratum_model::EvidenceId(id);
    let q =
        z.db.datei_quelle(u.id, ev, volume, record, Zugriff::Hashen)
            .await?;
    let h = tokio::task::spawn_blocking(move || {
        let o = ort(&q, volume, record)?;
        stratum_lauf::datei::schreiben(&o, std::io::sink())
            .map(|(_, h)| h)
            .map_err(|e| ApiFehler::NichtVerfuegbar(e.to_string()))
    })
    .await
    .map_err(|_| ApiFehler::NichtVerfuegbar("Lesen abgebrochen".into()))??;
    let vermerkt =
        z.db.datei_hash_vermerken(ev, volume, record, &h.sha256)
            .await?;
    let mut v = serde_json::to_value(&h).map_err(StoreError::from)?;
    v["im_katalog_vermerkt"] = json!(vermerkt);
    Ok(Json(v))
}

/// Schreibt in einen Kanal; der Server schickt die Blöcke als Antwort.
struct KanalWriter {
    tx: tokio::sync::mpsc::Sender<Result<axum::body::Bytes, std::io::Error>>,
    puffer: Vec<u8>,
}

impl KanalWriter {
    const BLOCK: usize = 256 * 1024;

    fn senden(&mut self) -> std::io::Result<()> {
        if self.puffer.is_empty() {
            return Ok(());
        }
        let block = std::mem::replace(&mut self.puffer, Vec::with_capacity(Self::BLOCK));
        self.tx
            .blocking_send(Ok(block.into()))
            .map_err(|_| std::io::Error::other("Verbindung beendet"))
    }
}

impl std::io::Write for KanalWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.puffer.extend_from_slice(buf);
        if self.puffer.len() >= Self::BLOCK {
            self.senden()?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.senden()
    }
}

/// Inhalt als Download (braucht `file.extract`). Nach dem letzten Block
/// steht der Export mit SHA-256 im War Room.
async fn datei_export(
    State(z): State<Zustand>,
    Angemeldet(u): Angemeldet,
    Path((id, volume, record)): DateiPfad,
) -> Antwort<Response> {
    use stratum_store::dateien::Zugriff;
    let q =
        z.db.datei_quelle(
            u.id,
            stratum_model::EvidenceId(id),
            volume,
            record,
            Zugriff::Exportieren,
        )
        .await?;
    // Image und Volume vorab prüfen, damit ein Fehler als Antwort und nicht
    // als abgebrochener Download ankommt.
    let q = tokio::task::spawn_blocking(move || {
        stratum_lauf::datei::pruefen(&ort(&q, volume, record)?)
            .map_err(|e| ApiFehler::NichtVerfuegbar(e.to_string()))?;
        Ok::<_, ApiFehler>(q)
    })
    .await
    .map_err(|_| ApiFehler::NichtVerfuegbar("Prüfen abgebrochen".into()))??;
    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    let db = z.db.clone();
    let handle = tokio::runtime::Handle::current();
    let name = q.name.clone();
    let akteur = u.id;
    tokio::task::spawn_blocking(move || {
        let Ok(o) = ort(&q, volume, record) else {
            return;
        };
        let w = KanalWriter {
            tx: tx.clone(),
            puffer: Vec::with_capacity(KanalWriter::BLOCK),
        };
        match stratum_lauf::datei::schreiben(&o, w) {
            Ok((mut w, h)) => {
                let _ = std::io::Write::flush(&mut w);
                let _ = handle
                    .block_on(db.datei_exportiert(akteur, &q, volume, record, h.bytes, &h.sha256));
            }
            Err(e) => {
                let _ = tx.blocking_send(Err(std::io::Error::other(e.to_string())));
            }
        }
    });
    let strom = stream::poll_fn(move |cx| rx.poll_recv(cx));
    let mut r = Response::new(axum::body::Body::from_stream(strom));
    let h = r.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    // Nur sichere Zeichen im Dateinamen; der Rest wird ersetzt.
    let sicher: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || ".-_".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect();
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{sicher}\"")) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    Ok(r)
}

async fn audit(
    State(z): State<Zustand>,
    Angemeldet(u): Angemeldet,
    Query(q): Query<AuditAuswahl>,
) -> Antwort<Json<Value>> {
    let fall = match &q.fall {
        Some(n) => Some(fall_id(&z, n).await?),
        None => None,
    };
    let liste =
        z.db.audit_seite(u.id, fall, q.anzahl.unwrap_or(100).clamp(1, 1000), q.vor)
            .await?;
    Ok(Json(serde_json::to_value(liste).map_err(StoreError::from)?))
}

#[derive(Deserialize)]
struct AuditAuswahl {
    fall: Option<String>,
    anzahl: Option<i64>,
    vor: Option<i64>,
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

async fn bookmarks(
    State(z): State<Zustand>,
    Angemeldet(u): Angemeldet,
    Path(nummer): Path<String>,
    Query(q): Query<WarRoomAnfrage>,
) -> Antwort<Json<Value>> {
    let case = fall_id(&z, &nummer).await?;
    Ok(Json(
        z.db.bookmarks(u.id, case, q.vor, q.anzahl.unwrap_or(100))
            .await?,
    ))
}
async fn bookmark_schreiben(
    State(z): State<Zustand>,
    Angemeldet(u): Angemeldet,
    Path(nummer): Path<String>,
    Koerper(s): Koerper<stratum_store::bookmarks::Auswahl>,
) -> Antwort<Json<Value>> {
    let case = fall_id(&z, &nummer).await?;
    Ok(Json(z.db.bookmark_schreiben(u.id, case, &s).await?))
}

#[derive(Deserialize)]
struct BookmarkZiel {
    kind: stratum_model::bookmark::BookmarkKind,
    target: String,
}

async fn http_replay_job(
    State(z): State<Zustand>,
    Angemeldet(u): Angemeldet,
    Path(nummer): Path<String>,
    Koerper(request): Koerper<stratum_model::http_lab::HttpReplayRequest>,
) -> Antwort<Json<Value>> {
    let case = fall_id(&z, &nummer).await?;
    let id = z.db.http_replay_job(u.id, case, &request).await?;
    Ok(Json(
        json!({"job_id":id,"network_policy":"none","mode":"offline_simulation"}),
    ))
}
async fn bookmark_status(
    State(z): State<Zustand>,
    Angemeldet(u): Angemeldet,
    Path(nummer): Path<String>,
    Query(q): Query<BookmarkZiel>,
) -> Antwort<Json<Value>> {
    let case = fall_id(&z, &nummer).await?;
    Ok(Json(
        z.db.bookmark_status(u.id, case, q.kind, &q.target).await?,
    ))
}
