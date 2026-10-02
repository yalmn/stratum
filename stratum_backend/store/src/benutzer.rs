//! Benutzerkonten, Rollen und Anmeldung.
//!
//! Passwörter werden mit Argon2id (Standardparameter von `argon2`, zufälliges
//! Salz) im PHC-Format gespeichert. Jede Änderung an Konten und Rollen und
//! jede Anmeldung, auch eine abgelehnte, steht im Audit.

use argon2::password_hash::PasswordHasher;
use argon2::{Argon2, PasswordVerifier};
use chrono::Utc;
use serde_json::json;
use stratum_model::{ActorId, AuditAction, AuditResult, Role, User, UserKind};

use crate::audit::{self, AuditEintrag};
use crate::{Datenbank, StoreError};

/// Mindestlänge eines Passworts.
pub const PASSWORT_MINDESTLAENGE: usize = 12;

/// Angaben für ein neues Konto.
#[derive(Debug, Clone)]
pub struct NeuerBenutzer<'a> {
    /// Anmeldename (klein, `a-z 0-9 . _ -`, höchstens 64 Zeichen).
    pub username: &'a str,
    /// Anzeigename.
    pub display_name: &'a str,
    /// Art.
    pub kind: UserKind,
    /// Passwort, nur bei Menschen.
    pub passwort: Option<&'a str>,
    /// Rollen.
    pub rollen: &'a [Role],
}

/// Gültiger PHC-Hash für ein nie vergebenes Passwort. Bei unbekanntem Namen
/// wird dagegen geprüft, damit die Antwortzeit nicht verrät, ob es ein Konto
/// gibt.
const ATTRAPPE: &str =
    "$argon2id$v=19$m=19456,t=2,p=1$c3RyYXR1bWF0dHJhcHBl$x3k3jmy3XsMPQ0V1XX+Fq/qxHZwzLMd4P6mP0n1eBJ0";

/// Zeile aus `app_user`: id, username, display_name, kind, active,
/// created_at, created_by.
type Kontozeile = (
    uuid::Uuid,
    String,
    String,
    String,
    bool,
    chrono::DateTime<Utc>,
    Option<uuid::Uuid>,
);

fn rollentext(r: Role) -> Result<String, StoreError> {
    match serde_json::to_value(r)? {
        serde_json::Value::String(s) => Ok(s),
        _ => Err(StoreError::Wert("Rolle ohne Textform")),
    }
}

impl Datenbank {
    /// Rollen eines Kontos.
    pub async fn rollen(&self, user: ActorId) -> Result<Vec<Role>, StoreError> {
        let texte: Vec<String> =
            sqlx::query_scalar("SELECT role FROM user_role WHERE user_id = $1 ORDER BY role")
                .bind(user.0)
                .fetch_all(&self.pool)
                .await?;
        texte
            .into_iter()
            .map(|t| Ok(serde_json::from_value(serde_json::Value::String(t))?))
            .collect()
    }

    /// Konto nach Anmeldename, mit Rollen.
    pub async fn benutzer(&self, username: &str) -> Result<Option<User>, StoreError> {
        let zeile: Option<Kontozeile> = sqlx::query_as(
            "SELECT id, username, display_name, kind, active, created_at, created_by \
                 FROM app_user WHERE username = $1",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;
        let Some((id, username, display_name, kind, active, created_at, created_by)) = zeile else {
            return Ok(None);
        };
        Ok(Some(User {
            id: ActorId(id),
            username,
            display_name,
            kind: serde_json::from_value(serde_json::Value::String(kind))?,
            active,
            created_at,
            created_by: created_by.map(ActorId),
            roles: self.rollen(ActorId(id)).await?,
        }))
    }

    /// Ob `akteur` Konten und Rollen verwalten darf: aktiv und
    /// Administrator. Solange es kein aktives menschliches
    /// Administratorkonto gibt, darf das Systemkonto der Kommandozeile das
    /// erste anlegen.
    async fn darf_verwalten(&self, akteur: ActorId) -> Result<bool, StoreError> {
        let admin: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM user_role r JOIN app_user u ON u.id = r.user_id \
             WHERE r.user_id = $1 AND r.role = 'administrator' AND u.active)",
        )
        .bind(akteur.0)
        .fetch_one(&self.pool)
        .await?;
        if admin {
            return Ok(true);
        }
        if akteur != ActorId::cli() {
            return Ok(false);
        }
        let gibt_admin: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM user_role r JOIN app_user u ON u.id = r.user_id \
             WHERE r.role = 'administrator' AND u.active AND u.kind = 'human')",
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(!gibt_admin)
    }

    /// Protokolliert eine Ablehnung in eigener Transaktion und liefert den
    /// passenden Fehler.
    async fn verweigert(&self, e: AuditEintrag, grund: &str) -> StoreError {
        if let Err(f) = self.audit(&e).await {
            return f;
        }
        StoreError::Verweigert(grund.to_string())
    }

    /// Legt ein Konto mit Rollen an.
    pub async fn benutzer_anlegen(
        &self,
        akteur: ActorId,
        n: &NeuerBenutzer<'_>,
    ) -> Result<User, StoreError> {
        let mut rollen: Vec<Role> = n.rollen.to_vec();
        rollen.sort();
        rollen.dedup();
        let rollen_text: Vec<String> = rollen
            .iter()
            .map(|r| rollentext(*r))
            .collect::<Result<_, _>>()?;
        let eintrag = |ergebnis, details| AuditEintrag {
            akteur,
            case_id: None,
            aktion: AuditAction::UserCreate,
            objekt_typ: "user",
            objekt_id: Some(n.username.to_string()),
            ergebnis,
            details,
        };
        if !self.darf_verwalten(akteur).await? {
            return Err(self
                .verweigert(
                    eintrag(AuditResult::Denied, json!({"rollen": rollen_text})),
                    "nur Administratoren verwalten Konten",
                )
                .await);
        }
        let hash = match (n.kind, n.passwort) {
            (UserKind::Human, Some(p)) if p.chars().count() >= PASSWORT_MINDESTLAENGE => Some(
                Argon2::default()
                    .hash_password(p.as_bytes())
                    .map_err(|e| StoreError::Passwort(e.to_string()))?
                    .to_string(),
            ),
            (UserKind::Human, _) => {
                return Err(StoreError::Passwort(format!(
                    "Konto für Menschen braucht ein Passwort mit mindestens \
                     {PASSWORT_MINDESTLAENGE} Zeichen"
                )))
            }
            (UserKind::Service, None) => None,
            (UserKind::Service, Some(_)) => {
                return Err(StoreError::Passwort(
                    "Dienstkonten haben kein Passwort".into(),
                ))
            }
        };
        let user = User {
            id: ActorId::new(),
            username: n.username.to_string(),
            display_name: n.display_name.to_string(),
            kind: n.kind,
            active: true,
            created_at: Utc::now(),
            created_by: Some(akteur),
            roles: rollen.clone(),
        };
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO app_user (id, username, display_name, kind, password_hash, active, \
             created_at, created_by) VALUES ($1, $2, $3, $4, $5, true, $6, $7)",
        )
        .bind(user.id.0)
        .bind(&user.username)
        .bind(&user.display_name)
        .bind(if n.kind == UserKind::Human {
            "human"
        } else {
            "service"
        })
        .bind(hash)
        .bind(user.created_at)
        .bind(akteur.0)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO user_role (user_id, role, granted_at, granted_by) \
             SELECT $1, r, $2, $3 FROM unnest($4::text[]) AS r",
        )
        .bind(user.id.0)
        .bind(user.created_at)
        .bind(akteur.0)
        .bind(&rollen_text)
        .execute(&mut *tx)
        .await?;
        audit::schreiben(
            &mut tx,
            &AuditEintrag {
                objekt_id: Some(user.id.to_string()),
                ..eintrag(
                    AuditResult::Success,
                    json!({"username": user.username, "art": n.kind, "rollen": rollen_text}),
                )
            },
        )
        .await?;
        tx.commit().await?;
        Ok(user)
    }

    /// Vergibt (`vergeben = true`) oder entzieht eine Rolle.
    pub async fn rolle_setzen(
        &self,
        akteur: ActorId,
        user: ActorId,
        rolle: Role,
        vergeben: bool,
    ) -> Result<bool, StoreError> {
        let eintrag = |ergebnis| AuditEintrag {
            akteur,
            case_id: None,
            aktion: if vergeben {
                AuditAction::RoleGrant
            } else {
                AuditAction::RoleRevoke
            },
            objekt_typ: "user",
            objekt_id: Some(user.to_string()),
            ergebnis,
            details: json!({"rolle": rolle}),
        };
        if !self.darf_verwalten(akteur).await? {
            return Err(self
                .verweigert(
                    eintrag(AuditResult::Denied),
                    "nur Administratoren verwalten Rollen",
                )
                .await);
        }
        let mut tx = self.pool.begin().await?;
        let geaendert = if vergeben {
            sqlx::query(
                "INSERT INTO user_role (user_id, role, granted_at, granted_by) \
                 VALUES ($1, $2, now(), $3) ON CONFLICT DO NOTHING",
            )
            .bind(user.0)
            .bind(rollentext(rolle)?)
            .bind(akteur.0)
            .execute(&mut *tx)
            .await?
            .rows_affected()
        } else {
            // DELETE ist der Anwendung nicht erlaubt; ein Entzug läuft über
            // die Funktion mit den Rechten des Eigentümers (Migration 0004).
            sqlx::query_scalar::<_, i64>("SELECT rolle_entziehen($1, $2)")
                .bind(user.0)
                .bind(rollentext(rolle)?)
                .fetch_one(&mut *tx)
                .await? as u64
        };
        if geaendert > 0 {
            audit::schreiben(&mut tx, &eintrag(AuditResult::Success)).await?;
        }
        tx.commit().await?;
        Ok(geaendert > 0)
    }

    /// Meldet ein Konto an. Abgelehnt werden unbekannte Namen, deaktivierte
    /// Konten, Dienstkonten und falsche Passwörter, jeweils mit Audit, ohne
    /// nach außen zu verraten, welcher Grund vorlag.
    pub async fn anmelden(&self, username: &str, passwort: &str) -> Result<User, StoreError> {
        let zeile: Option<(uuid::Uuid, Option<String>, bool)> =
            sqlx::query_as("SELECT id, password_hash, active FROM app_user WHERE username = $1")
                .bind(username)
                .fetch_optional(&self.pool)
                .await?;
        let (akteur, hash, aktiv) = match &zeile {
            Some((id, h, a)) => (ActorId(*id), h.as_deref(), *a),
            None => (ActorId::unbekannt(), None, false),
        };
        // Immer einmal prüfen, damit die Dauer nichts verrät.
        let passt = Argon2::default()
            .verify_password(passwort.as_bytes(), hash.unwrap_or(ATTRAPPE))
            .is_ok();
        let erfolg = zeile.is_some() && aktiv && hash.is_some() && passt;
        let grund = match (&zeile, aktiv, hash.is_some(), passt) {
            (None, _, _, _) => "unbekannter_name",
            (_, false, _, _) => "konto_deaktiviert",
            (_, _, false, _) => "kein_passwort",
            (_, _, _, false) => "passwort_falsch",
            _ => "",
        };
        let e = AuditEintrag {
            akteur,
            case_id: None,
            aktion: AuditAction::Login,
            objekt_typ: "user",
            objekt_id: Some(username.to_string()),
            ergebnis: if erfolg {
                AuditResult::Success
            } else {
                AuditResult::Denied
            },
            details: if erfolg {
                json!({})
            } else {
                json!({"grund": grund})
            },
        };
        self.audit(&e).await?;
        if !erfolg {
            return Err(StoreError::Verweigert("Anmeldung abgelehnt".into()));
        }
        self.benutzer(username)
            .await?
            .ok_or_else(|| StoreError::Verweigert("Anmeldung abgelehnt".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attrappe_ist_gueltiger_hash() {
        // Muss parsebar sein, sonst wäre die Prüfung bei unbekanntem Namen
        // schneller als bei bekanntem.
        assert!(argon2::password_hash::phc::PasswordHash::new(ATTRAPPE).is_ok());
        assert!(Argon2::default()
            .verify_password(b"irgendwas", ATTRAPPE)
            .is_err());
    }
}
