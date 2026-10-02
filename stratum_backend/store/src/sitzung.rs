//! Sitzungen: nach der Anmeldung ein zufälliges Token (256 Bit), in der
//! Datenbank nur als SHA-256. Gültig bis zur Abmeldung, höchstens
//! [`SITZUNG_STUNDEN`] Stunden und nach [`UNTAETIG_MINUTEN`] Minuten ohne
//! Anfrage nicht mehr.

use serde_json::json;
use sha2::{Digest, Sha256};
use stratum_model::{AuditAction, AuditResult, User};

use crate::audit::AuditEintrag;
use crate::{Datenbank, StoreError};

/// Höchstdauer einer Sitzung.
pub const SITZUNG_STUNDEN: i64 = 12;
/// Untätigkeit, nach der eine Sitzung endet.
pub const UNTAETIG_MINUTEN: i64 = 60;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn token_hash(token: &str) -> String {
    hex(&Sha256::digest(token.as_bytes()))
}

impl Datenbank {
    /// Meldet an (wie [`Datenbank::anmelden`], mit Audit) und legt eine
    /// Sitzung an. Liefert das Token, das nur der Client erhält.
    pub async fn sitzung_anlegen(
        &self,
        username: &str,
        passwort: &str,
        client: Option<&str>,
    ) -> Result<(String, User), StoreError> {
        let user = self.anmelden(username, passwort).await?;
        let mut zufall = [0u8; 32];
        getrandom::fill(&mut zufall)
            .map_err(|e| StoreError::Eingabe(format!("kein Zufall verfügbar: {e}")))?;
        let token = hex(&zufall);
        sqlx::query(
            "INSERT INTO app_session (token_sha256, user_id, created_at, expires_at, \
             last_seen_at, client) \
             VALUES ($1, $2, now(), now() + make_interval(hours => $3), now(), $4)",
        )
        .bind(token_hash(&token))
        .bind(user.id.0)
        .bind(SITZUNG_STUNDEN as i32)
        .bind(client)
        .execute(&self.pool)
        .await?;
        Ok((token, user))
    }

    /// Konto zu einem Token, wenn die Sitzung gilt und das Konto aktiv ist.
    /// Frischt den Zeitpunkt der letzten Anfrage auf.
    pub async fn sitzung_pruefen(&self, token: &str) -> Result<Option<User>, StoreError> {
        let name: Option<String> = sqlx::query_scalar(
            "UPDATE app_session s SET last_seen_at = now() FROM app_user u \
             WHERE s.token_sha256 = $1 AND u.id = s.user_id AND u.status = 'active' \
             AND s.ended_at IS NULL AND s.expires_at > now() \
             AND s.last_seen_at > now() - make_interval(mins => $2) \
             RETURNING u.username",
        )
        .bind(token_hash(token))
        .bind(UNTAETIG_MINUTEN as i32)
        .fetch_optional(&self.pool)
        .await?;
        match name {
            Some(n) => self.benutzer(&n).await,
            None => Ok(None),
        }
    }

    /// Beendet eine Sitzung (Abmeldung, `LOGOUT` im Audit).
    pub async fn sitzung_beenden(&self, token: &str) -> Result<(), StoreError> {
        let user: Option<uuid::Uuid> = sqlx::query_scalar(
            "UPDATE app_session SET ended_at = now() \
             WHERE token_sha256 = $1 AND ended_at IS NULL RETURNING user_id",
        )
        .bind(token_hash(token))
        .fetch_optional(&self.pool)
        .await?;
        if let Some(u) = user {
            self.audit(&AuditEintrag {
                akteur: stratum_model::ActorId(u),
                case_id: None,
                aktion: AuditAction::Logout,
                objekt_typ: "user",
                objekt_id: Some(u.to_string()),
                ergebnis: AuditResult::Success,
                details: json!({}),
            })
            .await?;
        }
        Ok(())
    }
}
