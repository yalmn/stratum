//! Konten, frei definierbare Rollen, Berechtigungen und Anmeldung.
//!
//! Ablauf: Menschen registrieren sich selbst (`pending`), ein Superadmin
//! gibt das Konto frei und vergibt Rollen. Rollen sind Bündel aus dem festen
//! Katalog [`Permission`]; Superadmins legen sie an und ändern sie.
//! Superadmins dürfen alles; es bleibt immer mindestens einer aktiv. Den
//! ersten richtet das Systemkonto der Kommandozeile ein.
//!
//! Passwörter: Argon2id (Standardparameter von `argon2`, zufälliges Salz)
//! im PHC-Format. Jede Änderung an Konten und Rollen und jede Anmeldung, auch
//! eine abgelehnte, steht im Audit.

use argon2::password_hash::PasswordHasher;
use argon2::{Argon2, PasswordVerifier};
use chrono::Utc;
use serde_json::{json, Value};
use stratum_model::{
    ActorId, AuditAction, AuditResult, Permission, Role, RoleId, User, UserKind, UserStatus,
};

use crate::audit::{self, AuditEintrag};
use crate::{Datenbank, StoreError};

/// Mindestlänge eines Passworts.
pub const PASSWORT_MINDESTLAENGE: usize = 12;

/// Gültiger PHC-Hash für ein nie vergebenes Passwort. Bei unbekanntem Namen
/// wird dagegen geprüft, damit die Antwortzeit nicht verrät, ob es ein Konto
/// gibt.
const ATTRAPPE: &str =
    "$argon2id$v=19$m=19456,t=2,p=1$c3RyYXR1bWF0dHJhcHBl$x3k3jmy3XsMPQ0V1XX+Fq/qxHZwzLMd4P6mP0n1eBJ0";

/// Zeile aus `app_user`: id, username, display_name, kind, status,
/// superadmin, created_at.
type Kontozeile = (
    uuid::Uuid,
    String,
    String,
    String,
    String,
    bool,
    chrono::DateTime<Utc>,
);

fn aus_text<T: serde::de::DeserializeOwned>(t: String) -> Result<T, StoreError> {
    Ok(serde_json::from_value(Value::String(t))?)
}

fn als_text<T: serde::Serialize>(v: &T) -> Result<String, StoreError> {
    match serde_json::to_value(v)? {
        Value::String(s) => Ok(s),
        _ => Err(StoreError::Wert("Aufzählung ohne Textform")),
    }
}

fn passwort_hash(p: &str) -> Result<String, StoreError> {
    if p.chars().count() < PASSWORT_MINDESTLAENGE {
        return Err(StoreError::Passwort(format!(
            "mindestens {PASSWORT_MINDESTLAENGE} Zeichen"
        )));
    }
    Ok(Argon2::default()
        .hash_password(p.as_bytes())
        .map_err(|e| StoreError::Passwort(e.to_string()))?
        .to_string())
}

/// Prüft einen Anmeldenamen wie die Datenbank (`^[a-z0-9._-]{1,64}$`),
/// aber mit verständlicher Meldung.
pub fn anmeldename_pruefen(name: &str) -> Result<(), StoreError> {
    let gueltig = (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b));
    if gueltig {
        return Ok(());
    }
    let klein = name.to_lowercase();
    let hinweis = if klein != name
        && klein
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
    {
        format!(" (etwa {klein})")
    } else {
        String::new()
    };
    Err(StoreError::Eingabe(format!(
        "Anmeldename {name:?} ungültig: nur Kleinbuchstaben a-z, Ziffern und . _ -, \
         1 bis 64 Zeichen{hinweis}"
    )))
}

fn rechte_namen(rechte: &[Permission]) -> Vec<&'static str> {
    let mut n: Vec<_> = rechte.iter().map(|p| p.name()).collect();
    n.sort_unstable();
    n.dedup();
    n
}

fn vergeben(e: &sqlx::Error, was: &str) -> Option<StoreError> {
    match e.as_database_error().and_then(|d| d.code()) {
        Some(c) if c == "23505" => Some(StoreError::Verweigert(format!("{was} vergeben"))),
        _ => None,
    }
}

fn eintrag(
    akteur: ActorId,
    aktion: AuditAction,
    objekt_typ: &'static str,
    objekt_id: impl ToString,
    ergebnis: AuditResult,
    details: Value,
) -> AuditEintrag {
    AuditEintrag {
        akteur,
        case_id: None,
        aktion,
        objekt_typ,
        objekt_id: Some(objekt_id.to_string()),
        ergebnis,
        details,
    }
}

impl Datenbank {
    /// Konto nach Anmeldename, mit Rollen.
    pub async fn benutzer(&self, username: &str) -> Result<Option<User>, StoreError> {
        let zeile: Option<Kontozeile> = sqlx::query_as(
            "SELECT id, username, display_name, kind, status, superadmin, created_at \
             FROM app_user WHERE username = $1",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;
        let Some((id, username, display_name, kind, status, superadmin, created_at)) = zeile else {
            return Ok(None);
        };
        let rollen: Vec<uuid::Uuid> =
            sqlx::query_scalar("SELECT role_id FROM user_role WHERE user_id = $1 ORDER BY role_id")
                .bind(id)
                .fetch_all(&self.pool)
                .await?;
        Ok(Some(User {
            id: ActorId(id),
            username,
            display_name,
            kind: aus_text(kind)?,
            status: aus_text(status)?,
            superadmin,
            created_at,
            roles: rollen.into_iter().map(RoleId).collect(),
        }))
    }

    /// Alle Konten mit Rollen, nach Anmeldename. Nur für Superadmins; der
    /// Lesezugriff steht im Audit.
    pub async fn konten(&self, akteur: ActorId) -> Result<Vec<User>, StoreError> {
        let e = eintrag(
            akteur,
            AuditAction::UserList,
            "user",
            "*",
            AuditResult::Success,
            json!({}),
        );
        self.nur_superadmin(akteur, &e).await?;
        let namen: Vec<String> =
            sqlx::query_scalar("SELECT username FROM app_user ORDER BY username")
                .fetch_all(&self.pool)
                .await?;
        let mut out = Vec::with_capacity(namen.len());
        for n in namen {
            if let Some(u) = self.benutzer(&n).await? {
                out.push(u);
            }
        }
        self.audit(&AuditEintrag {
            details: json!({"anzahl": out.len()}),
            ..e
        })
        .await?;
        Ok(out)
    }

    /// Alle Rollen mit ihren Berechtigungen, nach Name.
    pub async fn rollen(&self) -> Result<Vec<Role>, StoreError> {
        let zeilen: Vec<(uuid::Uuid, String, Option<String>, Vec<String>)> = sqlx::query_as(
            "SELECT r.id, r.name, r.description, \
             COALESCE(array_agg(p.permission ORDER BY p.permission) \
               FILTER (WHERE p.permission IS NOT NULL), '{}') \
             FROM app_role r LEFT JOIN role_permission p ON p.role_id = r.id \
             GROUP BY r.id ORDER BY r.name",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(zeilen
            .into_iter()
            .map(|(id, name, description, rechte)| Role {
                id: RoleId(id),
                name,
                description,
                permissions: rechte
                    .iter()
                    .filter_map(|r| Permission::from_name(r))
                    .collect(),
            })
            .collect())
    }

    /// Wirksame Berechtigungen eines Kontos: keine, wenn es nicht aktiv ist;
    /// alle für Superadmins; sonst die Vereinigung seiner Rollen.
    pub async fn rechte(&self, akteur: ActorId) -> Result<Vec<Permission>, StoreError> {
        let zeile: Option<(String, bool)> =
            sqlx::query_as("SELECT status, superadmin FROM app_user WHERE id = $1")
                .bind(akteur.0)
                .fetch_optional(&self.pool)
                .await?;
        match zeile {
            Some((s, _)) if s != "active" => Ok(Vec::new()),
            Some((_, true)) => Ok(Permission::ALL.to_vec()),
            Some(_) => {
                let namen: Vec<String> = sqlx::query_scalar(
                    "SELECT DISTINCT p.permission FROM user_role u \
                     JOIN role_permission p ON p.role_id = u.role_id \
                     WHERE u.user_id = $1 ORDER BY 1",
                )
                .bind(akteur.0)
                .fetch_all(&self.pool)
                .await?;
                Ok(namen
                    .iter()
                    .filter_map(|n| Permission::from_name(n))
                    .collect())
            }
            None => Ok(Vec::new()),
        }
    }

    /// Ob `akteur` die Berechtigung hat.
    pub async fn berechtigt(&self, akteur: ActorId, p: Permission) -> Result<bool, StoreError> {
        let ja: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM app_user u WHERE u.id = $1 AND u.status = 'active' \
             AND (u.superadmin OR EXISTS (SELECT 1 FROM user_role r \
               JOIN role_permission p ON p.role_id = r.role_id \
               WHERE r.user_id = u.id AND p.permission = $2)))",
        )
        .bind(akteur.0)
        .bind(p.name())
        .fetch_one(&self.pool)
        .await?;
        Ok(ja)
    }

    /// Prüft eine Berechtigung; ohne sie wird `abgelehnt` (mit Ergebnis
    /// `denied` und der fehlenden Berechtigung) protokolliert. Auch für
    /// Vorabprüfungen, bevor eine lange Arbeit beginnt.
    pub async fn verlangen(
        &self,
        akteur: ActorId,
        p: Permission,
        mut abgelehnt: AuditEintrag,
    ) -> Result<(), StoreError> {
        if self.berechtigt(akteur, p).await? {
            return Ok(());
        }
        abgelehnt.ergebnis = AuditResult::Denied;
        match &mut abgelehnt.details {
            Value::Object(d) => {
                d.insert("fehlende_berechtigung".into(), p.name().into());
            }
            d => *d = json!({"fehlende_berechtigung": p.name()}),
        }
        self.audit(&abgelehnt).await?;
        Err(StoreError::Verweigert(format!(
            "Berechtigung {} fehlt",
            p.name()
        )))
    }

    async fn ist_superadmin(&self, akteur: ActorId) -> Result<bool, StoreError> {
        Ok(sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM app_user WHERE id = $1 AND superadmin \
             AND status = 'active')",
        )
        .bind(akteur.0)
        .fetch_one(&self.pool)
        .await?)
    }

    /// Nur Superadmins verwalten Konten und Rollen; sonst Ablehnung mit
    /// Audit.
    async fn nur_superadmin(&self, akteur: ActorId, e: &AuditEintrag) -> Result<(), StoreError> {
        if self.ist_superadmin(akteur).await? {
            return Ok(());
        }
        self.audit(&AuditEintrag {
            ergebnis: AuditResult::Denied,
            ..e.clone()
        })
        .await?;
        Err(StoreError::Verweigert(
            "nur Superadmins verwalten Konten und Rollen".into(),
        ))
    }

    async fn aktive_superadmins(&self) -> Result<i64, StoreError> {
        Ok(sqlx::query_scalar(
            "SELECT count(*) FROM app_user WHERE superadmin AND status = 'active'",
        )
        .fetch_one(&self.pool)
        .await?)
    }

    /// Richtet einen Superadmin ein. Erlaubt einem aktiven Superadmin, und
    /// dem Systemkonto der Kommandozeile nur, solange es keinen aktiven
    /// Superadmin gibt (erste Einrichtung).
    pub async fn superadmin_einrichten(
        &self,
        akteur: ActorId,
        username: &str,
        display_name: &str,
        passwort: &str,
    ) -> Result<User, StoreError> {
        let e = eintrag(
            akteur,
            AuditAction::UserCreate,
            "user",
            username,
            AuditResult::Success,
            json!({"superadmin": true}),
        );
        anmeldename_pruefen(username)?;
        let erste = akteur == ActorId::cli() && self.aktive_superadmins().await? == 0;
        if !erste {
            self.nur_superadmin(akteur, &e).await?;
        }
        let u = User {
            id: ActorId::new(),
            username: username.into(),
            display_name: display_name.into(),
            kind: UserKind::Human,
            status: UserStatus::Active,
            superadmin: true,
            created_at: Utc::now(),
            roles: Vec::new(),
        };
        let hash = passwort_hash(passwort)?;
        let mut tx = self.pool.begin().await?;
        konto_einfuegen(&mut tx, &u, Some(hash), Some(akteur)).await?;
        audit::schreiben(
            &mut tx,
            &AuditEintrag {
                objekt_id: Some(u.id.to_string()),
                details: json!({"username": username, "superadmin": true,
                                "erste_einrichtung": erste}),
                ..e
            },
        )
        .await?;
        tx.commit().await?;
        Ok(u)
    }

    /// Registriert ein Konto für einen Menschen. Es bleibt ohne Rechte und
    /// ohne Anmeldung (`pending`), bis ein Superadmin es freigibt.
    pub async fn registrieren(
        &self,
        username: &str,
        display_name: &str,
        passwort: &str,
    ) -> Result<User, StoreError> {
        anmeldename_pruefen(username)?;
        let hash = passwort_hash(passwort)?;
        let u = User {
            id: ActorId::new(),
            username: username.into(),
            display_name: display_name.into(),
            kind: UserKind::Human,
            status: UserStatus::Pending,
            superadmin: false,
            created_at: Utc::now(),
            roles: Vec::new(),
        };
        let mut tx = self.pool.begin().await?;
        if let Err(f) = konto_einfuegen(&mut tx, &u, Some(hash), None).await {
            tx.rollback().await?;
            self.audit(&eintrag(
                ActorId::unbekannt(),
                AuditAction::UserRegister,
                "user",
                username,
                AuditResult::Denied,
                json!({"grund": f.to_string()}),
            ))
            .await?;
            return Err(f);
        }
        audit::schreiben(
            &mut tx,
            &eintrag(
                u.id,
                AuditAction::UserRegister,
                "user",
                u.id,
                AuditResult::Success,
                json!({"username": username, "display_name": display_name}),
            ),
        )
        .await?;
        tx.commit().await?;
        Ok(u)
    }

    /// Legt ein Dienstkonto (ohne Passwort) mit Rollen an.
    pub async fn dienstkonto_anlegen(
        &self,
        akteur: ActorId,
        username: &str,
        display_name: &str,
        rollen: &[RoleId],
    ) -> Result<User, StoreError> {
        let e = eintrag(
            akteur,
            AuditAction::UserCreate,
            "user",
            username,
            AuditResult::Success,
            json!({"art": "service", "rollen": rollen}),
        );
        self.nur_superadmin(akteur, &e).await?;
        let u = User {
            id: ActorId::new(),
            username: username.into(),
            display_name: display_name.into(),
            kind: UserKind::Service,
            status: UserStatus::Active,
            superadmin: false,
            created_at: Utc::now(),
            roles: rollen.to_vec(),
        };
        let mut tx = self.pool.begin().await?;
        konto_einfuegen(&mut tx, &u, None, Some(akteur)).await?;
        rollen_schreiben(&mut tx, u.id, rollen, akteur).await?;
        audit::schreiben(
            &mut tx,
            &AuditEintrag {
                objekt_id: Some(u.id.to_string()),
                ..e
            },
        )
        .await?;
        tx.commit().await?;
        Ok(u)
    }

    /// Ändert den Stand eines Kontos (Freigabe, Ablehnung, Sperre).
    async fn stand_setzen(
        &self,
        akteur: ActorId,
        user: ActorId,
        aktion: AuditAction,
        von: &[&str],
        nach: UserStatus,
        rollen: Option<&[RoleId]>,
    ) -> Result<(), StoreError> {
        let e = eintrag(
            akteur,
            aktion,
            "user",
            user,
            AuditResult::Success,
            json!({"rollen": rollen}),
        );
        self.nur_superadmin(akteur, &e).await?;
        if nach == UserStatus::Disabled
            && self.ist_superadmin(user).await?
            && self.aktive_superadmins().await? <= 1
        {
            return Err(StoreError::Verweigert(
                "der letzte aktive Superadmin kann nicht gesperrt werden".into(),
            ));
        }
        let mut tx = self.pool.begin().await?;
        let geaendert = sqlx::query(
            "UPDATE app_user SET status = $2, decided_at = now(), decided_by = $3 \
             WHERE id = $1 AND status = ANY($4)",
        )
        .bind(user.0)
        .bind(als_text(&nach)?)
        .bind(akteur.0)
        .bind(von)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if geaendert != 1 {
            return Err(StoreError::Verweigert(format!(
                "Konto nicht im Stand {}",
                von.join(" oder ")
            )));
        }
        if let Some(r) = rollen {
            rollen_schreiben(&mut tx, user, r, akteur).await?;
        }
        audit::schreiben(&mut tx, &e).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Gibt ein registriertes (oder gesperrtes) Konto frei und setzt seine
    /// Rollen.
    pub async fn freigeben(
        &self,
        akteur: ActorId,
        user: ActorId,
        rollen: &[RoleId],
    ) -> Result<(), StoreError> {
        self.stand_setzen(
            akteur,
            user,
            AuditAction::UserApprove,
            &["pending", "disabled"],
            UserStatus::Active,
            Some(rollen),
        )
        .await
    }

    /// Lehnt eine Registrierung ab.
    pub async fn ablehnen(&self, akteur: ActorId, user: ActorId) -> Result<(), StoreError> {
        self.stand_setzen(
            akteur,
            user,
            AuditAction::UserReject,
            &["pending"],
            UserStatus::Rejected,
            None,
        )
        .await
    }

    /// Sperrt ein Konto. Der letzte aktive Superadmin lässt sich nicht
    /// sperren.
    pub async fn sperren(&self, akteur: ActorId, user: ActorId) -> Result<(), StoreError> {
        self.stand_setzen(
            akteur,
            user,
            AuditAction::UserDisable,
            &["active"],
            UserStatus::Disabled,
            None,
        )
        .await
    }

    /// Vergibt oder entzieht das Superadmin-Recht (nur aktiven Menschen; dem
    /// letzten aktiven Superadmin nicht).
    pub async fn superadmin_setzen(
        &self,
        akteur: ActorId,
        user: ActorId,
        ja: bool,
    ) -> Result<(), StoreError> {
        let e = eintrag(
            akteur,
            AuditAction::SuperadminSet,
            "user",
            user,
            AuditResult::Success,
            json!({"superadmin": ja}),
        );
        self.nur_superadmin(akteur, &e).await?;
        if !ja && self.ist_superadmin(user).await? && self.aktive_superadmins().await? <= 1 {
            return Err(StoreError::Verweigert(
                "der letzte aktive Superadmin bleibt Superadmin".into(),
            ));
        }
        let mut tx = self.pool.begin().await?;
        let n = sqlx::query(
            "UPDATE app_user SET superadmin = $2 WHERE id = $1 AND kind = 'human' \
             AND status = 'active' AND superadmin <> $2",
        )
        .bind(user.0)
        .bind(ja)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if n == 1 {
            audit::schreiben(&mut tx, &e).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Setzt die Rollen eines Kontos auf genau die gegebene Menge.
    pub async fn konto_rollen_setzen(
        &self,
        akteur: ActorId,
        user: ActorId,
        rollen: &[RoleId],
    ) -> Result<(), StoreError> {
        let e = eintrag(
            akteur,
            AuditAction::RoleGrant,
            "user",
            user,
            AuditResult::Denied,
            json!({"rollen": rollen}),
        );
        self.nur_superadmin(akteur, &e).await?;
        let mut tx = self.pool.begin().await?;
        rollen_schreiben(&mut tx, user, rollen, akteur).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Legt eine Rolle an.
    pub async fn rolle_anlegen(
        &self,
        akteur: ActorId,
        name: &str,
        beschreibung: Option<&str>,
        rechte: &[Permission],
    ) -> Result<Role, StoreError> {
        let namen = rechte_namen(rechte);
        let e = eintrag(
            akteur,
            AuditAction::RoleCreate,
            "role",
            name,
            AuditResult::Success,
            json!({"name": name, "rechte": namen}),
        );
        self.nur_superadmin(akteur, &e).await?;
        let r = Role {
            id: RoleId::new(),
            name: name.into(),
            description: beschreibung.map(Into::into),
            permissions: rechte.to_vec(),
        };
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO app_role (id, name, description, created_at, created_by) \
             VALUES ($1, $2, $3, now(), $4)",
        )
        .bind(r.id.0)
        .bind(name)
        .bind(beschreibung)
        .bind(akteur.0)
        .execute(&mut *tx)
        .await
        .map_err(|f| vergeben(&f, "Rollenname").unwrap_or(f.into()))?;
        sqlx::query("SELECT rolle_rechte_setzen($1, $2)")
            .bind(r.id.0)
            .bind(&namen)
            .execute(&mut *tx)
            .await?;
        audit::schreiben(
            &mut tx,
            &AuditEintrag {
                objekt_id: Some(r.id.to_string()),
                ..e
            },
        )
        .await?;
        tx.commit().await?;
        Ok(r)
    }

    /// Ändert Name, Beschreibung und Berechtigungen einer Rolle. Im Audit
    /// stehen die Berechtigungen vorher und nachher.
    pub async fn rolle_aendern(
        &self,
        akteur: ActorId,
        rolle: RoleId,
        name: &str,
        beschreibung: Option<&str>,
        rechte: &[Permission],
    ) -> Result<(), StoreError> {
        let namen = rechte_namen(rechte);
        let mut e = eintrag(
            akteur,
            AuditAction::RoleModify,
            "role",
            rolle,
            AuditResult::Success,
            json!({"name": name, "rechte": namen}),
        );
        self.nur_superadmin(akteur, &e).await?;
        let mut tx = self.pool.begin().await?;
        let vorher: Vec<String> = sqlx::query_scalar(
            "SELECT permission FROM role_permission WHERE role_id = $1 ORDER BY 1",
        )
        .bind(rolle.0)
        .fetch_all(&mut *tx)
        .await?;
        let n = sqlx::query(
            "UPDATE app_role SET name = $2, description = $3, updated_at = now() WHERE id = $1",
        )
        .bind(rolle.0)
        .bind(name)
        .bind(beschreibung)
        .execute(&mut *tx)
        .await
        .map_err(|f| vergeben(&f, "Rollenname").unwrap_or(f.into()))?
        .rows_affected();
        if n != 1 {
            return Err(StoreError::Verweigert("Rolle unbekannt".into()));
        }
        sqlx::query("SELECT rolle_rechte_setzen($1, $2)")
            .bind(rolle.0)
            .bind(&namen)
            .execute(&mut *tx)
            .await?;
        e.details = json!({"name": name, "rechte_vorher": vorher, "rechte": namen});
        audit::schreiben(&mut tx, &e).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Löscht eine Rolle; Konten verlieren sie.
    pub async fn rolle_loeschen(&self, akteur: ActorId, rolle: RoleId) -> Result<(), StoreError> {
        let mut e = eintrag(
            akteur,
            AuditAction::RoleDelete,
            "role",
            rolle,
            AuditResult::Success,
            json!({}),
        );
        self.nur_superadmin(akteur, &e).await?;
        let mut tx = self.pool.begin().await?;
        let name: Option<String> = sqlx::query_scalar("SELECT name FROM app_role WHERE id = $1")
            .bind(rolle.0)
            .fetch_optional(&mut *tx)
            .await?;
        let Some(name) = name else {
            return Err(StoreError::Verweigert("Rolle unbekannt".into()));
        };
        let konten: i64 = sqlx::query_scalar("SELECT rolle_loeschen($1)")
            .bind(rolle.0)
            .fetch_one(&mut *tx)
            .await?;
        e.details = json!({"name": name, "betroffene_konten": konten});
        audit::schreiben(&mut tx, &e).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Ändert ein Passwort. Das eigene nur mit dem bisherigen Passwort,
    /// das eines anderen Kontos nur als Superadmin. Alle offenen Sitzungen
    /// des Kontos enden; im Audit steht die Änderung, nie das Passwort.
    pub async fn passwort_aendern(
        &self,
        akteur: ActorId,
        username: &str,
        bisher: Option<&str>,
        neu: &str,
    ) -> Result<(), StoreError> {
        let ziel: Option<(uuid::Uuid, Option<String>)> =
            sqlx::query_as("SELECT id, password_hash FROM app_user WHERE username = $1")
                .bind(username)
                .fetch_optional(&self.pool)
                .await?;
        let Some((id, hash)) = ziel else {
            return Err(StoreError::NichtGefunden(format!("kein Konto {username}")));
        };
        let user = ActorId(id);
        let e = eintrag(
            akteur,
            AuditAction::PasswordChange,
            "user",
            user,
            AuditResult::Success,
            json!({"eigenes": akteur == user}),
        );
        if akteur == user {
            let passt = match (bisher, hash.as_deref()) {
                (Some(b), Some(h)) => Argon2::default().verify_password(b.as_bytes(), h).is_ok(),
                _ => false,
            };
            if !passt {
                self.audit(&AuditEintrag {
                    ergebnis: AuditResult::Denied,
                    details: json!({"eigenes": true, "grund": "bisheriges_passwort_falsch"}),
                    ..e
                })
                .await?;
                return Err(StoreError::Verweigert("bisheriges Passwort falsch".into()));
            }
        } else {
            self.nur_superadmin(akteur, &e).await?;
        }
        if hash.is_none() {
            return Err(StoreError::Eingabe(
                "Dienstkonten haben kein Passwort".into(),
            ));
        }
        let neu_hash = passwort_hash(neu)?;
        let mut tx = self.pool.begin().await?;
        sqlx::query("UPDATE app_user SET password_hash = $2 WHERE id = $1")
            .bind(id)
            .bind(neu_hash)
            .execute(&mut *tx)
            .await?;
        let beendet = sqlx::query(
            "UPDATE app_session SET ended_at = now() WHERE user_id = $1 AND ended_at IS NULL",
        )
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        audit::schreiben(
            &mut tx,
            &AuditEintrag {
                details: json!({"eigenes": akteur == user, "beendete_sitzungen": beendet}),
                ..e
            },
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Meldet ein Konto an. Abgelehnt werden unbekannte Namen, nicht
    /// freigegebene oder gesperrte Konten, Dienstkonten und falsche
    /// Passwörter, jeweils mit Audit, ohne nach außen zu verraten, welcher
    /// Grund vorlag.
    pub async fn anmelden(&self, username: &str, passwort: &str) -> Result<User, StoreError> {
        let zeile: Option<(uuid::Uuid, Option<String>, String)> =
            sqlx::query_as("SELECT id, password_hash, status FROM app_user WHERE username = $1")
                .bind(username)
                .fetch_optional(&self.pool)
                .await?;
        let (akteur, hash, status) = match &zeile {
            Some((id, h, s)) => (ActorId(*id), h.as_deref(), s.as_str()),
            None => (ActorId::unbekannt(), None, ""),
        };
        // Immer einmal prüfen, damit die Dauer nichts verrät.
        let passt = Argon2::default()
            .verify_password(passwort.as_bytes(), hash.unwrap_or(ATTRAPPE))
            .is_ok();
        let grund = if zeile.is_none() {
            Some("unbekannter_name")
        } else if status != "active" {
            Some(match status {
                "pending" => "nicht_freigegeben",
                "rejected" => "abgelehnt",
                _ => "gesperrt",
            })
        } else if hash.is_none() {
            Some("kein_passwort")
        } else if !passt {
            Some("passwort_falsch")
        } else {
            None
        };
        self.audit(&eintrag(
            akteur,
            AuditAction::Login,
            "user",
            username,
            if grund.is_none() {
                AuditResult::Success
            } else {
                AuditResult::Denied
            },
            match grund {
                Some(g) => json!({"grund": g}),
                None => json!({}),
            },
        ))
        .await?;
        if grund.is_some() {
            return Err(StoreError::Verweigert("Anmeldung abgelehnt".into()));
        }
        self.benutzer(username)
            .await?
            .ok_or_else(|| StoreError::Verweigert("Anmeldung abgelehnt".into()))
    }
}

async fn konto_einfuegen(
    tx: &mut sqlx::PgConnection,
    u: &User,
    hash: Option<String>,
    durch: Option<ActorId>,
) -> Result<(), StoreError> {
    anmeldename_pruefen(&u.username)?;
    let entschieden = u.status != UserStatus::Pending;
    sqlx::query(
        "INSERT INTO app_user (id, username, display_name, kind, password_hash, status, \
         superadmin, created_at, created_by, decided_at, decided_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
    )
    .bind(u.id.0)
    .bind(&u.username)
    .bind(&u.display_name)
    .bind(als_text(&u.kind)?)
    .bind(hash)
    .bind(als_text(&u.status)?)
    .bind(u.superadmin)
    .bind(u.created_at)
    .bind(durch.map(|a| a.0))
    .bind(entschieden.then_some(u.created_at))
    .bind(durch.filter(|_| entschieden).map(|a| a.0))
    .execute(&mut *tx)
    .await
    .map_err(|f| vergeben(&f, "Anmeldename").unwrap_or(f.into()))?;
    Ok(())
}

/// Setzt die Rollen eines Kontos und schreibt je vergebener und entzogener
/// Rolle ein Audit-Ereignis.
async fn rollen_schreiben(
    tx: &mut sqlx::PgConnection,
    user: ActorId,
    rollen: &[RoleId],
    akteur: ActorId,
) -> Result<(), StoreError> {
    let vorher: Vec<uuid::Uuid> =
        sqlx::query_scalar("SELECT role_id FROM user_role WHERE user_id = $1")
            .bind(user.0)
            .fetch_all(&mut *tx)
            .await?;
    let nachher: Vec<uuid::Uuid> = rollen.iter().map(|r| r.0).collect();
    sqlx::query("SELECT konto_rollen_setzen($1, $2, $3)")
        .bind(user.0)
        .bind(&nachher)
        .bind(akteur.0)
        .execute(&mut *tx)
        .await?;
    let vergeben = nachher
        .iter()
        .filter(|r| !vorher.contains(r))
        .map(|r| (AuditAction::RoleGrant, r));
    let entzogen = vorher
        .iter()
        .filter(|r| !nachher.contains(r))
        .map(|r| (AuditAction::RoleRevoke, r));
    for (aktion, rolle) in vergeben.chain(entzogen) {
        audit::schreiben(
            &mut *tx,
            &eintrag(
                akteur,
                aktion,
                "user",
                user,
                AuditResult::Success,
                json!({"rolle": rolle}),
            ),
        )
        .await?;
    }
    Ok(())
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

    #[test]
    fn anmeldenamen() {
        for n in ["mia", "h.yalman", "admin_2", "a-b"] {
            assert!(anmeldename_pruefen(n).is_ok(), "{n}");
        }
        for n in ["", "NAME", "mia müller", "ä", &"x".repeat(65)] {
            assert!(anmeldename_pruefen(n).is_err(), "{n}");
        }
        let f = anmeldename_pruefen("NAME").unwrap_err().to_string();
        assert!(f.contains("etwa name"), "{f}");
    }

    #[test]
    fn rechtenamen_sortiert_ohne_doppelte() {
        assert_eq!(
            rechte_namen(&[
                Permission::FileView,
                Permission::CaseView,
                Permission::FileView
            ]),
            ["case.view", "file.view"]
        );
    }
}
