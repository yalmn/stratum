//! Benutzer und Rollen (rollenbasierte Rechte von Anfang an).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::ids::ActorId;

/// Feste Rollen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Verwaltet Benutzer, Rollen und Einstellungen.
    Administrator,
    /// Legt Fälle an und verteilt Arbeit.
    CaseManager,
    /// Führt forensische Analysen durch.
    ForensicExaminer,
    /// Wertet Ergebnisse aus.
    Analyst,
    /// Bearbeitet Threat Intelligence.
    ThreatIntelAnalyst,
    /// Prüft Ergebnisse.
    Reviewer,
    /// Darf nur lesen.
    ReadOnly,
    /// Technisches Konto für automatische Abläufe.
    AutomationService,
}

impl Role {
    /// Alle Rollen.
    pub const ALL: [Role; 8] = [
        Role::Administrator,
        Role::CaseManager,
        Role::ForensicExaminer,
        Role::Analyst,
        Role::ThreatIntelAnalyst,
        Role::Reviewer,
        Role::ReadOnly,
        Role::AutomationService,
    ];

    /// Ob die Rolle sensible Zugangsdaten (Passwörter, Hashes, Schlüssel) im
    /// Klartext sehen darf. Nutzerentscheidung: nur Administrator und
    /// Forensic Examiner.
    pub fn may_view_sensitive_credentials(self) -> bool {
        matches!(self, Role::Administrator | Role::ForensicExaminer)
    }
}

/// Art eines Kontos.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserKind {
    /// Mensch, meldet sich mit Passwort an.
    Human,
    /// Dienst oder Werkzeug ohne Passwort (z. B. die Kommandozeile).
    Service,
}

/// Ein Benutzerkonto.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    /// ID; dieselbe wie in `created_by`, `imported_by` und im Audit.
    pub id: ActorId,
    /// Anmeldename (klein, `a-z 0-9 . _ -`).
    pub username: String,
    /// Anzeigename.
    pub display_name: String,
    /// Art.
    pub kind: UserKind,
    /// Aktiv; deaktivierte Konten bleiben für das Audit erhalten.
    pub active: bool,
    /// Angelegt am.
    pub created_at: DateTime<Utc>,
    /// Angelegt von.
    pub created_by: Option<ActorId>,
    /// Rollen.
    pub roles: Vec<Role>,
}
