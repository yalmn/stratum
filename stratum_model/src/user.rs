//! Benutzer, Rollen und Berechtigungen.
//!
//! Berechtigungen sind ein fester Katalog: stratum prüft genau diese. Rollen
//! sind frei benannte Bündel von Berechtigungen, die Superadmins anlegen,
//! ändern und vergeben. Superadmins dürfen alles, auch Konten und Rollen
//! verwalten; das hängt nicht an einer Rolle, damit sich niemand durch eine
//! Rollenänderung aussperrt.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::ids::{ActorId, RoleId};

/// Eine einzelne Berechtigung.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
pub enum Permission {
    /// Fall anlegen.
    #[serde(rename = "case.create")]
    CaseCreate,
    /// Fälle sehen.
    #[serde(rename = "case.view")]
    CaseView,
    /// Fall bearbeiten (Titel, Stand, Einstufung).
    #[serde(rename = "case.edit")]
    CaseEdit,
    /// Fall schließen.
    #[serde(rename = "case.close")]
    CaseClose,
    /// Evidence registrieren.
    #[serde(rename = "evidence.import")]
    EvidenceImport,
    /// Evidence sehen.
    #[serde(rename = "evidence.view")]
    EvidenceView,
    /// Analyse starten.
    #[serde(rename = "analysis.start")]
    AnalysisStart,
    /// Analyse abbrechen.
    #[serde(rename = "analysis.cancel")]
    AnalysisCancel,
    /// Dateien und Ergebnisse ansehen.
    #[serde(rename = "file.view")]
    FileView,
    /// Dateien extrahieren und herunterladen.
    #[serde(rename = "file.extract")]
    FileExtract,
    /// Suchen.
    #[serde(rename = "search.run")]
    SearchRun,
    /// Sensible Zugangsdaten (Passwörter, Hashes, Schlüssel) im Klartext sehen.
    #[serde(rename = "credential.view_sensitive")]
    CredentialViewSensitive,
    /// Findings anlegen.
    #[serde(rename = "finding.create")]
    FindingCreate,
    /// Findings bearbeiten und bewerten.
    #[serde(rename = "finding.edit")]
    FindingEdit,
    /// Beziehungen anlegen und entfernen.
    #[serde(rename = "relation.edit")]
    RelationEdit,
    /// Reports erstellen.
    #[serde(rename = "report.create")]
    ReportCreate,
    /// Reports exportieren.
    #[serde(rename = "report.export")]
    ReportExport,
    /// Audit lesen.
    #[serde(rename = "audit.view")]
    AuditView,
    /// Audit-Kette nachrechnen.
    #[serde(rename = "audit.verify")]
    AuditVerify,
    /// Threat Intelligence verwalten.
    #[serde(rename = "ti.manage")]
    TiManage,
    /// Playbooks ausführen.
    #[serde(rename = "playbook.run")]
    PlaybookRun,
    /// Sprachmodell befragen.
    #[serde(rename = "ai.query")]
    AiQuery,
    /// Connectoren nutzen.
    #[serde(rename = "connector.use")]
    ConnectorUse,
}

impl Permission {
    /// Der ganze Katalog.
    pub const ALL: [Permission; 23] = [
        Permission::CaseCreate,
        Permission::CaseView,
        Permission::CaseEdit,
        Permission::CaseClose,
        Permission::EvidenceImport,
        Permission::EvidenceView,
        Permission::AnalysisStart,
        Permission::AnalysisCancel,
        Permission::FileView,
        Permission::FileExtract,
        Permission::SearchRun,
        Permission::CredentialViewSensitive,
        Permission::FindingCreate,
        Permission::FindingEdit,
        Permission::RelationEdit,
        Permission::ReportCreate,
        Permission::ReportExport,
        Permission::AuditView,
        Permission::AuditVerify,
        Permission::TiManage,
        Permission::PlaybookRun,
        Permission::AiQuery,
        Permission::ConnectorUse,
    ];

    /// Name wie in der Datenbank (`case.create`).
    pub fn name(self) -> &'static str {
        match self {
            Permission::CaseCreate => "case.create",
            Permission::CaseView => "case.view",
            Permission::CaseEdit => "case.edit",
            Permission::CaseClose => "case.close",
            Permission::EvidenceImport => "evidence.import",
            Permission::EvidenceView => "evidence.view",
            Permission::AnalysisStart => "analysis.start",
            Permission::AnalysisCancel => "analysis.cancel",
            Permission::FileView => "file.view",
            Permission::FileExtract => "file.extract",
            Permission::SearchRun => "search.run",
            Permission::CredentialViewSensitive => "credential.view_sensitive",
            Permission::FindingCreate => "finding.create",
            Permission::FindingEdit => "finding.edit",
            Permission::RelationEdit => "relation.edit",
            Permission::ReportCreate => "report.create",
            Permission::ReportExport => "report.export",
            Permission::AuditView => "audit.view",
            Permission::AuditVerify => "audit.verify",
            Permission::TiManage => "ti.manage",
            Permission::PlaybookRun => "playbook.run",
            Permission::AiQuery => "ai.query",
            Permission::ConnectorUse => "connector.use",
        }
    }

    /// Kurze Beschreibung für Listen und Oberflächen.
    pub fn description(self) -> &'static str {
        match self {
            Permission::CaseCreate => "Fall anlegen",
            Permission::CaseView => "Fälle sehen",
            Permission::CaseEdit => "Fall bearbeiten (Titel, Stand, Einstufung)",
            Permission::CaseClose => "Fall schließen",
            Permission::EvidenceImport => "Evidence registrieren",
            Permission::EvidenceView => "Evidence sehen",
            Permission::AnalysisStart => "Analyse starten",
            Permission::AnalysisCancel => "Analyse abbrechen",
            Permission::FileView => "Dateien und Ergebnisse ansehen",
            Permission::FileExtract => "Dateien extrahieren und herunterladen",
            Permission::SearchRun => "Suchen",
            Permission::CredentialViewSensitive => {
                "Sensible Zugangsdaten (Passwörter, Hashes, Schlüssel) im Klartext sehen"
            }
            Permission::FindingCreate => "Findings anlegen",
            Permission::FindingEdit => "Findings bearbeiten und bewerten",
            Permission::RelationEdit => "Beziehungen anlegen und entfernen",
            Permission::ReportCreate => "Reports erstellen",
            Permission::ReportExport => "Reports exportieren",
            Permission::AuditView => "Audit lesen",
            Permission::AuditVerify => "Audit-Kette nachrechnen",
            Permission::TiManage => "Threat Intelligence verwalten",
            Permission::PlaybookRun => "Playbooks ausführen",
            Permission::AiQuery => "Sprachmodell befragen",
            Permission::ConnectorUse => "Connectoren nutzen",
        }
    }

    /// Umkehrung von [`Self::name`].
    pub fn from_name(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.name() == s)
    }
}

/// Eine Rolle: frei benanntes Bündel von Berechtigungen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
pub struct Role {
    /// ID.
    pub id: RoleId,
    /// Eindeutiger Name.
    pub name: String,
    /// Beschreibung.
    pub description: Option<String>,
    /// Berechtigungen.
    pub permissions: Vec<Permission>,
}

/// Mitgelieferte Vorlagen: die Rollen der Zielarchitektur mit einer
/// Vorbelegung. Superadmins können sie ändern, umbenennen oder löschen.
/// Sensible Zugangsdaten nur für Administrator und Forensic Examiner.
pub fn role_templates() -> Vec<(&'static str, &'static str, Vec<Permission>)> {
    use Permission::*;
    vec![
        (
            "Administrator",
            "Alle fachlichen Rechte (Konten und Rollen verwalten nur Superadmins)",
            Permission::ALL.to_vec(),
        ),
        (
            "Case Manager",
            "Fälle anlegen, steuern und abschließen",
            vec![
                CaseCreate,
                CaseView,
                CaseEdit,
                CaseClose,
                EvidenceImport,
                EvidenceView,
                AnalysisStart,
                AnalysisCancel,
                FileView,
                SearchRun,
                FindingCreate,
                FindingEdit,
                RelationEdit,
                ReportCreate,
                ReportExport,
                AuditView,
            ],
        ),
        (
            "Forensic Examiner",
            "Forensische Analyse einschließlich sensibler Zugangsdaten",
            vec![
                CaseView,
                EvidenceImport,
                EvidenceView,
                AnalysisStart,
                AnalysisCancel,
                FileView,
                FileExtract,
                SearchRun,
                CredentialViewSensitive,
                FindingCreate,
                FindingEdit,
                RelationEdit,
                ReportCreate,
                ReportExport,
            ],
        ),
        (
            "Analyst",
            "Ergebnisse auswerten",
            vec![
                CaseView,
                EvidenceView,
                FileView,
                SearchRun,
                FindingCreate,
                FindingEdit,
                RelationEdit,
                ReportCreate,
            ],
        ),
        (
            "Threat Intel Analyst",
            "Threat Intelligence bearbeiten",
            vec![
                CaseView,
                EvidenceView,
                SearchRun,
                TiManage,
                FindingCreate,
                ReportCreate,
            ],
        ),
        (
            "Reviewer",
            "Ergebnisse prüfen",
            vec![
                CaseView,
                EvidenceView,
                FileView,
                SearchRun,
                FindingEdit,
                ReportCreate,
                AuditView,
            ],
        ),
        (
            "Read Only",
            "Nur lesen",
            vec![CaseView, EvidenceView, FileView],
        ),
        (
            "Automation Service",
            "Technische Konten für automatische Analysen (z. B. die Kommandozeile)",
            vec![
                CaseCreate,
                CaseView,
                EvidenceImport,
                EvidenceView,
                AnalysisStart,
                FindingCreate,
                RelationEdit,
                ReportCreate,
                AuditVerify,
            ],
        ),
    ]
}

/// Art eines Kontos.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
pub enum UserKind {
    /// Mensch, meldet sich mit Passwort an.
    Human,
    /// Dienst oder Werkzeug ohne Passwort (z. B. die Kommandozeile).
    Service,
}

/// Stand eines Kontos.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
pub enum UserStatus {
    /// Selbst registriert, wartet auf Freigabe durch einen Superadmin.
    Pending,
    /// Freigegeben.
    Active,
    /// Gesperrt; bleibt für das Audit erhalten.
    Disabled,
    /// Registrierung abgelehnt.
    Rejected,
}

/// Ein Benutzerkonto.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
pub struct User {
    /// ID; dieselbe wie in `created_by`, `imported_by` und im Audit.
    pub id: ActorId,
    /// Anmeldename (klein, `a-z 0-9 . _ -`).
    pub username: String,
    /// Anzeigename.
    pub display_name: String,
    /// Art.
    pub kind: UserKind,
    /// Stand.
    pub status: UserStatus,
    /// Superadmin: verwaltet Konten und Rollen, hat alle Rechte.
    pub superadmin: bool,
    /// Angelegt bzw. registriert am.
    pub created_at: DateTime<Utc>,
    /// Rollen.
    pub roles: Vec<RoleId>,
    /// Muss zuerst ein eigenes Passwort setzen (Startpasswort oder vom
    /// Superadmin zurückgesetzt); bis dahin ist nichts anderes erlaubt.
    #[serde(default)]
    pub password_change_required: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn katalog_vollstaendig_und_namen_wie_serde() {
        for p in Permission::ALL {
            assert_eq!(serde_json::to_value(p).unwrap(), p.name());
            assert_eq!(Permission::from_name(p.name()), Some(p));
        }
        let mut namen: Vec<_> = Permission::ALL.iter().map(|p| p.name()).collect();
        namen.sort();
        namen.dedup();
        assert_eq!(namen.len(), Permission::ALL.len());
    }

    #[test]
    fn sensible_zugangsdaten_nur_admin_und_examiner() {
        let mit: Vec<_> = role_templates()
            .into_iter()
            .filter(|(_, _, p)| p.contains(&Permission::CredentialViewSensitive))
            .map(|(n, _, _)| n)
            .collect();
        assert_eq!(mit, ["Administrator", "Forensic Examiner"]);
    }
}
