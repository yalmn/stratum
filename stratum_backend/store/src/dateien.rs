//! Dateibaum aus dem Katalog: Volumes einer Evidence und Inhalt eines
//! Verzeichnisses, seitenweise.
//!
//! Lesen braucht `case.view` und `file.view` und steht als `FILE_VIEW` im
//! Audit. Zeiten kommen als Text wie im Katalog (`filetime_iso`), also mit
//! voller FILETIME-Auflösung.

use serde_json::{json, Value};
use sqlx::types::Json;
use stratum_model::{ActorId, AuditAction, AuditResult, CaseId, EvidenceId, Permission};

use crate::audit::AuditEintrag;
use crate::daten::Seite;
use crate::{Datenbank, StoreError};

/// MFT-Datensatz des Wurzelverzeichnisses in NTFS.
pub const WURZEL: i64 = 5;

/// Welches Verzeichnis gelesen wird.
#[derive(Debug, Clone)]
pub struct Verzeichnis {
    /// Volume (Byte-Offset im Image).
    pub volume_offset: i64,
    /// MFT-Datensatz des Verzeichnisses, [`WURZEL`] für die oberste Ebene.
    pub mft_record: i64,
    /// Weiter nach diesem Eintrag (aus `naechste` der vorigen Seite).
    pub nach: Option<String>,
    /// Höchstens so viele Einträge (1 bis 1000).
    pub anzahl: i64,
}

/// Marke `d|datensatz|name`: d ist 0 für Verzeichnisse, 1 für Dateien.
fn marke_lesen(m: &str) -> Result<(bool, i64, String), StoreError> {
    let falsch = || StoreError::Eingabe("Seitenmarke ungültig".into());
    let mut t = m.splitn(3, '|');
    let datei = match t.next() {
        Some("0") => false,
        Some("1") => true,
        _ => return Err(falsch()),
    };
    let rec = t.next().and_then(|r| r.parse().ok()).ok_or_else(falsch)?;
    let name = t.next().ok_or_else(falsch)?.to_string();
    Ok((datei, rec, name))
}

const VERZEICHNIS: &str = "\
SELECT jsonb_build_object(
    'mft_record', f.mft_record, 'name', f.name, 'path', f.path,
    'is_directory', f.is_directory, 'sequence', f.sequence, 'size', f.size,
    'valid_length', f.valid_length,
    'si_created', filetime_iso(f.si_created), 'si_modified', filetime_iso(f.si_modified),
    'si_mft_modified', filetime_iso(f.si_mft_modified), 'si_accessed', filetime_iso(f.si_accessed),
    'fn_created', filetime_iso(f.fn_created), 'fn_modified', filetime_iso(f.fn_modified),
    'fn_mft_modified', filetime_iso(f.fn_mft_modified), 'fn_accessed', filetime_iso(f.fn_accessed),
    'attributes', f.attributes, 'streams', f.streams, 'hardlinks', f.hardlinks,
    'reparse_tag', f.reparse_tag, 'wof', f.wof, 'mft_record_offset', f.mft_record_offset,
    'sha256', f.sha256, 'file_type', f.file_type, 'mime', f.mime, 'signature', f.signature,
    'hash_error', f.hash_error, 'error', f.error, 'content_error', f.content_error,
    'hat_kinder', f.is_directory AND EXISTS (
        SELECT 1 FROM file c WHERE c.evidence_id = f.evidence_id
            AND c.volume_offset = f.volume_offset AND c.parent_record = f.mft_record
            AND c.mft_record <> c.parent_record)),
    NOT f.is_directory, f.mft_record, f.name
FROM file f
WHERE f.evidence_id = $1 AND f.volume_offset = $2 AND f.parent_record = $3
  AND f.mft_record <> f.parent_record
  AND ($4::boolean IS NULL OR (NOT f.is_directory, f.name, f.mft_record) > ($4, $6, $5))
ORDER BY NOT f.is_directory, f.name, f.mft_record
LIMIT $7";

impl Datenbank {
    /// Fall einer Evidence und Prüfung der Leserechte; liefert den
    /// Audit-Eintrag für den Erfolg.
    async fn datei_lesen_erlaubt(
        &self,
        akteur: ActorId,
        evidence: EvidenceId,
        details: Value,
    ) -> Result<AuditEintrag, StoreError> {
        let fall: Option<uuid::Uuid> =
            sqlx::query_scalar("SELECT case_id FROM evidence WHERE id = $1")
                .bind(evidence.0)
                .fetch_optional(&self.pool)
                .await?;
        let fall =
            fall.ok_or_else(|| StoreError::NichtGefunden(format!("keine Evidence {evidence}")))?;
        let e = AuditEintrag {
            akteur,
            case_id: Some(CaseId(fall)),
            aktion: AuditAction::FileView,
            objekt_typ: "evidence",
            objekt_id: Some(evidence.to_string()),
            ergebnis: AuditResult::Success,
            details,
        };
        self.verlangen(akteur, Permission::CaseView, e.clone())
            .await?;
        self.verlangen(akteur, Permission::FileView, e.clone())
            .await?;
        Ok(e)
    }

    /// Volumes im Katalog einer Evidence mit Anzahl der Einträge.
    pub async fn volumes(
        &self,
        akteur: ActorId,
        evidence: EvidenceId,
    ) -> Result<Vec<Value>, StoreError> {
        let e = self
            .datei_lesen_erlaubt(akteur, evidence, json!({"art": "volumes"}))
            .await?;
        let zeilen: Vec<(i64, i64, i64)> = sqlx::query_as(
            "SELECT volume_offset, count(*), count(*) FILTER (WHERE is_directory) \
             FROM file WHERE evidence_id = $1 GROUP BY volume_offset ORDER BY volume_offset",
        )
        .bind(evidence.0)
        .fetch_all(&self.pool)
        .await?;
        self.audit(&e).await?;
        Ok(zeilen
            .into_iter()
            .map(|(v, n, d)| {
                json!({"volume_offset": v, "eintraege": n, "verzeichnisse": d, "wurzel": WURZEL})
            })
            .collect())
    }

    /// Inhalt eines Verzeichnisses: erst Unterverzeichnisse, dann Dateien,
    /// je nach Name. `hat_kinder` sagt, ob ein Unterverzeichnis Einträge hat.
    pub async fn verzeichnis(
        &self,
        akteur: ActorId,
        evidence: EvidenceId,
        v: &Verzeichnis,
    ) -> Result<Seite, StoreError> {
        let e = self
            .datei_lesen_erlaubt(
                akteur,
                evidence,
                json!({"art": "verzeichnis", "volume_offset": v.volume_offset,
                       "mft_record": v.mft_record}),
            )
            .await?;
        let anzahl = v.anzahl.clamp(1, 1000);
        let nach = v.nach.as_deref().map(marke_lesen).transpose()?;
        let (d, r, n) = match nach {
            Some((d, r, n)) => (Some(d), Some(r), Some(n)),
            None => (None, None, None),
        };
        let zeilen: Vec<(Json<Value>, bool, i64, String)> = sqlx::query_as(VERZEICHNIS)
            .bind(evidence.0)
            .bind(v.volume_offset)
            .bind(v.mft_record)
            .bind(d)
            .bind(r)
            .bind(n)
            .bind(anzahl + 1)
            .fetch_all(&self.pool)
            .await?;
        let mehr = zeilen.len() as i64 > anzahl;
        let mut eintraege = Vec::with_capacity(zeilen.len().min(anzahl as usize));
        let mut naechste = None;
        for (i, (eintrag, datei, rec, name)) in zeilen.into_iter().enumerate() {
            if i as i64 == anzahl {
                break;
            }
            if mehr && i as i64 == anzahl - 1 {
                naechste = Some(format!("{}|{rec}|{name}", u8::from(datei)));
            }
            eintraege.push(eintrag.0);
        }
        self.audit(&AuditEintrag {
            details: json!({"art": "verzeichnis", "volume_offset": v.volume_offset,
                            "mft_record": v.mft_record, "anzahl": eintraege.len()}),
            ..e
        })
        .await?;
        Ok(Seite {
            eintraege,
            naechste,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seitenmarke_mit_trenner_im_namen() {
        assert_eq!(
            marke_lesen("1|42|a|b.txt").unwrap(),
            (true, 42, "a|b.txt".to_string())
        );
        assert_eq!(marke_lesen("0|5|").unwrap(), (false, 5, String::new()));
        assert!(marke_lesen("2|5|x").is_err());
        assert!(marke_lesen("0|x|y").is_err());
        assert!(marke_lesen("0|5").is_err());
    }
}
