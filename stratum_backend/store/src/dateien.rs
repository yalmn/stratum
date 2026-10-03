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

/// Ein Katalogeintrag als JSON mit Zeiten als Text und `hat_kinder`.
macro_rules! datei_json {
    () => {
        "jsonb_build_object(
    'mft_record', f.mft_record, 'parent_record', f.parent_record, 'name', f.name, 'path', f.path,
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
            AND c.mft_record <> c.parent_record))"
    };
}

const VERZEICHNIS: &str = concat!(
    "SELECT ",
    datei_json!(),
    ",
        NOT f.is_directory, f.mft_record, f.name
    FROM file f
    WHERE f.evidence_id = $1 AND f.volume_offset = $2 AND f.parent_record = $3
      AND f.mft_record <> f.parent_record
      AND ($4::boolean IS NULL OR (NOT f.is_directory, f.name, f.mft_record) > ($4, $6, $5))
    ORDER BY NOT f.is_directory, f.name, f.mft_record
    LIMIT $7"
);

/// Alle Einträge eines Datensatzes (mehrere bei Hardlinks).
const EINTRAG: &str = concat!(
    "SELECT ",
    datei_json!(),
    " FROM file f WHERE f.evidence_id = $1 AND f.volume_offset = $2 AND f.mft_record = $3 \
     ORDER BY f.parent_record, f.name LIMIT 32"
);

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

    /// Ein Datensatz aus dem Katalog mit allen Namen (Hardlinks).
    pub async fn datei_eintrag(
        &self,
        akteur: ActorId,
        evidence: EvidenceId,
        volume_offset: i64,
        mft_record: i64,
    ) -> Result<Vec<Value>, StoreError> {
        let e = self
            .datei_lesen_erlaubt(
                akteur,
                evidence,
                json!({"art": "eintrag", "volume_offset": volume_offset, "mft_record": mft_record}),
            )
            .await?;
        let zeilen: Vec<Json<Value>> = sqlx::query_scalar(EINTRAG)
            .bind(evidence.0)
            .bind(volume_offset)
            .bind(mft_record)
            .fetch_all(&self.pool)
            .await?;
        if zeilen.is_empty() {
            return Err(StoreError::NichtGefunden(format!(
                "MFT-Datensatz {mft_record} nicht im Katalog"
            )));
        }
        self.audit(&e).await?;
        Ok(zeilen.into_iter().map(|j| j.0).collect())
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

/// Wofür eine Datei gelesen wird; bestimmt Recht und Audit-Aktion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Zugriff {
    /// Ausschnitt ansehen (Hex-Ansicht).
    Ansehen,
    /// Vollständig lesen und hashen.
    Hashen,
    /// Inhalt herunterladen.
    Exportieren,
}

/// Was der Server zum Lesen einer Datei braucht, nach geprüften Rechten.
#[derive(Debug, Clone)]
pub struct DateiQuelle {
    /// Fall.
    pub fall: CaseId,
    /// Evidence.
    pub evidence: EvidenceId,
    /// Pfad des Images.
    pub image: String,
    /// bdp.info, falls bei der Evidence vermerkt.
    pub bdp: Option<String>,
    /// Name der Datei im Katalog.
    pub name: String,
    /// Pfad im Volume.
    pub pfad: String,
    /// Größe laut Katalog.
    pub groesse: Option<i64>,
    /// Audit-Ereignis des Zugriffs.
    pub audit: stratum_model::AuditEventId,
}

impl Datenbank {
    /// Prüft Rechte und Katalog für einen Dateizugriff und trägt ihn ins
    /// Audit ein (`FILE_VIEW`, beim Export `FILE_EXTRACT`). Nur Dateien aus
    /// dem Katalog der Evidence sind erreichbar.
    pub async fn datei_quelle(
        &self,
        akteur: ActorId,
        evidence: EvidenceId,
        volume_offset: i64,
        mft_record: i64,
        zugriff: Zugriff,
    ) -> Result<DateiQuelle, StoreError> {
        let ev: Option<(uuid::Uuid, String, Json<Value>)> =
            sqlx::query_as("SELECT case_id, source_uri, metadata FROM evidence WHERE id = $1")
                .bind(evidence.0)
                .fetch_optional(&self.pool)
                .await?;
        let (fall, image, meta) =
            ev.ok_or_else(|| StoreError::NichtGefunden(format!("keine Evidence {evidence}")))?;
        let fall = CaseId(fall);
        let (aktion, recht) = match zugriff {
            Zugriff::Exportieren => (AuditAction::FileExtract, Permission::FileExtract),
            _ => (AuditAction::FileView, Permission::FileView),
        };
        let mut e = AuditEintrag {
            akteur,
            case_id: Some(fall),
            aktion,
            objekt_typ: "file",
            objekt_id: Some(format!("{evidence}:{volume_offset}:{mft_record}")),
            ergebnis: AuditResult::Success,
            details: json!({"zugriff": format!("{zugriff:?}").to_lowercase()}),
        };
        self.verlangen(akteur, Permission::CaseView, e.clone())
            .await?;
        self.verlangen(akteur, recht, e.clone()).await?;
        let datei: Option<(String, String, Option<i64>, bool)> = sqlx::query_as(
            "SELECT name, path, size, is_directory FROM file \
             WHERE evidence_id = $1 AND volume_offset = $2 AND mft_record = $3 LIMIT 1",
        )
        .bind(evidence.0)
        .bind(volume_offset)
        .bind(mft_record)
        .fetch_optional(&self.pool)
        .await?;
        let (name, pfad, groesse, verzeichnis) = datei.ok_or_else(|| {
            StoreError::NichtGefunden(format!("MFT-Datensatz {mft_record} nicht im Katalog"))
        })?;
        if verzeichnis {
            return Err(StoreError::Eingabe(
                "ein Verzeichnis hat keinen Dateiinhalt".into(),
            ));
        }
        e.details["pfad"] = json!(pfad);
        let audit = self.audit(&e).await?;
        Ok(DateiQuelle {
            fall,
            evidence,
            image,
            bdp: meta
                .0
                .get("bdp_info")
                .and_then(Value::as_str)
                .map(String::from),
            name,
            pfad,
            groesse,
            audit,
        })
    }

    /// Vermerkt den berechneten SHA-256 im Katalog, falls dort noch keiner
    /// steht. Liefert, ob er neu eingetragen wurde.
    pub async fn datei_hash_vermerken(
        &self,
        evidence: EvidenceId,
        volume_offset: i64,
        mft_record: i64,
        sha256: &str,
    ) -> Result<bool, StoreError> {
        let n = sqlx::query(
            "UPDATE file SET sha256 = $4 WHERE evidence_id = $1 AND volume_offset = $2 \
             AND mft_record = $3 AND sha256 IS NULL",
        )
        .bind(evidence.0)
        .bind(volume_offset)
        .bind(mft_record)
        .bind(sha256)
        .execute(&self.pool)
        .await?
        .rows_affected();
        Ok(n > 0)
    }

    /// Trägt einen abgeschlossenen Export in den War Room ein (mit Hash des
    /// gelieferten Inhalts), verknüpft mit dem Audit-Ereignis des Zugriffs.
    pub async fn datei_exportiert(
        &self,
        akteur: ActorId,
        q: &DateiQuelle,
        volume_offset: i64,
        mft_record: i64,
        bytes: u64,
        sha256: &str,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await?;
        crate::war_room::anhaengen(
            &mut tx,
            crate::war_room::Neu {
                fall: q.fall,
                akteur,
                art: stratum_model::WarRoomEntryKind::FileExtracted,
                refs: &[stratum_model::ObjectRef::Evidence(q.evidence)],
                payload: json!({"pfad": q.pfad, "name": q.name, "volume_offset": volume_offset,
                    "mft_record": mft_record, "bytes": bytes, "sha256": sha256}),
                parent: None,
                audit: Some(q.audit),
            },
        )
        .await?;
        tx.commit().await?;
        Ok(())
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
