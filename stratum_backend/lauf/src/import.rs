//! Evidence einlesen: Art erkennen, hashen, Angaben zusammenstellen.
//!
//! Gemeinsam für `stratum evidence hinzu` und den Import-Job. Die Datei wird
//! nur lesend geöffnet. Registriert wird danach vom Aufrufer
//! (`Datenbank::evidence_registrieren`), damit Rechte und Audit dort bleiben.

use std::path::{Path, PathBuf};

use serde_json::json;
use stratum_core::{hash_image_abbrechbar, ImageFormat, ImageReader, PartitionScheme};
use stratum_model::{ActorId, CaseId, Evidence, EvidenceKind, EvidenceSupport};

use crate::{evidence_id_ableiten, ewf_report, Kontext, LaufFehler, Phase, Rueckmeldung};

/// Was eingelesen werden soll.
#[derive(Debug, Clone)]
pub struct Einlesen {
    /// Fall.
    pub fall: CaseId,
    /// Datei (Image, Mitschnitt, Speicherabbild …).
    pub datei: PathBuf,
    /// Anzeigename (Standard: Dateiname).
    pub name: Option<String>,
    /// System oder Rolle, zu der die Evidence gehört.
    pub rolle: Option<String>,
    /// Art statt der Erkennung.
    pub art: Option<EvidenceKind>,
    /// Wer importiert.
    pub akteur: ActorId,
}

/// Erkennt die Art am Format. Nur Formate mit belegter Kennung; alles
/// andere ist `other`.
pub fn art_erkennen(img: &ImageReader) -> EvidenceKind {
    if img.format() == ImageFormat::Ewf {
        return EvidenceKind::E01Image;
    }
    let kopf = img
        .read_at(0, 4)
        .map(|k| k.into_owned())
        .unwrap_or_default();
    // pcap: Magic 0xa1b2c3d4 (Mikro-) bzw. 0xa1b23c4d (Nanosekunden) in
    // der Byte-Reihenfolge des Schreibers (pcap-savefile(5)); pcapng: Section
    // Header Block 0x0A0D0D0A (IETF draft-ietf-opsawg-pcapng).
    match kopf.as_slice() {
        [0xd4, 0xc3, 0xb2, 0xa1]
        | [0xa1, 0xb2, 0xc3, 0xd4]
        | [0x4d, 0x3c, 0xb2, 0xa1]
        | [0xa1, 0xb2, 0x3c, 0x4d]
        | [0x0a, 0x0d, 0x0d, 0x0a] => return EvidenceKind::Pcap,
        _ => {}
    }
    match stratum_core::scan_partitions(img).scheme {
        PartitionScheme::None => EvidenceKind::Other,
        _ => EvidenceKind::RawDiskImage,
    }
}

/// Liegt `datei` innerhalb von `ordner`? Beide werden aufgelöst
/// (symbolische Links, `..`), damit kein Pfad aus dem Ordner herausführt.
pub fn im_ordner(datei: &Path, ordner: &Path) -> Result<PathBuf, LaufFehler> {
    let d = std::fs::canonicalize(datei)
        .kontext(|| format!("Datei nicht gefunden: {}", datei.display()))?;
    let o = std::fs::canonicalize(ordner)
        .kontext(|| format!("Fallordner nicht gefunden: {}", ordner.display()))?;
    if d.starts_with(&o) && d != o {
        Ok(d)
    } else {
        Err(LaufFehler::Eingabe(format!(
            "{} liegt nicht im Fallordner {}",
            datei.display(),
            ordner.display()
        )))
    }
}

/// Eintrag im Fallordner.
#[derive(Debug, Clone, serde::Serialize)]
pub struct OrdnerEintrag {
    /// Name.
    pub name: String,
    /// `dir`, `file` oder `link` (symbolische Links werden nicht verfolgt).
    pub typ: &'static str,
    /// Größe in Bytes (Dateien).
    pub groesse: Option<u64>,
    /// Absoluter, aufgelöster Pfad.
    pub pfad: String,
}

/// Höchstens so viele Einträge liefert [`ordner_auflisten`].
pub const ORDNER_MAX: usize = 2000;

/// Listet `rel` innerhalb von `ordner` auf: erst Verzeichnisse, dann
/// Dateien, je nach Name. Der aufgelöste Pfad muss im Ordner bleiben.
pub fn ordner_auflisten(
    ordner: &Path,
    rel: &str,
) -> Result<(String, Vec<OrdnerEintrag>), LaufFehler> {
    let basis = std::fs::canonicalize(ordner)
        .kontext(|| format!("Fallordner nicht gefunden: {}", ordner.display()))?;
    let ziel = std::fs::canonicalize(basis.join(rel.trim_start_matches('/')))
        .kontext(|| format!("Ordner nicht gefunden: {rel}"))?;
    if !ziel.starts_with(&basis) {
        return Err(LaufFehler::Eingabe(format!(
            "{rel} liegt nicht im Fallordner"
        )));
    }
    let mut liste = Vec::new();
    for e in
        std::fs::read_dir(&ziel).kontext(|| format!("Ordner nicht lesbar: {}", ziel.display()))?
    {
        let Ok(e) = e else { continue };
        let Ok(m) = e.metadata() else { continue };
        let typ = if m.file_type().is_symlink() {
            "link"
        } else if m.is_dir() {
            "dir"
        } else {
            "file"
        };
        liste.push(OrdnerEintrag {
            name: e.file_name().to_string_lossy().into_owned(),
            typ,
            groesse: (typ == "file").then_some(m.len()),
            pfad: e.path().display().to_string(),
        });
        if liste.len() >= ORDNER_MAX {
            break;
        }
    }
    liste.sort_by(|a, b| (a.typ != "dir", &a.name).cmp(&(b.typ != "dir", &b.name)));
    let rel = ziel
        .strip_prefix(&basis)
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    Ok((rel, liste))
}

/// Liest die Datei, hasht sie (abbrechbar, mit Fortschritt als
/// [`Phase::Hashing`]) und stellt die Evidence zusammen. Bei E01 müssen die
/// Akquise-Hashes zu den Mediendaten passen.
pub fn einlesen(e: &Einlesen, r: &dyn Rueckmeldung) -> Result<Evidence, LaufFehler> {
    let img = ImageReader::open(&e.datei)
        .kontext(|| format!("Datei nicht lesbar: {}", e.datei.display()))?;
    let kind = e.art.unwrap_or_else(|| art_erkennen(&img));
    r.phase_beginn(Phase::Hashing);
    let cb = |done| r.fortschritt(Phase::Hashing, done, img.len());
    let cb: stratum_core::Progress = &cb;
    let abbruch = || r.abbruch_angefordert();
    let h = hash_image_abbrechbar(&img, Some(cb), &abbruch)
        .kontext(|| "Hash nicht berechenbar (Datei beschädigt?)".into())?
        .ok_or(LaufFehler::Abgebrochen)?;
    r.phase_ende(Phase::Hashing);
    let ewf = img.ewf().map(|x| ewf_report(x, Some(&h)));
    if let Some(i) = &ewf {
        for (n, stimmt) in [("MD5", i.md5_stimmt), ("SHA-1", i.sha1_stimmt)] {
            if stimmt == Some(false) {
                return Err(LaufFehler::Eingabe(format!(
                    "Akquise-{n} des E01 stimmt nicht mit den Mediendaten überein"
                )));
            }
        }
    }
    // bdp.info von ForensiCUnlock neben einem Image gehört dazu.
    let bdp = e
        .datei
        .parent()
        .map(|d| d.join("bdp.info"))
        .filter(|p| p.is_file())
        .and_then(|p| std::fs::canonicalize(p).ok());
    let support = match kind {
        EvidenceKind::RawDiskImage | EvidenceKind::E01Image => EvidenceSupport::Recognized,
        _ => EvidenceSupport::UnsupportedFormat,
    };
    let dateiname = e
        .datei
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| e.datei.display().to_string());
    let quelle = std::fs::canonicalize(&e.datei)
        .kontext(|| format!("Pfad nicht auflösbar: {}", e.datei.display()))?;
    Ok(Evidence {
        id: evidence_id_ableiten(e.fall, &h.sha256, kind),
        case_id: e.fall,
        kind,
        name: e.name.clone().unwrap_or_else(|| dateiname.clone()),
        role: e.rolle.clone(),
        original_name: Some(dateiname),
        source_uri: quelle.display().to_string(),
        size: img.len(),
        sha256: h.sha256.clone(),
        blake3: h.blake3.clone(),
        acquired_at: img
            .ewf()
            .and_then(|x| x.info().acquired_unix())
            .and_then(|u| chrono::DateTime::from_timestamp(u, 0)),
        imported_at: chrono::Utc::now(),
        imported_by: e.akteur,
        acquisition_method: None,
        read_only: true,
        support,
        parent_evidence_id: None,
        metadata: json!({
            "md5": h.md5,
            "sha1": h.sha1,
            "ewf": ewf,
            "bdp_info": bdp.map(|p| p.display().to_string()),
            "art_erkannt": e.art.is_none(),
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Still;
    impl Rueckmeldung for Still {
        fn meldung(&self, _: &str) {}
        fn fortschritt(&self, _: Phase, _: u64, _: u64) {}
    }

    struct Sofort;
    impl Rueckmeldung for Sofort {
        fn meldung(&self, _: &str) {}
        fn fortschritt(&self, _: Phase, _: u64, _: u64) {}
        fn abbruch_angefordert(&self) -> bool {
            true
        }
    }

    fn angaben(datei: PathBuf) -> Einlesen {
        Einlesen {
            fall: CaseId(uuid::Uuid::from_u128(1)),
            datei,
            name: None,
            rolle: Some("Router".into()),
            art: None,
            akteur: ActorId::cli(),
        }
    }

    #[test]
    fn pcap_erkannt_und_gehasht() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("mitschnitt.pcap");
        let mut inhalt = vec![0xd4, 0xc3, 0xb2, 0xa1];
        inhalt.resize(4096, 7);
        std::fs::write(&p, &inhalt).unwrap();
        let ev = einlesen(&angaben(p), &Still).unwrap();
        assert_eq!(ev.kind, EvidenceKind::Pcap);
        assert_eq!(ev.support, EvidenceSupport::UnsupportedFormat);
        assert_eq!(ev.sha256, stratum_core::hash_bytes(&inhalt).sha256);
        assert_eq!(ev.name, "mitschnitt.pcap");
        assert_eq!(ev.role.as_deref(), Some("Router"));
        assert_eq!(ev.metadata["art_erkannt"], true);
    }

    #[test]
    fn abbruch_beim_hash() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("gross.bin");
        std::fs::write(&p, vec![0u8; 1 << 22]).unwrap();
        assert!(matches!(
            einlesen(&angaben(p), &Sofort),
            Err(LaufFehler::Abgebrochen)
        ));
    }

    #[test]
    fn ordner_nur_innerhalb() {
        let d = tempfile::tempdir().unwrap();
        let fall = d.path().join("fall");
        std::fs::create_dir_all(fall.join("unter")).unwrap();
        std::fs::write(fall.join("b.dd"), b"12345").unwrap();
        std::fs::write(fall.join("a.E01"), b"1").unwrap();
        let (rel, l) = ordner_auflisten(&fall, "").unwrap();
        assert_eq!(rel, "");
        let namen: Vec<_> = l
            .iter()
            .map(|e| (e.name.as_str(), e.typ, e.groesse))
            .collect();
        assert_eq!(
            namen,
            [
                ("unter", "dir", None),
                ("a.E01", "file", Some(1)),
                ("b.dd", "file", Some(5))
            ]
        );
        assert_eq!(ordner_auflisten(&fall, "unter").unwrap().0, "unter");
        assert!(ordner_auflisten(&fall, "..").is_err());
        assert!(ordner_auflisten(&fall, "fehlt").is_err());
    }

    #[test]
    fn nur_innerhalb_des_fallordners() {
        let d = tempfile::tempdir().unwrap();
        let fall = d.path().join("fall");
        std::fs::create_dir(&fall).unwrap();
        std::fs::write(fall.join("image.dd"), b"x").unwrap();
        std::fs::write(d.path().join("fremd.dd"), b"x").unwrap();
        assert!(im_ordner(&fall.join("image.dd"), &fall).is_ok());
        assert!(im_ordner(&fall.join("../fremd.dd"), &fall).is_err());
        assert!(im_ordner(&fall, &fall).is_err());
        assert!(im_ordner(&fall.join("fehlt.dd"), &fall).is_err());
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(d.path().join("fremd.dd"), fall.join("link.dd")).unwrap();
            assert!(im_ordner(&fall.join("link.dd"), &fall).is_err());
        }
    }
}
