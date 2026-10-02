//! Unterbefehle für Konten, Rollen, Rechte und Audit.
//!
//! Verwaltende Befehle laufen als angemeldetes Konto (`--als NAME`); das
//! Passwort wird verdeckt abgefragt oder, für Skripte, aus einer Datei
//! gelesen, nie von der Kommandozeile. Ohne `--als` handelt das Systemkonto
//! `stratum-cli`, das nur den ersten Superadmin einrichten darf. Ob eine
//! Aktion erlaubt ist, entscheidet der Store; Ablehnungen stehen im Audit.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use stratum_model::{
    ActorId, Case, CaseClassification, CaseId, CaseStatus, Evidence, EvidenceKind, EvidenceSupport,
    Permission, Role, RoleId,
};
use stratum_store::Datenbank;

use crate::datenbank;

/// Unterbefehle.
#[derive(Debug, Subcommand)]
pub enum Befehl {
    /// Superadmins einrichten, ernennen oder herabstufen.
    #[command(subcommand)]
    Superadmin(SuperadminBefehl),
    /// Konten registrieren, freigeben, ablehnen, sperren, Rollen setzen.
    #[command(subcommand)]
    Konto(KontoBefehl),
    /// Rollen anlegen, ändern, löschen und auflisten.
    #[command(subcommand)]
    Rolle(RolleBefehl),
    /// Fälle anlegen, auflisten und ansehen.
    #[command(subcommand)]
    Fall(FallBefehl),
    /// Evidence in einem Fall registrieren.
    #[command(subcommand)]
    Evidence(EvidenceBefehl),
    /// Analysen als Jobs in die Warteschlange stellen und verfolgen.
    #[command(subcommand)]
    Job(JobBefehl),
    /// Worker: führt wartende Jobs aus (läuft, bis er beendet wird).
    Worker {
        /// Nur einen Job ausführen (oder keinen, wenn keiner wartet) und
        /// beenden.
        #[arg(long)]
        einmal: bool,
        /// Ordner für Reports der Jobs (sonst aus stratum.toml bzw.
        /// STRATUM_JOB_AUSGABE).
        #[arg(long, value_name = "ORDNER")]
        ausgabe: Option<PathBuf>,
        /// Sekunden Pause, wenn kein Job wartet.
        #[arg(long, default_value_t = 5)]
        pause: u64,
    },
    /// Katalog aller Berechtigungen ausgeben.
    Rechte,
    /// Zeigen, welche Konfiguration gilt (Datei, Datenbank, Konto; ohne
    /// Passwörter).
    Konfig,
    /// Audit lesen und nachrechnen.
    #[command(subcommand)]
    Audit(AuditBefehl),
}

/// Anmeldung des handelnden Kontos.
#[derive(Debug, Args)]
pub struct Als {
    /// Anmeldename des handelnden Kontos (Superadmin für die Verwaltung).
    #[arg(long, value_name = "NAME")]
    als: Option<String>,
    /// Passwort des handelnden Kontos aus dieser Datei statt der Abfrage.
    #[arg(long, value_name = "DATEI", requires = "als")]
    als_passwort_datei: Option<PathBuf>,
}

/// Unterbefehle zu Fällen.
#[derive(Debug, Subcommand)]
pub enum FallBefehl {
    /// Fall anlegen (braucht case.create).
    Neu {
        /// Fallnummer, z. B. DFIR-2026-0017 (eindeutig).
        nummer: String,
        /// Titel.
        #[arg(long)]
        titel: String,
        /// Fallordner auf dem Server, in dem die Evidence liegt.
        #[arg(long, value_name = "ORDNER")]
        ordner: Option<PathBuf>,
        /// Beschreibung.
        #[arg(long)]
        beschreibung: Option<String>,
        /// Einstufung: open, internal, confidential, strictly_confidential.
        #[arg(long, default_value = "internal")]
        einstufung: String,
        /// Zeitzone für die Anzeige (z. B. Europe/Berlin); Analysezeiten
        /// bleiben UTC.
        #[arg(long)]
        zeitzone: Option<String>,
        #[command(flatten)]
        als: Als,
    },
    /// Alle Fälle (braucht case.view).
    Liste {
        #[command(flatten)]
        als: Als,
    },
    /// Fall mit seiner Evidence (braucht case.view und evidence.view).
    Zeigen {
        /// Fallnummer.
        nummer: String,
        #[command(flatten)]
        als: Als,
    },
}

/// Unterbefehle zu Evidence.
#[derive(Debug, Subcommand)]
pub enum EvidenceBefehl {
    /// Datei im Fall registrieren und hashen (braucht evidence.import). Die
    /// Art wird am Format erkannt; nicht unterstützte Arten werden trotzdem
    /// registriert und gehasht.
    Hinzu {
        /// Fallnummer.
        fall: String,
        /// Datei (Image, Mitschnitt, Speicherabbild …); nur lesend geöffnet.
        datei: PathBuf,
        /// Anzeigename (Standard: Dateiname).
        #[arg(long)]
        name: Option<String>,
        /// System oder Rolle, zu der die Evidence gehört (z. B. Webserver).
        #[arg(long)]
        rolle: Option<String>,
        /// Art statt der Erkennung, z. B. memory_dump, log_bundle, pcap.
        #[arg(long)]
        art: Option<String>,
        #[command(flatten)]
        als: Als,
    },
}

/// Unterbefehle zu Jobs.
#[derive(Debug, Subcommand)]
pub enum JobBefehl {
    /// Analyse einer registrierten Evidence einreihen (braucht
    /// analysis.start); ein Worker führt sie im Namen dieses Kontos aus.
    Analyse {
        /// Fallnummer.
        fall: String,
        /// Evidence (Name oder ID, siehe stratum fall zeigen).
        evidence: String,
        /// Dateikatalog zusätzlich als Datei.
        #[arg(long)]
        katalog: bool,
        /// SHA-256 und Signaturtyp jeder Datei im Katalog.
        #[arg(long)]
        datei_hashes: bool,
        /// MFT-Zeitachse als Datei.
        #[arg(long)]
        mft_timeline: bool,
        /// USN-Journal als Datei.
        #[arg(long)]
        usn_journal: bool,
        /// Das ganze Image roh nach Begriffen durchsuchen.
        #[arg(long)]
        raw_sweep: bool,
        /// Die mitgelieferte Begriffsliste nicht verwenden.
        #[arg(long)]
        ohne_begriffe: bool,
        /// Die bei der Evidence vermerkte bdp.info verwenden.
        #[arg(long)]
        bdp: bool,
        #[command(flatten)]
        als: Als,
    },
    /// Jobs, neueste zuerst (braucht case.view).
    Liste {
        /// Nur Jobs dieses Falls (Fallnummer).
        #[arg(long)]
        fall: Option<String>,
        /// Höchstens so viele.
        #[arg(long, default_value_t = 20)]
        anzahl: i64,
        #[command(flatten)]
        als: Als,
    },
    /// Stand, Fortschritt und Ergebnis eines Jobs.
    Zeigen {
        /// Job-ID.
        id: uuid::Uuid,
        /// Als JSON ausgeben.
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        als: Als,
    },
    /// Job abbrechen: wartend sofort, laufend vor dem nächsten Analyzer.
    Abbrechen {
        /// Job-ID.
        id: uuid::Uuid,
        #[command(flatten)]
        als: Als,
    },
}

/// Unterbefehle zu Superadmins.
#[derive(Debug, Subcommand)]
pub enum SuperadminBefehl {
    /// Superadmin anlegen: der erste ohne `--als`, solange es keinen gibt,
    /// weitere nur durch einen Superadmin.
    Einrichten {
        /// Anmeldename (klein, a-z 0-9 . _ -).
        name: String,
        /// Anzeigename.
        #[arg(long)]
        anzeigename: String,
        /// Passwort des neuen Kontos aus dieser Datei statt der Abfrage.
        #[arg(long, value_name = "DATEI")]
        passwort_datei: Option<PathBuf>,
        #[command(flatten)]
        als: Als,
    },
    /// Einem freigegebenen Konto das Superadmin-Recht geben.
    Ernennen {
        /// Anmeldename.
        name: String,
        #[command(flatten)]
        als: Als,
    },
    /// Das Superadmin-Recht entziehen (nicht dem letzten).
    Entziehen {
        /// Anmeldename.
        name: String,
        #[command(flatten)]
        als: Als,
    },
}

/// Unterbefehle zu Konten.
#[derive(Debug, Subcommand)]
pub enum KontoBefehl {
    /// Selbst registrieren; das Konto wartet auf Freigabe durch einen
    /// Superadmin.
    Registrieren {
        /// Anmeldename (klein, a-z 0-9 . _ -).
        name: String,
        /// Anzeigename.
        #[arg(long)]
        anzeigename: String,
        /// Passwort aus dieser Datei statt der Abfrage.
        #[arg(long, value_name = "DATEI")]
        passwort_datei: Option<PathBuf>,
    },
    /// Konten mit Stand und Rollen (nur Superadmins). Gesperrte
    /// Dienstkonten (etwa aus früheren Daten übernommene) nur mit `--alle`.
    Liste {
        /// Auch gesperrte Dienstkonten zeigen.
        #[arg(long)]
        alle: bool,
        #[command(flatten)]
        als: Als,
    },
    /// Registrierung freigeben und Rollen vergeben.
    Freigeben {
        /// Anmeldename.
        name: String,
        /// Rolle (Name), mehrfach möglich.
        #[arg(long = "rolle", value_name = "ROLLE")]
        rollen: Vec<String>,
        #[command(flatten)]
        als: Als,
    },
    /// Registrierung ablehnen.
    Ablehnen {
        /// Anmeldename.
        name: String,
        #[command(flatten)]
        als: Als,
    },
    /// Konto sperren.
    Sperren {
        /// Anmeldename.
        name: String,
        #[command(flatten)]
        als: Als,
    },
    /// Rollen eines Kontos auf genau diese setzen.
    Rollen {
        /// Anmeldename.
        name: String,
        /// Rolle (Name), mehrfach möglich; ohne Angabe keine Rolle.
        #[arg(long = "rolle", value_name = "ROLLE")]
        rollen: Vec<String>,
        #[command(flatten)]
        als: Als,
    },
    /// Dienstkonto (ohne Passwort) anlegen.
    Dienst {
        /// Anmeldename.
        name: String,
        /// Anzeigename.
        #[arg(long)]
        anzeigename: String,
        /// Rolle (Name), mehrfach möglich.
        #[arg(long = "rolle", value_name = "ROLLE")]
        rollen: Vec<String>,
        #[command(flatten)]
        als: Als,
    },
}

/// Unterbefehle zu Rollen.
#[derive(Debug, Subcommand)]
pub enum RolleBefehl {
    /// Alle Rollen mit ihren Berechtigungen.
    Liste,
    /// Rolle anlegen.
    Anlegen {
        /// Name der Rolle.
        name: String,
        /// Berechtigung (z. B. case.view), mehrfach möglich.
        #[arg(long = "recht", value_name = "RECHT")]
        rechte: Vec<String>,
        /// Beschreibung.
        #[arg(long)]
        beschreibung: Option<String>,
        #[command(flatten)]
        als: Als,
    },
    /// Rolle ändern. Ohne `--recht` bleiben die Berechtigungen, mit
    /// `--recht` gelten genau die angegebenen.
    Aendern {
        /// Bisheriger Name.
        name: String,
        /// Neuer Name.
        #[arg(long)]
        neuer_name: Option<String>,
        /// Berechtigung, mehrfach möglich.
        #[arg(long = "recht", value_name = "RECHT")]
        rechte: Vec<String>,
        /// Neue Beschreibung.
        #[arg(long)]
        beschreibung: Option<String>,
        #[command(flatten)]
        als: Als,
    },
    /// Rolle löschen; Konten verlieren sie.
    Loeschen {
        /// Name der Rolle.
        name: String,
        #[command(flatten)]
        als: Als,
    },
}

/// Unterbefehle zum Audit.
#[derive(Debug, Subcommand)]
pub enum AuditBefehl {
    /// Die ganze Kette nachrechnen (wie `--audit-pruefen`).
    Pruefen {
        #[command(flatten)]
        als: Als,
    },
    /// Die letzten Ereignisse ausgeben (braucht audit.view).
    Liste {
        /// Höchstens so viele Ereignisse.
        #[arg(long, default_value_t = 50)]
        anzahl: i64,
        /// Nur Ereignisse dieses Falls (UUID).
        #[arg(long, value_name = "UUID")]
        fall: Option<uuid::Uuid>,
        /// Als JSON ausgeben.
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        als: Als,
    },
}

/// Liest ein Passwort aus einer Datei oder verdeckt vom Terminal.
fn passwort(datei: Option<&PathBuf>, frage: &str, wiederholen: bool) -> Result<String> {
    if let Some(d) = datei {
        let p = std::fs::read_to_string(d)
            .with_context(|| format!("Passwortdatei nicht lesbar: {}", d.display()))?;
        return Ok(p.trim_end_matches(['\n', '\r']).to_string());
    }
    let p = rpassword::prompt_password(frage).context("Passwort nicht lesbar")?;
    if wiederholen {
        let w = rpassword::prompt_password("Passwort wiederholen: ")
            .context("Passwort nicht lesbar")?;
        if w != p {
            anyhow::bail!("Passwörter stimmen nicht überein");
        }
    }
    Ok(p)
}

/// Meldet `als` an; ohne Angabe das Konto aus `stratum.toml` bzw.
/// `STRATUM_KONTO`, sonst handelt das Systemkonto `stratum-cli`.
pub fn anmelden(
    rt: &tokio::runtime::Runtime,
    db: &Datenbank,
    als: Option<&str>,
    passwort_datei: Option<&Path>,
) -> Result<ActorId> {
    let name = match als {
        Some(n) => n.to_string(),
        None => match crate::konfig::konfig()?.konto() {
            Some(n) => n,
            None => return Ok(ActorId::cli()),
        },
    };
    let p = passwort(
        passwort_datei.map(Path::to_path_buf).as_ref(),
        &format!("Passwort für {name}: "),
        false,
    )?;
    let u = rt.block_on(db.anmelden(&name, &p))?;
    Ok(u.id)
}

/// Meldet das handelnde Konto an (siehe [`anmelden`]).
fn akteur(rt: &tokio::runtime::Runtime, db: &Datenbank, als: &Als) -> Result<ActorId> {
    anmelden(
        rt,
        db,
        als.als.as_deref(),
        als.als_passwort_datei.as_deref(),
    )
}

fn konto_id(rt: &tokio::runtime::Runtime, db: &Datenbank, name: &str) -> Result<ActorId> {
    Ok(rt
        .block_on(db.benutzer(name))?
        .with_context(|| format!("kein Konto {name}"))?
        .id)
}

fn rollen_ids(rollen: &[Role], namen: &[String]) -> Result<Vec<RoleId>> {
    namen
        .iter()
        .map(|n| {
            rollen
                .iter()
                .find(|r| r.name == *n)
                .map(|r| r.id)
                .with_context(|| format!("keine Rolle {n} (stratum rolle liste)"))
        })
        .collect()
}

fn rechte_aus(namen: &[String]) -> Result<Vec<Permission>> {
    namen
        .iter()
        .map(|n| {
            Permission::from_name(n)
                .with_context(|| format!("keine Berechtigung {n} (stratum rechte)"))
        })
        .collect()
}

fn rollennamen(rollen: &[Role], ids: &[RoleId]) -> String {
    ids.iter()
        .map(|id| {
            rollen
                .iter()
                .find(|r| r.id == *id)
                .map(|r| r.name.clone())
                .unwrap_or_else(|| id.to_string())
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Führt einen Unterbefehl aus.
pub fn ausfuehren(b: Befehl) -> Result<()> {
    match b {
        Befehl::Rechte => {
            for p in Permission::ALL {
                println!("{:<27} {}", p.name(), p.description());
            }
            return Ok(());
        }
        Befehl::Konfig => {
            let k = crate::konfig::konfig()?;
            let zeile = |n: &str, w: Option<String>| {
                println!("{n:<16}{}", w.unwrap_or_else(|| "(nicht gesetzt)".into()));
            };
            zeile("Datei", k.pfad().map(|p| p.display().to_string()));
            zeile("Datenbank", k.db_url());
            zeile(
                "Passwortdatei",
                k.db_passwort_datei().map(|p| p.display().to_string()),
            );
            zeile("Konto (--als)", k.konto());
            zeile("Job-Ausgabe", Some(k.jobs_ausgabe().display().to_string()));
            return Ok(());
        }
        _ => {}
    }
    let (rt, db) = datenbank::verbinden()?;
    match b {
        Befehl::Rechte | Befehl::Konfig => unreachable!("oben behandelt"),
        Befehl::Superadmin(s) => match s {
            SuperadminBefehl::Einrichten {
                name,
                anzeigename,
                passwort_datei,
                als,
            } => {
                stratum_store::anmeldename_pruefen(&name)?;
                // Ohne --als handelt hier immer das Systemkonto (erste
                // Einrichtung), auch wenn stratum.toml ein Konto vorgibt.
                let a = match &als.als {
                    Some(_) => akteur(&rt, &db, &als)?,
                    None => ActorId::cli(),
                };
                let p = passwort(
                    passwort_datei.as_ref(),
                    &format!("Neues Passwort für {name}: "),
                    true,
                )?;
                let u = rt.block_on(db.superadmin_einrichten(a, &name, &anzeigename, &p))?;
                eprintln!("[+] Superadmin {} eingerichtet ({})", u.username, u.id);
            }
            SuperadminBefehl::Ernennen { name, als } => {
                superadmin_setzen(&rt, &db, &name, &als, true)?
            }
            SuperadminBefehl::Entziehen { name, als } => {
                superadmin_setzen(&rt, &db, &name, &als, false)?
            }
        },
        Befehl::Konto(k) => konto(&rt, &db, k)?,
        Befehl::Fall(f) => fall(&rt, &db, f)?,
        Befehl::Job(j) => job(&rt, &db, j)?,
        Befehl::Worker {
            einmal,
            ausgabe,
            pause,
        } => {
            let ausgabe = match ausgabe {
                Some(a) => a,
                None => crate::konfig::konfig()?.jobs_ausgabe(),
            };
            let w = stratum_jobs::Worker::neu(db.clone(), rt.handle().clone(), ausgabe.clone());
            eprintln!(
                "[*] Worker {} wartet auf Jobs (Ausgabe {})",
                w.name(),
                ausgabe.display()
            );
            loop {
                match w.einmal()? {
                    Some((id, stand)) => {
                        eprintln!("[+] Job {id}: {}", text_von(&stand)?);
                        if einmal {
                            break;
                        }
                    }
                    None if einmal => {
                        eprintln!("[*] kein Job wartet");
                        break;
                    }
                    None => std::thread::sleep(std::time::Duration::from_secs(pause.max(1))),
                }
            }
        }
        Befehl::Evidence(e) => evidence(&rt, &db, e)?,
        Befehl::Rolle(r) => rolle(&rt, &db, r)?,
        Befehl::Audit(a) => match a {
            AuditBefehl::Pruefen { als } => {
                let akt = akteur(&rt, &db, &als)?;
                datenbank::audit_pruefen_mit(&rt, &db, akt)?;
            }
            AuditBefehl::Liste {
                anzahl,
                fall,
                json,
                als,
            } => {
                let akt = akteur(&rt, &db, &als)?;
                let liste =
                    rt.block_on(db.audit_liste(akt, fall.map(stratum_model::CaseId), anzahl))?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&liste)?);
                } else {
                    for z in liste {
                        let e = z.event;
                        println!(
                            "{:>6}  {} UTC  {:<14} {:<18} {:<8} {:<17} {}",
                            e.sequence,
                            e.timestamp.format("%Y-%m-%d %H:%M:%S"),
                            z.akteur,
                            serde_json::to_value(e.action)?.as_str().unwrap_or(""),
                            serde_json::to_value(e.result)?.as_str().unwrap_or(""),
                            e.object_type,
                            e.object_id.unwrap_or_default()
                        );
                    }
                }
            }
        },
    }
    Ok(())
}

fn superadmin_setzen(
    rt: &tokio::runtime::Runtime,
    db: &Datenbank,
    name: &str,
    als: &Als,
    ja: bool,
) -> Result<()> {
    let a = akteur(rt, db, als)?;
    let id = konto_id(rt, db, name)?;
    rt.block_on(db.superadmin_setzen(a, id, ja))?;
    eprintln!("[+] {name} ist {}Superadmin", if ja { "" } else { "kein " });
    Ok(())
}

fn konto(rt: &tokio::runtime::Runtime, db: &Datenbank, k: KontoBefehl) -> Result<()> {
    match k {
        KontoBefehl::Registrieren {
            name,
            anzeigename,
            passwort_datei,
        } => {
            stratum_store::anmeldename_pruefen(&name)?;
            let p = passwort(passwort_datei.as_ref(), "Neues Passwort: ", true)?;
            rt.block_on(db.registrieren(&name, &anzeigename, &p))?;
            eprintln!(
                "[+] Konto {name} registriert; es wartet auf Freigabe durch einen Superadmin"
            );
        }
        KontoBefehl::Liste { alle, als } => {
            let a = akteur(rt, db, &als)?;
            let rollen = rt.block_on(db.rollen())?;
            let konten = rt.block_on(db.konten(a))?;
            let (zeigen, verborgen): (Vec<_>, Vec<_>) = konten.into_iter().partition(|u| {
                alle || !(u.kind == stratum_model::UserKind::Service
                    && u.status == stratum_model::UserStatus::Disabled)
            });
            let breite = zeigen.iter().map(|u| u.username.len()).max().unwrap_or(0);
            for u in zeigen {
                println!(
                    "{:<breite$}  {:<9} {:<8} {:<11} {}",
                    u.username,
                    serde_json::to_value(u.status)?.as_str().unwrap_or(""),
                    serde_json::to_value(u.kind)?.as_str().unwrap_or(""),
                    if u.superadmin { "superadmin" } else { "" },
                    rollennamen(&rollen, &u.roles)
                );
            }
            if !verborgen.is_empty() {
                eprintln!(
                    "({} gesperrte Dienstkonten nicht gezeigt, --alle zeigt sie)",
                    verborgen.len()
                );
            }
        }
        KontoBefehl::Freigeben { name, rollen, als } => {
            let a = akteur(rt, db, &als)?;
            let ids = rollen_ids(&rt.block_on(db.rollen())?, &rollen)?;
            let id = konto_id(rt, db, &name)?;
            rt.block_on(db.freigeben(a, id, &ids))?;
            eprintln!("[+] {name} freigegeben");
        }
        KontoBefehl::Ablehnen { name, als } => {
            let a = akteur(rt, db, &als)?;
            let id = konto_id(rt, db, &name)?;
            rt.block_on(db.ablehnen(a, id))?;
            eprintln!("[+] Registrierung von {name} abgelehnt");
        }
        KontoBefehl::Sperren { name, als } => {
            let a = akteur(rt, db, &als)?;
            let id = konto_id(rt, db, &name)?;
            rt.block_on(db.sperren(a, id))?;
            eprintln!("[+] {name} gesperrt");
        }
        KontoBefehl::Rollen { name, rollen, als } => {
            let a = akteur(rt, db, &als)?;
            let ids = rollen_ids(&rt.block_on(db.rollen())?, &rollen)?;
            let id = konto_id(rt, db, &name)?;
            rt.block_on(db.konto_rollen_setzen(a, id, &ids))?;
            eprintln!("[+] Rollen von {name} gesetzt");
        }
        KontoBefehl::Dienst {
            name,
            anzeigename,
            rollen,
            als,
        } => {
            let a = akteur(rt, db, &als)?;
            let ids = rollen_ids(&rt.block_on(db.rollen())?, &rollen)?;
            let u = rt.block_on(db.dienstkonto_anlegen(a, &name, &anzeigename, &ids))?;
            eprintln!("[+] Dienstkonto {} angelegt ({})", u.username, u.id);
        }
    }
    Ok(())
}

fn rolle(rt: &tokio::runtime::Runtime, db: &Datenbank, r: RolleBefehl) -> Result<()> {
    match r {
        RolleBefehl::Liste => {
            for r in rt.block_on(db.rollen())? {
                let rechte: Vec<_> = r.permissions.iter().map(|p| p.name()).collect();
                println!("{}", r.name);
                if let Some(b) = &r.description {
                    println!("  {b}");
                }
                println!("  {}", rechte.join(", "));
            }
        }
        RolleBefehl::Anlegen {
            name,
            rechte,
            beschreibung,
            als,
        } => {
            let a = akteur(rt, db, &als)?;
            let rechte = rechte_aus(&rechte)?;
            rt.block_on(db.rolle_anlegen(a, &name, beschreibung.as_deref(), &rechte))?;
            eprintln!("[+] Rolle {name} angelegt");
        }
        RolleBefehl::Aendern {
            name,
            neuer_name,
            rechte,
            beschreibung,
            als,
        } => {
            let a = akteur(rt, db, &als)?;
            let alle = rt.block_on(db.rollen())?;
            let alt = alle
                .iter()
                .find(|r| r.name == name)
                .with_context(|| format!("keine Rolle {name}"))?;
            let rechte = if rechte.is_empty() {
                alt.permissions.clone()
            } else {
                rechte_aus(&rechte)?
            };
            let neu = neuer_name.as_deref().unwrap_or(&name);
            let beschreibung = beschreibung.or_else(|| alt.description.clone());
            rt.block_on(db.rolle_aendern(a, alt.id, neu, beschreibung.as_deref(), &rechte))?;
            eprintln!("[+] Rolle {neu} geändert");
        }
        RolleBefehl::Loeschen { name, als } => {
            let a = akteur(rt, db, &als)?;
            let id = rollen_ids(&rt.block_on(db.rollen())?, std::slice::from_ref(&name))?[0];
            rt.block_on(db.rolle_loeschen(a, id))?;
            eprintln!("[+] Rolle {name} gelöscht");
        }
    }
    Ok(())
}

fn fall(rt: &tokio::runtime::Runtime, db: &Datenbank, f: FallBefehl) -> Result<()> {
    match f {
        FallBefehl::Neu {
            nummer,
            titel,
            ordner,
            beschreibung,
            einstufung,
            zeitzone,
            als,
        } => {
            let a = akteur(rt, db, &als)?;
            let classification: CaseClassification =
                serde_json::from_value(serde_json::Value::String(einstufung.clone())).with_context(
                    || format!("Einstufung {einstufung}: open, internal, confidential oder strictly_confidential"),
                )?;
            let ordner = match ordner {
                Some(o) => Some(
                    std::fs::canonicalize(&o)
                        .with_context(|| format!("Fallordner nicht vorhanden: {}", o.display()))?
                        .display()
                        .to_string(),
                ),
                None => None,
            };
            let jetzt = chrono::Utc::now();
            let c = Case {
                id: CaseId::new(),
                case_number: nummer.clone(),
                title: titel,
                description: beschreibung,
                status: CaseStatus::Active,
                classification,
                created_at: jetzt,
                created_by: a,
                opened_at: Some(jetzt),
                closed_at: None,
                timezone: zeitzone,
                case_folder: ordner,
                tags: Vec::new(),
            };
            if rt.block_on(db.fall_id(&nummer))?.is_some() {
                anyhow::bail!("Fallnummer {nummer} ist schon vergeben");
            }
            rt.block_on(db.fall_anlegen(a, &c))?;
            eprintln!("[+] Fall {nummer} angelegt ({})", c.id);
        }
        FallBefehl::Liste { als } => {
            let a = akteur(rt, db, &als)?;
            let faelle = rt.block_on(db.faelle(a))?;
            let breite = faelle
                .iter()
                .map(|f| f.fall.case_number.len())
                .max()
                .unwrap_or(0);
            for f in faelle {
                println!(
                    "{:<breite$}  {:<9} {:>3} Evidence  {}",
                    f.fall.case_number,
                    text_von(&f.fall.status)?,
                    f.evidence,
                    f.fall.title
                );
            }
        }
        FallBefehl::Zeigen { nummer, als } => {
            let a = akteur(rt, db, &als)?;
            let id = rt
                .block_on(db.fall_id(&nummer))?
                .with_context(|| format!("kein Fall {nummer}"))?;
            let (c, evidence) = rt.block_on(db.fall_oeffnen(a, id))?;
            println!("Fall        {} ({})", c.case_number, c.id);
            println!("Titel       {}", c.title);
            println!("Stand       {}", text_von(&c.status)?);
            println!("Einstufung  {}", text_von(&c.classification)?);
            if let Some(o) = &c.case_folder {
                println!("Fallordner  {o}");
            }
            println!("Evidence    {}", evidence.len());
            for e in evidence {
                println!(
                    "  {}  {:<15} {:<18} {}{}",
                    e.id,
                    text_von(&e.kind)?,
                    text_von(&e.support)?,
                    e.name,
                    e.role.map(|r| format!(" ({r})")).unwrap_or_default()
                );
                println!("      {}  SHA-256 {}", e.source_uri, e.sha256);
            }
        }
    }
    Ok(())
}

/// Name einer Aufzählung, wie serde ihn schreibt.
fn text_von<T: serde::Serialize>(v: &T) -> Result<String> {
    Ok(serde_json::to_value(v)?
        .as_str()
        .unwrap_or_default()
        .to_string())
}

/// Erkennt die Art am Format. Nur Formate mit belegter Kennung; alles
/// andere ist `other` und kann mit `--art` gesetzt werden.
fn art_erkennen(img: &stratum_core::ImageReader) -> EvidenceKind {
    if img.format() == stratum_core::ImageFormat::Ewf {
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
        stratum_core::PartitionScheme::None => EvidenceKind::Other,
        _ => EvidenceKind::RawDiskImage,
    }
}

fn evidence(rt: &tokio::runtime::Runtime, db: &Datenbank, e: EvidenceBefehl) -> Result<()> {
    let EvidenceBefehl::Hinzu {
        fall,
        datei,
        name,
        rolle,
        art,
        als,
    } = e;
    // Anmelden und Fall prüfen vor dem langen Hash.
    let a = akteur(rt, db, &als)?;
    let fall_id = rt
        .block_on(db.fall_id(&fall))?
        .with_context(|| format!("kein Fall {fall}"))?;
    let img = stratum_core::ImageReader::open(&datei)
        .with_context(|| format!("Datei nicht lesbar: {}", datei.display()))?;
    let kind = match &art {
        Some(t) => serde_json::from_value(serde_json::Value::String(t.clone()))
            .with_context(|| format!("unbekannte Art {t}"))?,
        None => art_erkennen(&img),
    };
    let pb = crate::konsole::bytes_bar(img.len(), "Hashing");
    let cb: stratum_core::Progress = &|done| pb.set_position(done);
    let h = stratum_core::hash_image_with_progress(&img, Some(cb))
        .context("Hash nicht berechenbar (Datei beschädigt?)")?;
    pb.finish_and_clear();
    let ewf = img.ewf().map(|x| stratum_lauf::ewf_report(x, Some(&h)));
    if let Some(i) = &ewf {
        for (n, stimmt) in [("MD5", i.md5_stimmt), ("SHA-1", i.sha1_stimmt)] {
            if stimmt == Some(false) {
                anyhow::bail!("Akquise-{n} des E01 stimmt nicht mit den Mediendaten überein");
            }
        }
    }
    // bdp.info von ForensiCUnlock neben einem Image gehört dazu.
    let bdp = datei
        .parent()
        .map(|d| d.join("bdp.info"))
        .filter(|p| p.is_file())
        .and_then(|p| std::fs::canonicalize(p).ok());
    let support = match kind {
        EvidenceKind::RawDiskImage | EvidenceKind::E01Image => EvidenceSupport::Recognized,
        _ => EvidenceSupport::UnsupportedFormat,
    };
    let dateiname = datei
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| datei.display().to_string());
    let jetzt = chrono::Utc::now();
    let ev = Evidence {
        id: stratum_lauf::evidence_id_ableiten(fall_id, &h.sha256, kind),
        case_id: fall_id,
        kind,
        name: name.unwrap_or_else(|| dateiname.clone()),
        role: rolle,
        original_name: Some(dateiname),
        source_uri: std::fs::canonicalize(&datei)?.display().to_string(),
        size: img.len(),
        sha256: h.sha256.clone(),
        blake3: h.blake3.clone(),
        acquired_at: img
            .ewf()
            .and_then(|x| x.info().acquired_unix())
            .and_then(|u| chrono::DateTime::from_timestamp(u, 0)),
        imported_at: jetzt,
        imported_by: a,
        acquisition_method: None,
        read_only: true,
        support,
        parent_evidence_id: None,
        metadata: serde_json::json!({
            "md5": h.md5,
            "sha1": h.sha1,
            "ewf": ewf,
            "bdp_info": bdp.map(|p| p.display().to_string()),
            "art_erkannt": art.is_none(),
        }),
    };
    let neu = rt.block_on(db.evidence_registrieren(a, &ev))?;
    eprintln!(
        "[+] Evidence {} {} ({}, {}) im Fall {fall}",
        ev.name,
        if neu {
            "registriert"
        } else {
            "war schon registriert, Hash bestätigt"
        },
        text_von(&ev.kind)?,
        text_von(&ev.support)?
    );
    eprintln!("    ID      {}", ev.id);
    eprintln!("    SHA-256 {}", ev.sha256);
    eprintln!("    BLAKE3  {}", ev.blake3);
    Ok(())
}

fn job(rt: &tokio::runtime::Runtime, db: &Datenbank, j: JobBefehl) -> Result<()> {
    match j {
        JobBefehl::Analyse {
            fall,
            evidence,
            katalog,
            datei_hashes,
            mft_timeline,
            usn_journal,
            raw_sweep,
            ohne_begriffe,
            bdp,
            als,
        } => {
            let a = akteur(rt, db, &als)?;
            let fall_id = rt
                .block_on(db.fall_id(&fall))?
                .with_context(|| format!("kein Fall {fall}"))?;
            let ev = rt
                .block_on(db.evidence_id(fall_id, &evidence))?
                .with_context(|| format!("keine Evidence {evidence} im Fall {fall}"))?;
            let optionen = stratum_jobs::AnalyseOptionen {
                katalog,
                datei_hashes,
                mft_timeline,
                usn_journal,
                raw_sweep,
                ohne_begriffe,
                bdp,
            };
            let id =
                rt.block_on(db.analyse_einreihen(a, fall_id, ev, serde_json::to_value(optionen)?))?;
            eprintln!("[+] Job {id} eingereiht (Analyse von {evidence} im Fall {fall})");
            println!("{id}");
        }
        JobBefehl::Liste { fall, anzahl, als } => {
            let a = akteur(rt, db, &als)?;
            let fall_id = match fall {
                Some(n) => Some(
                    rt.block_on(db.fall_id(&n))?
                        .with_context(|| format!("kein Fall {n}"))?,
                ),
                None => None,
            };
            for j in rt.block_on(db.jobs(a, fall_id, anzahl))? {
                println!(
                    "{}  {:<9}  {}  {}",
                    j.id,
                    text_von(&j.status)?,
                    j.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
                    fortschritt_kurz(&j)
                );
            }
        }
        JobBefehl::Zeigen { id, json, als } => {
            let a = akteur(rt, db, &als)?;
            let j = rt.block_on(db.job_ansehen(a, stratum_model::JobId(id)))?;
            if json {
                println!("{}", serde_json::to_string_pretty(&j)?);
                return Ok(());
            }
            println!("Job         {}", j.id);
            println!("Stand       {}", text_von(&j.status)?);
            println!("Parameter   {}", j.parameters);
            println!("Fortschritt {}", fortschritt_kurz(&j));
            if let Some(w) = &j.worker {
                println!("Worker      {w}");
            }
            if let Some(l) = j.analysis_run_id {
                println!("Lauf        {l}");
            }
            if let Some(f) = &j.error {
                println!("Fehler      {f}");
            }
            if let Some(e) = &j.result {
                println!("Ergebnis    {e}");
            }
        }
        JobBefehl::Abbrechen { id, als } => {
            let a = akteur(rt, db, &als)?;
            let stand = rt.block_on(db.job_abbrechen(a, stratum_model::JobId(id)))?;
            match stand {
                stratum_model::JobStatus::Cancelled => eprintln!("[+] Job {id} abgebrochen"),
                _ => eprintln!("[+] Abbruch angefordert; der Job hält vor dem nächsten Schritt an"),
            }
        }
    }
    Ok(())
}

/// Phase, Anteil und letzte Meldung in einer Zeile.
fn fortschritt_kurz(j: &stratum_model::Job) -> String {
    let p = &j.progress;
    let phase = p["phase"].as_str().unwrap_or("");
    let anteil = match (
        p["phasen"][phase]["erledigt"].as_u64(),
        p["phasen"][phase]["gesamt"].as_u64(),
    ) {
        (Some(e), Some(g)) if g > 0 => format!(" {}%", e.saturating_mul(100) / g),
        _ => String::new(),
    };
    let meldung = p["meldung"].as_str().unwrap_or("");
    format!("{phase}{anteil}  {meldung}").trim().to_string()
}
