//! Unterbefehle für Konten, Rollen, Rechte und Audit.
//!
//! Verwaltende Befehle laufen als angemeldetes Konto (`--als NAME`); das
//! Passwort wird verdeckt abgefragt oder, für Skripte, aus einer Datei
//! gelesen, nie von der Kommandozeile. Ohne `--als` handelt das Systemkonto
//! `stratum-cli`, das nur den ersten Superadmin einrichten darf. Ob eine
//! Aktion erlaubt ist, entscheidet der Store; Ablehnungen stehen im Audit.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use stratum_model::{ActorId, Permission, Role, RoleId};
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
    /// Katalog aller Berechtigungen ausgeben.
    Rechte,
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
    /// Alle Konten mit Stand und Rollen (nur Superadmins).
    Liste {
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

/// Meldet das handelnde Konto an; ohne `--als` das Systemkonto.
fn akteur(rt: &tokio::runtime::Runtime, db: &Datenbank, als: &Als) -> Result<ActorId> {
    let Some(name) = &als.als else {
        return Ok(ActorId::cli());
    };
    let p = passwort(
        als.als_passwort_datei.as_ref(),
        &format!("Passwort für {name}: "),
        false,
    )?;
    let u = rt.block_on(db.anmelden(name, &p))?;
    Ok(u.id)
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
    if let Befehl::Rechte = b {
        for p in Permission::ALL {
            println!("{:<27} {}", p.name(), p.description());
        }
        return Ok(());
    }
    let (rt, db) = datenbank::verbinden()?;
    match b {
        Befehl::Rechte => unreachable!("oben behandelt"),
        Befehl::Superadmin(s) => match s {
            SuperadminBefehl::Einrichten {
                name,
                anzeigename,
                passwort_datei,
                als,
            } => {
                stratum_store::anmeldename_pruefen(&name)?;
                let a = akteur(&rt, &db, &als)?;
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
        KontoBefehl::Liste { als } => {
            let a = akteur(rt, db, &als)?;
            let rollen = rt.block_on(db.rollen())?;
            for u in rt.block_on(db.konten(a))? {
                println!(
                    "{:<24} {:<9} {:<8} {:<11} {}",
                    u.username,
                    serde_json::to_value(u.status)?.as_str().unwrap_or(""),
                    serde_json::to_value(u.kind)?.as_str().unwrap_or(""),
                    if u.superadmin { "superadmin" } else { "" },
                    rollennamen(&rollen, &u.roles)
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
