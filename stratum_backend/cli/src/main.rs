//! stratum: automatisierte, read-only Inhaltsanalyse eines Roh-Images.
//!
//! Der Lauf öffnet das Image ausschließlich lesend, bildet die
//! Integritäts-Hashes, erkennt die Partitionen und wertet jede NTFS-Partition
//! aus (Registry-Eckdaten und lokale Konten). Optional durchsucht er das Image
//! mit einer Begriffstabelle. Das Ergebnis ist ein JSON-Report.

mod abruf;
mod datenbank;
mod extract;
mod konfig;
mod konsole;
mod report_html;
mod verwaltung;

use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;

use stratum_analysis::DpapiInput;
use stratum_core::ImageReader;
use stratum_lauf::report::Report;

/// Automatisierte, gerichtsverwertbare Inhaltsanalyse eines Roh-Images (read-only).
#[derive(Parser, Debug)]
#[command(
    name = "stratum",
    version = concat!(
        env!("CARGO_PKG_VERSION"),
        " (Revision ",
        env!("STRATUM_REVISION"),
        ", nicht committete Änderungen: ",
        env!("STRATUM_REVISION_GEAENDERT"),
        ")"
    ),
    about,
    // `stratum IMAGE …` wie bisher, oder ein Unterbefehl (`stratum konto …`).
    args_conflicts_with_subcommands = true,
    subcommand_negates_reqs = true,
    // Der Dateikatalog geht in eine Datei, in die Datenbank oder in beide.
    group = clap::ArgGroup::new("katalog_ziel").args(["catalog", "db"]).multiple(true),
    group = clap::ArgGroup::new("modell_ziel").args(["modell", "db"]).multiple(true)
)]
struct Cli {
    /// Verwaltung von Konten, Rollen und Audit.
    #[command(subcommand)]
    befehl: Option<verwaltung::Befehl>,

    /// Pfad zum Image (Roh-Image wie merged.dd oder E01). Mit `--fund` der
    /// Pfad zum JSON-Report. Entfällt bei `--audit-pruefen`.
    #[arg(required_unless_present = "audit_pruefen")]
    image: Option<PathBuf>,

    /// Audit-Kette der Datenbank (`STRATUM_DB_URL`) vollständig nachrechnen,
    /// Ergebnis als JSON ausgeben und beenden. Exitcode ungleich 0, wenn sie
    /// nicht intakt ist.
    #[arg(long, conflicts_with_all = ["db", "fund", "dump", "dump_record", "masterkey"])]
    audit_pruefen: bool,

    /// Zieldatei für den JSON-Report (Standard: Ausgabe auf stdout).
    #[arg(short, long)]
    out: Option<PathBuf>,

    /// Zusätzlich einen übersichtlichen HTML-Report in diese Datei schreiben.
    #[arg(long)]
    html: Option<PathBuf>,

    /// Begriffstabelle(n) (TOML) für die Keyword-Suche. Mehrfach angebbar, die
    /// Tabellen werden zusammengeführt (z. B. eine mitgelieferte und eine
    /// eigene).
    #[arg(short, long)]
    keywords: Vec<PathBuf>,

    /// bdp.info von ForensiCUnlock: legt die zu analysierende Partition fest.
    #[arg(long)]
    bdp: Option<PathBuf>,

    /// Die Integritäts-Hashes nicht berechnen (spart bei großen Images Zeit).
    #[arg(long)]
    no_hash: bool,

    /// Zusätzlich das gesamte Image roh nach Begriffen durchsuchen (findet auch
    /// unallozierte und gelöschte Bereiche, dauert aber deutlich länger).
    #[arg(long)]
    raw_sweep: bool,

    /// Gefundene .onion-Adressen online über Tor auf Erreichbarkeit prüfen.
    /// Verlässt die Offline-Analyse und setzt einen laufenden Tor-Dienst voraus.
    #[arg(long)]
    check_onion: bool,

    /// SOCKS5-Proxy für --check-onion.
    #[arg(long, default_value = "127.0.0.1:9050")]
    tor_proxy: String,

    /// Die mitgelieferte Begriffsliste "Strafverfolgung" nicht verwenden
    /// (dann wird nur gesucht, wenn eine eigene Tabelle mit -k angegeben ist).
    #[arg(long)]
    no_default_keywords: bool,

    /// Eine einzelne Datei aus dem Image extrahieren und beenden, ohne Analyse.
    /// Zwei Werte: der NTFS-Pfad im Image und die Zieldatei.
    /// Beispiel: --dump "Windows/System32/config/SAM" /tmp/SAM
    #[arg(long, num_args = 2, value_names = ["NTFS_PFAD", "ZIEL"])]
    dump: Option<Vec<String>>,

    /// Eine Datei über Volume-Offset und MFT-Nummer extrahieren (Werte z. B. aus
    /// dem Dateikatalog) und beenden. Wie bei --dump entsteht daneben
    /// `<ZIEL>.herkunft.json` mit Quelle und Hashes; nichts wird überschrieben.
    #[arg(long, num_args = 3, value_names = ["VOLUME_OFFSET", "MFT", "ZIEL"])]
    dump_record: Option<Vec<String>>,

    /// Einen Rohfund über seine Kennung aus einem Report ausgeben und beenden.
    /// Der Pfad ist dann der Report, nicht das Image. Die Kennung wird aus dem
    /// Inhalt nachgerechnet; Artefakte im Datenmodell verweisen mit
    /// `rohfund_id` auf sie.
    #[arg(long, value_name = "KENNUNG")]
    fund: Option<String>,

    /// Einen DPAPI-System-Masterkey (GUID = Dateiname) entschlüsseln, mit
    /// Fundstelle und verwendetem Schlüssel ausgeben und beenden. Unabhängig
    /// von `STRATUM_DEBUG`; der Lauf über das ganze Image gibt Masterkeys nur
    /// im Debug-Modus aus.
    #[arg(long, value_name = "GUID")]
    masterkey: Option<String>,

    /// Funde zusätzlich auf das Datenmodell abbilden (Artefakte, Observationen,
    /// Entitäten, Ereignisse, Beziehungen, Herkunft) und als JSON in diese
    /// Datei schreiben. Der Report verweist mit Hashes und Zählern darauf.
    /// Eine vorhandene Datei wird nicht überschrieben.
    #[arg(long, value_name = "DATEI")]
    modell: Option<PathBuf>,

    /// Funde, Datenmodell und Dateikatalog in PostgreSQL schreiben, mit
    /// Fall, Evidence und Analyselauf (`--modell` ist dafür nicht nötig).
    /// Verbindung aus `STRATUM_DB_URL` oder `stratum.toml`, Passwort aus der
    /// Datei in `STRATUM_DB_PASSWORT_DATEI` oder `stratum.toml`, nie von der
    /// Kommandozeile. Das Schema wird beim ersten Mal angelegt. Braucht die
    /// Image-Hashes.
    #[arg(long, conflicts_with = "no_hash")]
    db: bool,

    /// Fall (Fallnummer, angelegt mit `stratum fall neu`), in den der Lauf
    /// mit `--db` geht. Ohne Angabe wird ein Fall `CLI-<ID>` aus dem
    /// Image-Hash abgeleitet.
    #[arg(
        long,
        value_name = "NUMMER",
        requires = "db",
        conflicts_with = "fall_id"
    )]
    fall: Option<String>,

    /// Mit `--db` als dieses Konto analysieren (Passwort wird verdeckt
    /// abgefragt). Ohne Angabe das Konto aus `stratum.toml`, sonst das
    /// Systemkonto `stratum-cli`.
    #[arg(long, value_name = "NAME", requires = "db")]
    als: Option<String>,

    /// Passwort für `--als` aus dieser Datei statt der Abfrage.
    #[arg(long, value_name = "DATEI", requires = "als")]
    als_passwort_datei: Option<PathBuf>,

    /// Fall-ID (UUID) für das Datenmodell. Ohne Angabe wird sie aus dem
    /// Image-Hash abgeleitet, sodass Läufe über dasselbe Image dieselben IDs
    /// ergeben.
    #[arg(long, value_name = "UUID", requires = "modell_ziel")]
    fall_id: Option<String>,

    /// Dateikatalog aller Dateien und Verzeichnisse mit Metadaten als JSON Lines
    /// in diese Datei schreiben. Der Report verweist mit Hashes darauf. Eine
    /// vorhandene Datei wird nicht überschrieben.
    #[arg(long, value_name = "DATEI")]
    catalog: Option<PathBuf>,

    /// Im Dateikatalog zusätzlich SHA-256 und Signaturtyp jeder Datei
    /// bestimmen. Liest dafür jede Datei vollständig und dauert entsprechend
    /// lange; die Integrität sichert bereits der Image-Hash. Braucht
    /// `--catalog` oder `--db`.
    #[arg(long, requires = "katalog_ziel")]
    datei_hashes: bool,

    /// Vollständige MFT-Zeitachse mit SI-/FN-MACB-Ereignissen als JSON Lines.
    /// Enthält auch lesbare gelöschte Datensätze. Eine vorhandene Datei wird
    /// nicht überschrieben.
    #[arg(long, value_name = "DATEI")]
    mft_timeline: Option<PathBuf>,

    /// NTFS-Änderungsjournal `$UsnJrnl:$J` als JSON Lines schreiben. Spärliche
    /// Bereiche werden übersprungen. Eine vorhandene Datei wird nicht
    /// überschrieben.
    #[arg(long, value_name = "DATEI")]
    usn_journal: Option<PathBuf>,

    /// Klartextpasswort des Benutzers, um gespeicherte Browser-Passwörter
    /// (DPAPI) zu entschlüsseln. Der NT-Hash genügt dafür nicht; das Passwort
    /// wird üblicherweise vorher aus dem NT-Hash geknackt (hashcat/john).
    #[arg(long, value_name = "PASSWORT")]
    dpapi_password: Option<String>,

    /// Statt des Klartextpassworts der vorberechnete SHA-1 (UTF-16LE), hex.
    #[arg(long, value_name = "HEX40")]
    dpapi_sha1: Option<String>,

    /// Statt des Passworts ein bereits entschlüsselter DPAPI-Masterkey (64 Byte,
    /// hex), z. B. aus mimikatz oder impacket.
    #[arg(long, value_name = "HEX128")]
    dpapi_masterkey: Option<String>,

    /// Firefox-Hauptpasswort, um gespeicherte Firefox-Passwörter zu
    /// entschlüsseln. Ohne Angabe wird ein leeres Hauptpasswort angenommen (der
    /// Normalfall).
    #[arg(long, value_name = "PASSWORT")]
    firefox_password: Option<String>,
}

/// Wandelt eine Hex-Zeichenkette fester Länge in Bytes; Fehler mit Kontext.
fn hex_bytes(s: &str, erwartet: usize, name: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if s.len() != erwartet * 2 {
        anyhow::bail!(
            "{name}: {} Hex-Zeichen erwartet, {} erhalten",
            erwartet * 2,
            s.len()
        );
    }
    (0..erwartet)
        .map(|i| {
            u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                .map_err(|_| anyhow::anyhow!("{name}: ungültiges Hex"))
        })
        .collect()
}

/// Baut aus den drei sich ausschliessenden DPAPI-Flags die Eingabe.
fn dpapi_from_cli(cli: &Cli) -> Result<Option<DpapiInput>> {
    let gesetzt = [
        cli.dpapi_password.is_some(),
        cli.dpapi_sha1.is_some(),
        cli.dpapi_masterkey.is_some(),
    ]
    .iter()
    .filter(|b| **b)
    .count();
    if gesetzt > 1 {
        anyhow::bail!("--dpapi-password, --dpapi-sha1 und --dpapi-masterkey schliessen sich aus");
    }
    if let Some(p) = &cli.dpapi_password {
        return Ok(Some(DpapiInput::Password(p.clone())));
    }
    if let Some(h) = &cli.dpapi_sha1 {
        let b = hex_bytes(h, 20, "--dpapi-sha1")?;
        return Ok(Some(DpapiInput::Sha1(b.try_into().unwrap())));
    }
    if let Some(m) = &cli.dpapi_masterkey {
        let b = hex_bytes(m, 64, "--dpapi-masterkey")?;
        return Ok(Some(DpapiInput::Masterkey(b.try_into().unwrap())));
    }
    Ok(None)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let gestartet = chrono::Utc::now();
    if let Some(b) = cli.befehl {
        return verwaltung::ausfuehren(b);
    }

    if cli.audit_pruefen {
        return datenbank::audit_pruefen();
    }
    let Some(image) = cli.image.as_deref() else {
        anyhow::bail!("Pfad zum Image fehlt");
    };
    if let Some(id) = &cli.fund {
        return abruf::fund(image, id);
    }

    // Schnellmodi: eine Datei extrahieren oder einen Masterkey abrufen und
    // beenden (keine Analyse).
    if cli.dump.is_some() || cli.dump_record.is_some() || cli.masterkey.is_some() {
        let img = ImageReader::open(image)
            .with_context(|| format!("Image nicht lesbar: {}", image.display()))?;
        let targets = stratum_lauf::ntfs_targets(&img, cli.bdp.as_deref())?;
        if let Some(d) = &cli.dump {
            return extract::run(
                &img,
                &targets,
                extract::Selector::Path(&d[0]),
                std::path::Path::new(&d[1]),
            );
        }
        if let Some(guid) = &cli.masterkey {
            return abruf::masterkey(&img, targets, guid);
        }
        if let Some(d) = &cli.dump_record {
            let volume_offset = d[0]
                .parse()
                .with_context(|| format!("VOLUME_OFFSET ist keine Zahl: {}", d[0]))?;
            let mft = d[1]
                .parse()
                .with_context(|| format!("MFT ist keine Zahl: {}", d[1]))?;
            return extract::run(
                &img,
                &targets,
                extract::Selector::Record { volume_offset, mft },
                std::path::Path::new(&d[2]),
            );
        }
    }

    // Mit --db zuerst verbinden, anmelden und den Fall prüfen: Fehler fallen
    // so vor dem langen Image-Hash auf.
    let vorbereitet = if cli.db {
        Some(datenbank::Vorbereitet::herstellen(
            cli.als.as_deref(),
            cli.als_passwort_datei.as_deref(),
            cli.fall.as_deref(),
        )?)
    } else {
        None
    };

    let optionen = stratum_lauf::Optionen {
        image: image.to_path_buf(),
        bdp: cli.bdp.clone(),
        hashen: !cli.no_hash,
        mitgelieferte_begriffe: !cli.no_default_keywords,
        begriffstabellen: cli.keywords.clone(),
        raw_sweep: cli.raw_sweep,
        onion_proxy: cli.check_onion.then(|| cli.tor_proxy.clone()),
        dpapi: dpapi_from_cli(&cli)?,
        firefox_passwort: cli.firefox_password.clone(),
        katalog: cli.catalog.clone(),
        datei_hashes: cli.datei_hashes,
        mft_timeline: cli.mft_timeline.clone(),
        usn_journal: cli.usn_journal.clone(),
        modell: cli.modell.clone(),
        fall_id: match &cli.fall_id {
            Some(s) => Some(
                uuid::Uuid::parse_str(s).with_context(|| format!("--fall-id: keine UUID: {s}"))?,
            ),
            None => None,
        },
        gestartet,
    };
    let konsole = konsole::Konsole::default();
    let stratum_lauf::Ergebnis { report, sitzung } = stratum_lauf::analysieren(
        &optionen,
        vorbereitet.as_ref().map(datenbank::Vorbereitet::ziel),
        &konsole,
    )?;

    let ergebnis = (|| {
        if let Some(path) = &cli.html {
            let html = report_html::render(&report);
            std::fs::write(path, html)
                .with_context(|| format!("HTML-Report nicht schreibbar: {}", path.display()))?;
            eprintln!("[+] HTML-Report geschrieben: {}", path.display());
        }
        write_report(&report, cli.out.as_deref())
    })();
    // Der Lauf in der Datenbank endet mit dem Report: abgeschlossen mit
    // dessen Hash, sonst als fehlgeschlagen.
    if let Some(s) = sitzung {
        let abschluss = s
            .abschliessen(ergebnis.as_ref().ok().map(String::as_str))
            .context("Analyselauf in der Datenbank nicht abschließbar");
        if ergebnis.is_ok() {
            abschluss?;
        } else if let Err(e) = abschluss {
            eprintln!("[!] {e:#}");
        }
    }
    drop(vorbereitet);
    ergebnis.map(|_| ())
}

/// Schreibt den Report und liefert seinen SHA-256.
fn write_report(report: &Report, out: Option<&std::path::Path>) -> Result<String> {
    match out {
        Some(path) => {
            let sha256 = stratum_lauf::report_schreiben(report, path)?;
            eprintln!("Report geschrieben: {}", path.display());
            eprintln!("[+] Report-SHA-256: {sha256}");
            eprintln!("[+] Pruefsummen geschrieben: {}.sha256", path.display());
            Ok(sha256)
        }
        None => {
            let json = stratum_lauf::report_json(report)?;
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(json.as_bytes())?;
            stdout.write_all(b"\n")?;
            Ok(stratum_core::hash_bytes(json.as_bytes()).sha256)
        }
    }
}
