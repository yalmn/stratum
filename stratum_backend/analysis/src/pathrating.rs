//! Sichtungsheuristik für Programmpfade aus Diensten und geplanten Aufgaben.
//!
//! Die Bewertung sagt nur, ob ein Pfad an einem für Autostarts ungewöhnlichen
//! oder von Nutzern beschreibbaren Ort liegt. Sie ist kein Nachweis für
//! Schadsoftware, und ein gewöhnlicher Pfad schließt Missbrauch nicht aus.

/// Ergebnis der Pfadprüfung.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathStatus {
    /// Unterhalb des Windows-Verzeichnisses oder von `Program Files`.
    Usual,
    /// Ungewöhnlicher Ort, mit Grund.
    Unusual(&'static str),
    /// Ort ohne weiteren Kontext nicht bestimmbar, mit Grund.
    Unknown(&'static str),
}

impl PathStatus {
    /// Kurzform für den Report.
    pub(crate) fn label(self) -> &'static str {
        match self {
            PathStatus::Usual => "gewoehnlich",
            PathStatus::Unusual(_) => "auffaellig",
            PathStatus::Unknown(_) => "unbestimmt",
        }
    }
}

/// Bewertung eines Befehls aus Programmpfad und Argumenten.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CommandRating {
    /// Bewertung des Programmpfads.
    pub path: PathStatus,
    /// Programm ist ein häufig missbrauchtes Systemwerkzeug.
    pub lolbin: bool,
    /// Auffälliges Merkmal in den Argumenten, falls vorhanden.
    pub suspicious_args: Option<&'static str>,
    /// Unquotierter Programmpfad mit Leerzeichen.
    pub unquoted_space: bool,
}

/// Bewertet einen vollständigen Befehl (Programm und Argumente).
pub(crate) fn rate_command(command: &str) -> CommandRating {
    let (program, args, unquoted_space) = split_command(command);
    let (path, name) = rate_path(program);
    CommandRating {
        path,
        lolbin: is_lolbin(&name),
        suspicious_args: suspicious_args(args),
        unquoted_space,
    }
}

/// Endungen, an denen ein unquotierter Programmpfad mit Leerzeichen endet.
const EXTENSIONS: [&str; 12] = [
    ".exe", ".com", ".bat", ".cmd", ".dll", ".sys", ".ps1", ".vbs", ".js", ".scr", ".cpl", ".msc",
];

/// Trennt Programm und Argumente. Bei unquotierten Pfaden mit Leerzeichen gilt,
/// wie bei der Auflösung durch Windows, das kürzeste Präfix aus ganzen Wörtern,
/// das auf eine bekannte Programmendung endet. Ab dem ersten Schalter (`/`, `-`)
/// oder Anführungszeichen beginnen sicher die Argumente.
fn split_command(command: &str) -> (&str, &str, bool) {
    let command = command.trim();
    if let Some(rest) = command.strip_prefix('"') {
        return match rest.find('"') {
            Some(end) => (&rest[..end], &rest[end + 1..], false),
            None => (rest, "", false),
        };
    }
    let first_end = command.find(char::is_whitespace).unwrap_or(command.len());
    let mut end = 0;
    for (start, word) in words(command) {
        if start > 0 && word.starts_with(['/', '-', '"']) {
            break;
        }
        let lower = word.to_ascii_lowercase();
        if EXTENSIONS.iter().any(|ext| lower.ends_with(ext)) {
            end = start + word.len();
            break;
        }
    }
    if end == 0 {
        end = first_end;
    }
    let program = &command[..end];
    (program, &command[end..], end > first_end)
}

/// Wörter mit ihrer Byte-Position, getrennt an beliebigem Unicode-Leerraum.
fn words(s: &str) -> impl Iterator<Item = (usize, &str)> {
    let base = s.as_ptr() as usize;
    s.split_whitespace()
        .map(move |w| (w.as_ptr() as usize - base, w))
}

/// Bewertet den Programmpfad und liefert zusätzlich den Dateinamen in Kleinschreibung.
fn rate_path(program: &str) -> (PathStatus, String) {
    let mut path = program.trim().replace('/', "\\").to_ascii_lowercase();
    for prefix in ["\\??\\", "\\\\?\\"] {
        if let Some(rest) = path.strip_prefix(prefix) {
            path = rest.to_string();
        }
    }
    let name = path.rsplit('\\').next().unwrap_or("").to_string();

    if path.starts_with("\\\\") {
        return (PathStatus::Unusual("unc_pfad"), name);
    }
    if path.split('\\').any(|part| part == "..") {
        return (PathStatus::Unusual("pfad_traversal"), name);
    }

    // Umgebungsvariablen am Anfang auf den festen Ort abbilden.
    if let Some(rest) = path.strip_prefix('%') {
        let Some(end) = rest.find('%') else {
            return (PathStatus::Unknown("unvollstaendige_variable"), name);
        };
        let tail = &rest[end + 1..];
        let base = match &rest[..end] {
            "systemroot" | "windir" => "\\windows",
            "programfiles" | "programfiles(x86)" | "programw6432" => "\\program files",
            "commonprogramfiles" | "commonprogramfiles(x86)" | "commonprogramw6432" => {
                "\\program files\\common files"
            }
            "programdata" | "allusersprofile" => "\\programdata",
            "systemdrive" => "",
            "comspec" => return (PathStatus::Usual, "cmd.exe".into()),
            "localappdata" | "appdata" | "userprofile" | "temp" | "tmp" | "public" | "onedrive"
            | "homepath" => {
                return (PathStatus::Unusual("nutzerbeschreibbar"), name);
            }
            _ => return (PathStatus::Unknown("unbekannte_variable"), name),
        };
        path = format!("{base}{tail}");
    } else if let Some(rest) = path.strip_prefix("\\systemroot") {
        path = format!("\\windows{rest}");
    } else if path.as_bytes().get(1) == Some(&b':') {
        path = path[2..].to_string();
    } else if !path.starts_with('\\') {
        // Relative Pfade: Treiber und Dienste unter System32 beziehen sich auf
        // das Windows-Verzeichnis. Andere relative Angaben hängen vom
        // Arbeitsverzeichnis oder Suchpfad ab.
        if path.starts_with("system32\\") || path.starts_with("syswow64\\") {
            path = format!("\\windows\\{path}");
        } else if path.contains('\\') {
            return (PathStatus::Unknown("relativer_pfad"), name);
        } else {
            return (PathStatus::Unknown("ohne_verzeichnis"), name);
        }
    }

    (classify_absolute(&path), name)
}

/// Ordnet einen normalisierten absoluten Pfad ohne Laufwerksbuchstaben ein.
fn classify_absolute(path: &str) -> PathStatus {
    // Defender aktualisiert sich nach ProgramData; der Ordner ist geschützt.
    if path.starts_with("\\programdata\\microsoft\\windows defender\\platform\\") {
        return PathStatus::Usual;
    }
    const WRITABLE_PREFIX: [&str; 6] = [
        "\\users\\",
        "\\programdata\\",
        "\\windows\\temp\\",
        "\\windows\\tasks\\",
        "\\$recycle.bin\\",
        "\\perflogs\\",
    ];
    const WRITABLE_PART: [&str; 3] = ["\\appdata\\", "\\temp\\", "\\downloads\\"];
    if WRITABLE_PREFIX.iter().any(|p| path.starts_with(p))
        || WRITABLE_PART.iter().any(|p| path.contains(p))
    {
        return PathStatus::Unusual("nutzerbeschreibbar");
    }
    const SYSTEM_PREFIX: [&str; 3] = [
        "\\windows\\",
        "\\program files\\",
        "\\program files (x86)\\",
    ];
    if SYSTEM_PREFIX.iter().any(|p| path.starts_with(p)) {
        PathStatus::Usual
    } else {
        PathStatus::Unusual("ausserhalb_standardorte")
    }
}

/// Häufig missbrauchte Systemwerkzeuge, verglichen über den vollständigen Dateinamen.
fn is_lolbin(name: &str) -> bool {
    let name = name.strip_suffix(".exe").unwrap_or(name);
    matches!(
        name,
        "powershell"
            | "pwsh"
            | "cmd"
            | "wscript"
            | "cscript"
            | "mshta"
            | "rundll32"
            | "regsvr32"
            | "certutil"
            | "bitsadmin"
            | "msbuild"
            | "installutil"
    )
}

/// Sucht in Argumenten nach Merkmalen, die bei Systemwerkzeugen auf nachgeladenen
/// oder versteckten Code hindeuten.
fn suspicious_args(args: &str) -> Option<&'static str> {
    let args = args.to_ascii_lowercase();
    const MARKERS: [(&str, &str); 24] = [
        ("http://", "url"),
        ("https://", "url"),
        ("ftp://", "url"),
        ("\\\\", "unc_pfad"),
        ("javascript:", "skriptprotokoll"),
        ("vbscript:", "skriptprotokoll"),
        ("\\users\\", "nutzerbeschreibbar"),
        ("\\appdata\\", "nutzerbeschreibbar"),
        ("\\temp\\", "nutzerbeschreibbar"),
        ("\\programdata\\", "nutzerbeschreibbar"),
        ("\\downloads\\", "nutzerbeschreibbar"),
        ("%temp%", "nutzerbeschreibbar"),
        ("%tmp%", "nutzerbeschreibbar"),
        ("%appdata%", "nutzerbeschreibbar"),
        ("%localappdata%", "nutzerbeschreibbar"),
        ("%userprofile%", "nutzerbeschreibbar"),
        ("%public%", "nutzerbeschreibbar"),
        ("-encodedcommand", "kodiert"),
        (" -enc ", "kodiert"),
        (" -ec ", "kodiert"),
        ("frombase64string", "kodiert"),
        ("downloadstring", "download"),
        ("downloadfile", "download"),
        ("hidden", "versteckt"),
    ];
    MARKERS
        .iter()
        .find(|(m, _)| args.contains(m))
        .map(|(_, reason)| *reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(cmd: &str) -> PathStatus {
        rate_command(cmd).path
    }

    #[test]
    fn echte_microsoft_dienste_sind_gewoehnlich() {
        // ImagePath-Werte aus einem echten Windows-11-System.
        for image in [
            r#""C:\Program Files (x86)\Microsoft\Edge\Application\147.0.3912.72\elevation_service.exe""#,
            r"%systemroot%\Microsoft.NET\Framework64\v4.0.30319\SMSvcHost.exe",
            r#""%ProgramFiles%\Windows Defender Advanced Threat Protection\MsSense.exe""#,
            r"%SystemRoot%\servicing\TrustedInstaller.exe",
            r#""%PROGRAMFILES%\Windows Media Player\wmpnetwk.exe""#,
            r#""%ProgramFiles%\Windows Defender\NisSrv.exe""#,
            r#""%ProgramFiles%\Windows Defender\MsMpEng.exe""#,
            r#""C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" /svc"#,
            r"System32\drivers\disk.sys",
            r"\SystemRoot\System32\drivers\disk.sys",
            r"\??\C:\Windows\system32\drivers\mountmgr.sys",
            r"C:\Windows\System32\svchost.exe -k netsvcs",
            r"%SystemRoot%\system32\svchost.exe -k netsvcs",
            r"C:\ProgramData\Microsoft\Windows Defender\platform\4.18.1\MsMpEng.exe",
        ] {
            let r = rate_command(image);
            assert_eq!(r.path, PathStatus::Usual, "{image}");
            assert!(!r.lolbin, "{image}");
        }
    }

    #[test]
    fn nutzerbeschreibbare_und_fremde_orte() {
        assert_eq!(
            path(r"C:\Users\ich\AppData\Local\Temp\svc.exe"),
            PathStatus::Unusual("nutzerbeschreibbar")
        );
        assert_eq!(
            path(r"%localappdata%\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe"),
            PathStatus::Unusual("nutzerbeschreibbar")
        );
        assert_eq!(
            path(r"C:\ProgramData\x\run.exe"),
            PathStatus::Unusual("nutzerbeschreibbar")
        );
        assert_eq!(
            path(r"C:\Windows\Temp\x.exe"),
            PathStatus::Unusual("nutzerbeschreibbar")
        );
        assert_eq!(
            path(r"C:\Windows\System32\..\Temp\svc.exe"),
            PathStatus::Unusual("pfad_traversal")
        );
        assert_eq!(
            path(r"\\server\share\a.exe"),
            PathStatus::Unusual("unc_pfad")
        );
        assert_eq!(
            path(r"D:\system32_backup\svc.exe"),
            PathStatus::Unusual("ausserhalb_standardorte")
        );
        assert_eq!(
            path(r"D:\tools\agent.exe"),
            PathStatus::Unusual("ausserhalb_standardorte")
        );
    }

    #[test]
    fn unbestimmte_orte() {
        assert_eq!(
            path("sc.exe config upnphost start= auto"),
            PathStatus::Unknown("ohne_verzeichnis")
        );
        assert_eq!(path(r"tools\a.exe"), PathStatus::Unknown("relativer_pfad"));
        assert_eq!(
            path(r"%FOO%\a.exe"),
            PathStatus::Unknown("unbekannte_variable")
        );
        assert_eq!(
            path("%FOO"),
            PathStatus::Unknown("unvollstaendige_variable")
        );
    }

    #[test]
    fn unquotierte_pfade_mit_leerzeichen() {
        let r = rate_command(r"C:\Program Files\A B\svc.exe -k x");
        assert_eq!(r.path, PathStatus::Usual);
        assert!(r.unquoted_space);
        let r = rate_command(r"%ProgramFiles%\Windows Defender\MpCmdRun.exe Scan -ScheduleJob");
        assert_eq!(r.path, PathStatus::Usual);
        assert_eq!(r.suspicious_args, None);
        let r = rate_command(r#""C:\Program Files\A B\svc.exe" -k"#);
        assert!(!r.unquoted_space);
        // Endung nur am Wortende, nicht mitten im Namen.
        let (p, _, _) = split_command(r"C:\x.exec\a.exe /q");
        assert_eq!(p, r"C:\x.exec\a.exe");
        // Argumente mit Programmendung gehören nicht zum Pfad.
        let (p, a, space) = split_command(r"%COMSPEC% /c x > %TEMP%\e.bat");
        assert_eq!(p, "%COMSPEC%");
        assert_eq!(a, r" /c x > %TEMP%\e.bat");
        assert!(!space);
    }

    #[test]
    fn systemwerkzeuge_und_argumente() {
        let r = rate_command(r"%windir%\system32\rundll32.exe Startupscan.dll,SusRunTask");
        assert!(r.lolbin);
        assert_eq!(r.path, PathStatus::Usual);
        assert_eq!(r.suspicious_args, None);

        let r = rate_command(r"rundll32.exe C:\Users\a\x.dll,Run");
        assert!(r.lolbin);
        assert_eq!(r.suspicious_args, Some("nutzerbeschreibbar"));

        let r = rate_command(
            r"%COMSPEC% /Q /c echo dir ^> \\127.0.0.1\C$\__output 2^>^&1 > %TEMP%\execute.bat",
        );
        assert!(r.lolbin);
        assert_eq!(r.path, PathStatus::Usual);
        assert!(r.suspicious_args.is_some());

        let r = rate_command("powershell.exe -nop -w hidden -enc SQBFAFgA");
        assert!(r.lolbin);
        assert!(r.suspicious_args.is_some());

        assert!(!rate_command(r"C:\tools\notpowershell.exe").lolbin);
        assert!(!rate_command(r"C:\Windows\System32\svchost.exe --note powershell").lolbin);
    }

    #[test]
    fn keine_panik_bei_beliebiger_eingabe() {
        for s in [
            "",
            "\"",
            "%",
            "%%",
            "C:",
            "\\??\\",
            "ä.exe ö",
            "a\u{3000}b.exe c",
            "a\u{3000}/x",
            "\"ä",
            " .exe",
            "x:ü",
        ] {
            let _ = rate_command(s);
        }
    }
}
