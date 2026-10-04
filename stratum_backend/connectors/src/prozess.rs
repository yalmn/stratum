use crate::ConnectorFehler as YaraFehler;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub(crate) fn ausfuehren(
    cmd: Command,
    timeout: Duration,
    abbruch: &dyn Fn() -> bool,
) -> Result<String, YaraFehler> {
    ausgabe(cmd, timeout, abbruch, false, None)
}

pub(crate) fn mit_eingabe(
    cmd: Command,
    input: &[u8],
    timeout: Duration,
    abbruch: &dyn Fn() -> bool,
) -> Result<String, YaraFehler> {
    ausgabe(cmd, timeout, abbruch, false, Some(input))
}

pub(crate) fn version(cmd: Command, abbruch: &dyn Fn() -> bool) -> Result<String, YaraFehler> {
    ausgabe(cmd, Duration::from_secs(5), abbruch, true, None)
}

fn ausgabe(
    mut cmd: Command,
    timeout: Duration,
    abbruch: &dyn Fn() -> bool,
    versionsabfrage: bool,
    input: Option<&[u8]>,
) -> Result<String, YaraFehler> {
    cmd.stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
    let mut child = cmd.spawn()?;
    let stdin = child.stdin.take();
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| YaraFehler::Eingabe("stdout fehlt".into()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| YaraFehler::Eingabe("stderr fehlt".into()))?;
    let zu_gross = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let writer = input
            .zip(stdin)
            .map(|(data, mut pipe)| scope.spawn(move || pipe.write_all(data)));
        let lesen = |mut pipe: Box<dyn Read + Send>| -> Result<Vec<u8>, std::io::Error> {
            let mut data = Vec::new();
            pipe.by_ref().take(1024 * 1024 + 1).read_to_end(&mut data)?;
            if data.len() > 1024 * 1024 {
                zu_gross.store(true, Ordering::Relaxed);
            }
            Ok(data)
        };
        let out = scope.spawn(move || lesen(Box::new(stdout)));
        let err = scope.spawn(move || lesen(Box::new(stderr)));
        let start = Instant::now();
        let status = loop {
            if abbruch() || start.elapsed() > timeout || zu_gross.load(Ordering::Relaxed) {
                let _ = child.kill();
                let _ = child.wait();
                break Err(if abbruch() {
                    YaraFehler::Abgebrochen
                } else {
                    YaraFehler::Eingabe(
                        "Zeit- oder Ausgabelimit erreicht; kein vollständiges Ergebnis".into(),
                    )
                });
            }
            match child.try_wait() {
                Ok(Some(s)) => break Ok(s),
                Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break Err(e.into());
                }
            }
        };
        let out = out
            .join()
            .map_err(|_| YaraFehler::Eingabe("Ausgabeleser abgebrochen".into()))??;
        let err = err
            .join()
            .map_err(|_| YaraFehler::Eingabe("Fehlerleser abgebrochen".into()))??;
        let status = status?;
        if let Some(writer) = writer {
            writer
                .join()
                .map_err(|_| YaraFehler::Eingabe("Eingabeschreiber abgebrochen".into()))??;
        }
        if out.len() > 1024 * 1024 || err.len() > 1024 * 1024 {
            return Err(YaraFehler::Eingabe("Ausgabelimit überschritten".into()));
        }
        if !status.success() || (!versionsabfrage && !err.is_empty()) {
            return Err(YaraFehler::Eingabe(format!(
                "Werkzeugfehler: {}",
                format!(
                    "Exit {}: {} {}",
                    status,
                    String::from_utf8_lossy(&err),
                    String::from_utf8_lossy(&out)
                )
                .chars()
                .take(32768)
                .collect::<String>()
            )));
        }
        let mut text = String::from_utf8(out)
            .map_err(|_| YaraFehler::Eingabe("Ausgabe nicht UTF-8".into()))?;
        if versionsabfrage && !err.is_empty() {
            if !text.is_empty() {
                text.push('\n');
            }
            text.push_str(
                &String::from_utf8(err)
                    .map_err(|_| YaraFehler::Eingabe("Versionsausgabe nicht UTF-8".into()))?,
            );
        }
        Ok(text)
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[test]
    fn begrenzte_eingabe_und_abbruch() {
        let data = vec![b'x'; 128 * 1024];
        let out = mit_eingabe(
            Command::new("/bin/cat"),
            &data,
            Duration::from_secs(5),
            &|| false,
        )
        .unwrap();
        assert_eq!(out.as_bytes(), data);
        let mut cmd = Command::new("/bin/sleep");
        cmd.arg("10");
        assert!(matches!(
            mit_eingabe(cmd, &data, Duration::from_secs(5), &|| true),
            Err(YaraFehler::Abgebrochen)
        ));
    }
    #[test]
    fn prozessgrenzen_und_abbruch() {
        let mut cmd = Command::new("/bin/sleep");
        cmd.arg("10");
        assert!(ausfuehren(cmd, Duration::from_millis(30), &|| false).is_err());
        let mut cmd = Command::new("/bin/sleep");
        cmd.arg("10");
        assert!(matches!(
            ausfuehren(cmd, Duration::from_secs(10), &|| true),
            Err(YaraFehler::Abgebrochen)
        ));
        let cmd = Command::new("/usr/bin/yes");
        assert!(ausfuehren(cmd, Duration::from_secs(3), &|| false).is_err());
    }

    #[test]
    fn version_auf_stderr_ist_kein_abfragefehler() {
        let command = || {
            let mut c = Command::new("/bin/sh");
            c.args(["-c", "printf 'nslookup 9.18.39\\n' >&2"]);
            c
        };
        assert_eq!(
            version(command(), &|| false).unwrap().trim(),
            "nslookup 9.18.39"
        );
        assert!(ausfuehren(command(), Duration::from_secs(5), &|| false).is_err());
        let mut c = Command::new("/bin/sh");
        c.args(["-c", "printf 'Fehler' >&2; exit 1"]);
        assert!(version(c, &|| false).is_err());
    }
}
