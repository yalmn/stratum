use crate::ConnectorFehler as YaraFehler;
use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub(crate) fn ausfuehren(
    mut cmd: Command,
    timeout: Duration,
    abbruch: &dyn Fn() -> bool,
) -> Result<String, YaraFehler> {
    cmd.stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());
    let mut child = cmd.spawn()?;
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
        if out.len() > 1024 * 1024 || err.len() > 1024 * 1024 {
            return Err(YaraFehler::Eingabe("Ausgabelimit überschritten".into()));
        }
        if !status.success() || !err.is_empty() {
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
        String::from_utf8(out).map_err(|_| YaraFehler::Eingabe("Ausgabe nicht UTF-8".into()))
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
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
}
