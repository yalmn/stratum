//! HTTP-Versuche ausschließlich im abgeschotteten Offline-Container.
use crate::{prozess, ConnectorFehler};
use serde_json::{json, Value};
use std::process::Command;
use std::time::Duration;
use stratum_model::http_lab::HttpReplayRequest;

const IMAGE: &str = "stratum-http-lab:v1";
const DOCKER: &str = "/usr/bin/docker";

fn command(args: &[&str]) -> Command {
    let mut c = Command::new(DOCKER);
    c.args(args);
    c
}

fn create(name: &str, image: &str) -> Command {
    command(&[
        "create",
        "--pull=never",
        "--name",
        name,
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--user=65534:65534",
        "--pids-limit=32",
        "--memory=128m",
        "--memory-swap=128m",
        "--cpus=1",
        "--interactive",
        "--entrypoint=python3",
        image,
        "-I",
        "-B",
        "/lab/runner.py",
    ])
}

/// Ausführung mit geschlossenem Netzwerk und ohne Evidence-/Host-Mounts.
/// Bei fehlendem Docker oder Image gibt es keinen unisolierten Fallback.
pub fn replay(
    request: &HttpReplayRequest,
    cancel: &dyn Fn() -> bool,
) -> Result<Value, ConnectorFehler> {
    request.pruefen().map_err(ConnectorFehler::Eingabe)?;
    if !cfg!(target_os = "linux") {
        return Err(ConnectorFehler::Eingabe(
            "HTTP-Lab benötigt den Linux-Worker mit Docker und lokal gebautem stratum-http-lab:v1"
                .into(),
        ));
    }
    let mut normalized = request.clone();
    normalized.url = url::Url::parse(&request.url)
        .map_err(|_| ConnectorFehler::Eingabe("URL ungültig".into()))?
        .to_string();
    let version = prozess::version(command(&["--version"]), cancel)?;
    let image = prozess::ausfuehren(
        command(&["image", "inspect", "--format={{.Id}}", IMAGE]),
        Duration::from_secs(5),
        cancel,
    )?;
    let image = image.trim();
    if !image.starts_with("sha256:")
        || image.len() != 71
        || !image[7..].bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(ConnectorFehler::Eingabe("Lab-Image-ID ungültig".into()));
    }
    let name = format!("stratum-http-{}", uuid::Uuid::now_v7());
    let result = (|| {
        prozess::ausfuehren(create(&name, image), Duration::from_secs(10), cancel)?;
        let bytes =
            serde_json::to_vec(&normalized).map_err(|e| ConnectorFehler::Eingabe(e.to_string()))?;
        let raw = prozess::mit_eingabe(
            command(&["start", "--attach", "--interactive", &name]),
            &bytes,
            Duration::from_secs(30),
            cancel,
        )?;
        let r: Value = serde_json::from_str(&raw)
            .map_err(|_| ConnectorFehler::Eingabe("Lab-Ausgabe kein vollständiges JSON".into()))?;
        if r["network_interfaces"] != json!(["lo"])
            || !r["python_version"].is_string()
            || r["runner"] != "stratum-http-offline-v1"
            || r["peer_ip"] != "127.0.0.1"
            || r["original_url"] != normalized.url
            || r["status"] != request.simulated_status
            || r["transport"] != "http_loopback"
            || r["tls_replayed"] != false
            || r["redirects_followed"] != 0
            || !r["request_wire"].is_string()
            || !r["response_wire"].is_string()
        {
            return Err(ConnectorFehler::Eingabe(
                "Lab-Ausgabe verletzt den Offline-Vertrag".into(),
            ));
        }
        Ok(
            json!({"exchange":r, "image_id":image, "docker_version":version.trim(), "network_policy":"none", "runner":"stratum-http-offline-v1"}),
        )
    })();
    // Nur der für diesen Versuch erzeugte Container wird entfernt.
    let cleanup = prozess::ausfuehren(
        command(&["rm", "--force", &name]),
        Duration::from_secs(10),
        &|| false,
    );
    match (result, cleanup) {
        (Ok(r), Ok(_)) => Ok(r),
        (Err(e), _) => Err(e),
        (_, Err(_)) => Err(ConnectorFehler::Eingabe(
            "Lab beendet, aber Container konnte nicht entfernt werden".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn isolation_ohne_mounts_oder_egress() {
        let c = create("stratum-http-fixture", "sha256:fixture");
        let args: Vec<_> = c
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        for required in [
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--user=65534:65534",
            "--pull=never",
            "--memory=128m",
            "--cpus=1",
        ] {
            assert!(args.iter().any(|a| a == required));
        }
        assert!(!args.iter().any(|a| a.contains("mount")
            || a.contains("volume")
            || a.contains("privileged")
            || a.contains("publish")));
    }
}
