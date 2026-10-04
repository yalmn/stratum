//! Echter Offline-Container auf der Linux-VM, keine externe Zielverbindung.
#[test]
#[ignore = "benötigt Linux, Docker und lokal gebautes stratum-http-lab:v1"]
fn isolierter_http_versuch() {
    use stratum_model::http_lab::{HttpDirection, HttpReplayRequest};
    let p = HttpReplayRequest {
        direction: HttpDirection::Incoming,
        url: "http://web01.invalid/admin/export?fixture=1".into(),
        method: "POST".into(),
        headers: vec![["Content-Type".into(), "application/json".into()]],
        body: "{\"fixture\":true}".into(),
        simulated_status: 403,
        simulated_body: "Synthetic denial".into(),
        hypothesis: "Eingehenden Request synthetisch prüfen".into(),
        source: None,
    };
    let result = stratum_connectors::http_lab::replay(&p, &|| false)
        .expect("Offline-Container muss funktionieren");
    assert_eq!(result["network_policy"], "none");
    assert_eq!(result["exchange"]["peer_ip"], "127.0.0.1");
    assert_eq!(result["exchange"]["status"], 403);
    assert!(result["exchange"]["request_wire"]
        .as_str()
        .unwrap()
        .contains("POST /admin/export?fixture=1 HTTP/1.1"));
    assert!(result["exchange"]["response_wire"]
        .as_str()
        .unwrap()
        .ends_with("Synthetic denial"));
    assert_eq!(result["exchange"]["tls_replayed"], false);
}
