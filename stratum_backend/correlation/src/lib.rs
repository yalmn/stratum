//! Begrenzte Kontextregeln. Ein Treffer belegt weder Identität einer Ausführung
//! noch Kausalität oder eine erfolgreiche Persistenz.
#![forbid(unsafe_code)]
#![warn(missing_docs)]
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use stratum_model::{
    CaseId, DerivationKind, ForensicTime, ProvenanceRef, SourceLocator, TimePrecision,
    TimeSemantics,
};
use uuid::Uuid;

/// Feste Regeldefinition, Bestandteil der reproduzierbaren Auswertung.
#[derive(Debug, Serialize)]
pub struct Rule {
    /// Stabile Regelkennung.
    pub id: &'static str,
    /// Fachliche Version.
    pub version: &'static str,
    /// Titel für die Oberfläche.
    pub title: &'static str,
    /// Maximale Differenz der Quellzeiten in Sekunden.
    pub window_seconds: i64,
    /// Aussagegrenze.
    pub limitation: &'static str,
}
/// Aktuell unterstützte Regeln, ohne frei ausführbare Regeltexte.
pub const RULES: [Rule; 3] = [
    Rule { id: "execution-sources", version: "1", title: "Different execution sources", window_seconds: 2, limitation: "Different parsers report execution for the same normalized executable within two seconds. This does not establish the same process instance." },
    Rule { id: "persistence-activity", version: "1", title: "Persistence creation and activity", window_seconds: 86400, limitation: "Creation and activity refer to the same normalized service or task within 24 hours. Creation may use artifact time. This does not prove malicious or successful persistence." },
    Rule { id: "process-network", version: "1", title: "Process and network context", window_seconds: 300, limitation: "Process start precedes network activity for the same normalized process within five minutes. PID reuse and clock errors remain possible; causality is not established." },
];
/// Eine Ereignisbeteiligung mit einer konkreten Quellstelle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trace {
    /// Ereigniskennung.
    pub event_id: Uuid,
    /// Ereignisart des Modells.
    pub kind: String,
    /// Gemeinsame Entität, nie nur Dateiname oder PID.
    pub entity_id: Uuid,
    /// Entitätsart.
    pub entity_kind: String,
    /// Rolle dieser Beteiligung.
    pub role: String,
    /// Rechnerkontext.
    pub host_id: Uuid,
    /// Quellstand aus der Observation, live oder VSS#n.
    #[serde(default)]
    pub snapshot: Option<String>,
    /// Ursprüngliche Zeitangabe, nicht die Erfassungszeit.
    pub time: ForensicTime,
    /// Ableitungsstatus des Ereignisses.
    pub derivation: DerivationKind,
    /// Quelle mit unverändertem Parser und Byte-Anker.
    pub source: ProvenanceRef,
}
/// Ergebnis einer Kontextregel mit vollständigen Eingabeverweisen.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Match {
    /// Deterministische UUIDv5 über Regelversion und Quellen.
    pub id: Uuid,
    /// Fall.
    pub case_id: CaseId,
    /// Regelkennung.
    pub rule_id: String,
    /// Regelversion.
    pub rule_version: String,
    /// Kein beobachteter Fakt.
    pub derivation: DerivationKind,
    /// Quellen in zeitlicher Reihenfolge.
    pub traces: [Trace; 2],
}
/// Begrenzte Auswertung mit sichtbarer Unvollständigkeit.
#[derive(Debug, Serialize)]
pub struct Evaluation {
    /// Eindeutige Treffer.
    pub matches: Vec<Match>,
    /// Paarvergleiche.
    pub comparisons: usize,
    /// Eingabezahl vor fachlicher Prüfung.
    pub input_count: usize,
    /// Ausgeschlossene Quellen, etwa ohne Byte-Anker oder mit unklarer Zeit.
    pub excluded_count: usize,
    /// Schutzgrenze erreicht; niemals als vollständiger Nullbefund ausgeben.
    pub limited: bool,
}
fn source_scope(t: &Trace) -> Option<String> {
    t.source.artifact_id?;
    let p = t.source.parser.as_ref()?;
    if p.name.is_empty() || p.version.is_empty() {
        return None;
    }
    let locator = t.source.source_locator.as_ref()?;
    let scope = match locator {
        SourceLocator::Ntfs {
            record_offset,
            byte_offset,
            image_offset,
            shadow_copy,
            ..
        } => {
            if record_offset.is_none() && byte_offset.is_none() && image_offset.is_none() {
                return None;
            }
            match shadow_copy {
                Some(s) => format!("VSS#{}", s.store.checked_add(1)?),
                None => "live".into(),
            }
        }
        SourceLocator::ByteRange {
            length: Some(0), ..
        } => return None,
        SourceLocator::ByteRange { .. } => t.snapshot.clone().unwrap_or_else(|| "live".into()),
        SourceLocator::Registry {
            cell_offset: Some(_),
            ..
        }
        | SourceLocator::FileLine {
            byte_offset: Some(_),
            ..
        }
        | SourceLocator::Ese { .. } => t.snapshot.clone()?,
        _ => return None,
    };
    if let Some(marker) = &t.snapshot {
        if matches!(locator, SourceLocator::Ntfs { .. }) && marker != &scope {
            return None;
        }
    }
    if scope != "live"
        && scope
            .strip_prefix("VSS#")
            .and_then(|s| s.parse::<u32>().ok())
            .is_none_or(|n| n == 0)
    {
        return None;
    }
    Some(scope)
}
fn eligible(t: &Trace) -> bool {
    matches!(
        t.derivation,
        DerivationKind::Observed | DerivationKind::Parsed | DerivationKind::Derived
    ) && matches!(
        t.time.precision,
        TimePrecision::Nanosecond
            | TimePrecision::HundredNanoseconds
            | TimePrecision::Microsecond
            | TimePrecision::Millisecond
            | TimePrecision::Second
    ) && matches!(
        t.time.semantics,
        TimeSemantics::EventTime | TimeSemantics::ArtifactTime
    ) && source_scope(t).is_some()
}
fn rule_for(a: &Trace, b: &Trace, seconds: i64) -> Option<&'static Rule> {
    if a.event_id == b.event_id || a.source.artifact_id == b.source.artifact_id {
        return None;
    }
    if a.kind == "process_start"
        && b.kind == "process_start"
        && matches!(a.entity_kind.as_str(), "file" | "application")
        && a.role == "executable"
        && b.role == "executable"
        && a.time.semantics == TimeSemantics::EventTime
        && b.time.semantics == TimeSemantics::EventTime
        && a.source.parser.as_ref()?.name != b.source.parser.as_ref()?.name
        && seconds <= RULES[0].window_seconds
    {
        return Some(&RULES[0]);
    }
    let persistence = (a.entity_kind == "service"
        && a.kind == "service_installed"
        && b.kind == "service_started")
        || (a.entity_kind == "scheduled_task"
            && a.kind == "scheduled_task_created"
            && b.kind == "scheduled_task_executed");
    if persistence
        && b.time.semantics == TimeSemantics::EventTime
        && seconds <= RULES[1].window_seconds
    {
        return Some(&RULES[1]);
    }
    if a.entity_kind == "process"
        && a.role == "process"
        && b.role == "process"
        && a.kind == "process_start"
        && matches!(
            b.kind.as_str(),
            "network_connection" | "dns_query" | "http_request"
        )
        && a.time.semantics == TimeSemantics::EventTime
        && b.time.semantics == TimeSemantics::EventTime
        && seconds <= RULES[2].window_seconds
    {
        return Some(&RULES[2]);
    }
    None
}
/// Wertet nach Fall, Entität, Host, Evidence und Schattenstand getrennt aus.
/// Höchstens 200000 Paarvergleiche und 500 Treffer; andere Quellstände werden
/// nicht gleichgesetzt. Die übergebenen Quellen müssen bereits fallgeprüft sein.
pub fn evaluate(case: CaseId, input: Vec<Trace>) -> Evaluation {
    let count = input.len();
    let mut groups = BTreeMap::new();
    let mut excluded = 0;
    for t in input {
        if !eligible(&t) {
            excluded += 1;
            continue;
        }
        let key = (
            t.entity_id,
            t.host_id,
            t.source.evidence_id,
            source_scope(&t),
        );
        groups.entry(key).or_insert_with(Vec::new).push(t);
    }
    let mut result = Evaluation {
        matches: Vec::new(),
        comparisons: 0,
        input_count: count,
        excluded_count: excluded,
        limited: false,
    };
    let mut seen = BTreeSet::new();
    for group in groups.values_mut() {
        group.sort_by_key(|t| (t.time.utc, t.event_id, t.source.artifact_id));
        for (i, a) in group.iter().enumerate() {
            for b in &group[i + 1..] {
                let delta = b.time.utc.signed_duration_since(a.time.utc);
                if delta.num_seconds() > 86400 {
                    break;
                }
                if result.comparisons == 200000 || result.matches.len() == 500 {
                    result.limited = true;
                    return result;
                }
                result.comparisons += 1;
                // Grenzen mit voller Zeitpräzision prüfen, nicht auf Sekunden abrunden.
                let (a, b, rule) = if let Some(rule) = rule_for(a, b, delta.num_seconds()) {
                    (a, b, rule)
                } else if delta.is_zero() {
                    let Some(rule) = rule_for(b, a, 0) else {
                        continue;
                    };
                    (b, a, rule)
                } else {
                    continue;
                };
                if delta
                    .num_nanoseconds()
                    .is_none_or(|n| n > rule.window_seconds * 1_000_000_000)
                {
                    continue;
                }
                let mut stable_a = a.clone();
                let mut stable_b = b.clone();
                stable_a.source.analysis_run_id = None;
                stable_b.source.analysis_run_id = None;
                let signature =
                    serde_json::to_vec(&(case, rule.id, rule.version, stable_a, stable_b))
                        .unwrap_or_default();
                if signature.is_empty() {
                    continue;
                }
                let id = stratum_model::ids::derived_uuid("correlation", &[&signature]);
                if seen.insert(id) {
                    result.matches.push(Match {
                        id,
                        case_id: case,
                        rule_id: rule.id.into(),
                        rule_version: rule.version.into(),
                        derivation: DerivationKind::Correlated,
                        traces: [a.clone(), b.clone()],
                    });
                }
            }
        }
    }
    result.matches.sort_by_key(|m| m.id);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    fn registry(snapshot: serde_json::Value) -> Trace {
        serde_json::from_value(serde_json::json!({
            "event_id":Uuid::from_u128(1),"kind":"process_start","entity_id":Uuid::from_u128(2),
            "entity_kind":"file","role":"executable","host_id":Uuid::from_u128(3),"snapshot":snapshot,
            "time":{"utc":"2026-01-01T00:00:00Z","original":null,"timezone":null,"precision":"second","semantics":"event_time"},"derivation":"parsed",
            "source":{"evidence_id":Uuid::from_u128(4),"artifact_id":Uuid::from_u128(5),"observation_id":null,
            "source_locator":{"type":"registry","hive":"SYSTEM","key_path":"Fixture","value_name":null,"cell_offset":4096},
            "parser":{"name":"fixture","version":"1","stratum_version":"test","config_hash":null},"analysis_run_id":null}
        })).unwrap()
    }
    #[test]
    fn registry_ohne_quellstand_nicht_als_live_ausgeben() {
        assert!(!eligible(&registry(serde_json::Value::Null)));
        assert!(eligible(&registry(serde_json::json!("live"))));
        assert_eq!(
            source_scope(&registry(serde_json::json!("VSS#1"))).as_deref(),
            Some("VSS#1")
        );
        for marker in ["VSS#0", "VSS#unknown", "", "live-other", "VSS#4294967296"] {
            assert!(!eligible(&registry(serde_json::json!(marker))), "{marker}");
        }
    }
}
