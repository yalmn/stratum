//! Normalizer: bildet die Rohfunde der Engine auf das gemeinsame Datenmodell
//! (`stratum-model`) ab.
//!
//! Je Domäne gibt es einen Mapper. Er erzeugt aus einem Rohfund ein Artefakt
//! mit Fundstelle, eine Observation mit den gelesenen Feldern, die
//! beteiligten Entitäten, Ereignisse und Beziehungen und für jedes Ereignis
//! und jede Beziehung eine Herkunftsangabe. Entitäten und Beziehungen werden
//! über ihre abgeleiteten IDs zusammengeführt; erstmals und zuletzt gesehen
//! wachsen mit jedem Beleg.
//!
//! Was nicht abgebildet werden kann, wird gezählt, nicht verworfen: Funde
//! ohne Mapper, Funde mit unvollständiger Fundstelle und Hinweise erscheinen
//! in der Statistik des Ergebnisses.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod aktivitaet;
mod browser;
mod evtx;
mod hilfen;
mod persistenz;
mod prefetch;
mod programm;
mod srum;
mod usb;
mod zugangsdaten;

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::Serialize;
use stratum_analysis::RawFinding;
use stratum_model::{
    Artifact, CaseId, DerivationKind, Entity, EntityId, EntityKind, Event, EventId,
    EventParticipant, EvidenceId, ObjectRef, Observation, ParserIdentity, ProvenanceLink,
    ProvenanceRef, ProvenanceRole, Relationship, RelationshipId, RelationshipKind,
};

/// Rahmen eines Normalisierungslaufs.
#[derive(Debug, Clone)]
pub struct Kontext {
    /// Fall.
    pub case_id: CaseId,
    /// Evidence.
    pub evidence_id: EvidenceId,
    /// SHA-256 der Evidence (hex). Ohne Hash ein Ersatzschlüssel; die IDs sind
    /// dann nur innerhalb dieses Laufs belastbar.
    pub evidence_sha256: String,
    /// Rechnername des untersuchten Systems, falls bekannt.
    pub host: Option<String>,
    /// Version von stratum (mit Revision).
    pub stratum_version: String,
    /// Zeitpunkt des Laufs (Analysezeit).
    pub zeitpunkt: DateTime<Utc>,
}

/// Zählungen je Domäne.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct Statistik {
    /// Abgebildete Rohfunde.
    pub abgebildet: BTreeMap<String, usize>,
    /// Rohfunde ohne Mapper.
    pub ohne_mapper: BTreeMap<String, usize>,
    /// Abgebildete Rohfunde mit unvollständiger Fundstelle (etwa ohne
    /// MFT-Nummer oder ohne Image-Offset).
    pub fundstelle_unvollstaendig: BTreeMap<String, usize>,
}

/// Ergebnis der Normalisierung.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Modell {
    /// Artefakte.
    pub artifacts: Vec<Artifact>,
    /// Observationen.
    pub observations: Vec<Observation>,
    /// Entitäten (zusammengeführt).
    pub entities: Vec<Entity>,
    /// Ereignisse.
    pub events: Vec<Event>,
    /// Beteiligungen an Ereignissen.
    pub participants: Vec<EventParticipant>,
    /// Beziehungen (zusammengeführt).
    pub relationships: Vec<Relationship>,
    /// Herkunft von Ereignissen und Beziehungen.
    pub provenance: Vec<ProvenanceLink>,
    /// Zählungen.
    pub statistik: Statistik,
    /// Hinweise.
    pub hinweise: Vec<String>,
}

/// Sammelt die Ergebnisse und führt Entitäten und Beziehungen zusammen.
pub(crate) struct Baukasten<'k> {
    pub k: &'k Kontext,
    pub personen: hilfen::Personen,
    pub dienste: hilfen::Dienste,
    modell: Modell,
    entities: BTreeMap<EntityId, Entity>,
    relationships: BTreeMap<RelationshipId, Relationship>,
    ereignisse: BTreeSet<EventId>,
}

impl<'k> Baukasten<'k> {
    fn new(k: &'k Kontext, personen: hilfen::Personen, dienste: hilfen::Dienste) -> Self {
        Self {
            k,
            personen,
            dienste,
            modell: Modell::default(),
            entities: BTreeMap::new(),
            relationships: BTreeMap::new(),
            ereignisse: BTreeSet::new(),
        }
    }

    /// Parser-Angabe für eine Domäne.
    pub fn parser(&self, domain: &str) -> ParserIdentity {
        ParserIdentity {
            name: format!("stratum.{domain}"),
            version: self.k.stratum_version.clone(),
            stratum_version: self.k.stratum_version.clone(),
            config_hash: None,
        }
    }

    pub fn artifact(&mut self, a: Artifact) {
        self.modell.artifacts.push(a);
    }

    pub fn observation(&mut self, o: Observation) {
        self.modell.observations.push(o);
    }

    /// Entität aufnehmen oder mit einer vorhandenen zusammenführen; liefert
    /// ihre ID. Spätere Belege ergänzen fehlende Attribute, und ein Name
    /// ersetzt einen Anzeigenamen, der nur die SID war. `gesehen` erweitert
    /// erstmals und zuletzt gesehen.
    pub fn entity(&mut self, e: Entity, gesehen: Option<DateTime<Utc>>) -> EntityId {
        let id = e.id;
        let eintrag = match self.entities.entry(id) {
            std::collections::btree_map::Entry::Vacant(v) => v.insert(e),
            std::collections::btree_map::Entry::Occupied(o) => {
                let eintrag = o.into_mut();
                let nur_sid = |n: &str| n.starts_with("S-1-");
                if nur_sid(&eintrag.display_name)
                    && !nur_sid(&e.display_name)
                    && !e.display_name.is_empty()
                {
                    eintrag.display_name = e.display_name;
                }
                if let (Some(alt), serde_json::Value::Object(neu)) =
                    (eintrag.attributes.as_object_mut(), e.attributes)
                {
                    for (k, v) in neu {
                        alt.entry(k).or_insert(v);
                    }
                }
                eintrag
            }
        };
        if let Some(t) = gesehen {
            eintrag.first_seen = Some(eintrag.first_seen.map_or(t, |f| f.min(t)));
            eintrag.last_seen = Some(eintrag.last_seen.map_or(t, |l| l.max(t)));
        }
        id
    }

    /// Attribute einer vorhandenen Entität ergänzen; vorhandene Werte
    /// bleiben.
    pub fn entity_attribute(&mut self, id: EntityId, neu: serde_json::Value) {
        let (Some(e), serde_json::Value::Object(neu)) = (self.entities.get_mut(&id), neu) else {
            return;
        };
        if !e.attributes.is_object() {
            e.attributes = serde_json::json!({});
        }
        if let Some(alt) = e.attributes.as_object_mut() {
            for (k, v) in neu {
                alt.entry(k).or_insert(v);
            }
        }
    }

    /// Ereignis aufnehmen. Belegt eine weitere Quelle dasselbe Ereignis
    /// (gleiche abgeleitete ID), wird nur ihre Herkunft als stützend
    /// angehängt.
    pub fn event(&mut self, e: Event, teilnehmer: Vec<EventParticipant>, herkunft: ProvenanceRef) {
        let neu = self.ereignisse.insert(e.id);
        self.modell.provenance.push(ProvenanceLink {
            object: ObjectRef::Event(e.id),
            provenance: herkunft,
            role: if neu {
                ProvenanceRole::Primary
            } else {
                ProvenanceRole::Supporting
            },
        });
        if neu {
            self.modell.participants.extend(teilnehmer);
            self.modell.events.push(e);
        }
    }

    /// Beziehung aufnehmen; ein weiterer Beleg derselben Beziehung wird als
    /// stützende Herkunft angehängt.
    pub fn relationship(&mut self, r: Relationship, herkunft: ProvenanceRef) {
        let rolle = if self.relationships.contains_key(&r.id) {
            ProvenanceRole::Supporting
        } else {
            ProvenanceRole::Primary
        };
        self.modell.provenance.push(ProvenanceLink {
            object: ObjectRef::Relationship(r.id),
            provenance: herkunft,
            role: rolle,
        });
        self.relationships.entry(r.id).or_insert(r);
    }

    pub fn hinweis(&mut self, h: String) {
        self.modell.hinweise.push(h);
    }

    /// Dateien mit gleichem Pfad, einmal unter einem Laufwerksbuchstaben und
    /// einmal unter einem Gerätepfad (`\\Device\\HarddiskVolumeN`), sind
    /// möglicherweise dieselbe Datei. Sicher ist das nicht, weil die
    /// Zuordnung von Buchstabe zu Gerät hier nicht geprüft wird; die
    /// Beziehung ist deshalb korreliert.
    fn gleiche_pfade_verbinden(&mut self) {
        let mut gruppen: BTreeMap<&str, (Vec<EntityId>, Vec<EntityId>)> = BTreeMap::new();
        for e in self.entities.values() {
            if e.kind != EntityKind::File {
                continue;
            }
            let (Some(volume), Some(rest)) = (
                e.attributes.get("volume").and_then(|v| v.as_str()),
                e.attributes
                    .get("pfad_ohne_volume")
                    .and_then(|v| v.as_str()),
            ) else {
                continue;
            };
            let g = gruppen.entry(rest).or_default();
            if volume.len() == 2 && volume.ends_with(':') {
                g.0.push(e.id);
            } else if volume.starts_with("harddiskvolume") {
                g.1.push(e.id);
            }
        }
        let mut neu = Vec::new();
        for (rest, (buchstaben, geraete)) in gruppen {
            for &l in &buchstaben {
                for &d in &geraete {
                    let mut r = Relationship::new(
                        self.k.case_id,
                        RelationshipKind::PossiblySameAs,
                        l,
                        d,
                        DerivationKind::Correlated,
                    );
                    r.attributes = serde_json::json!({
                        "grundlage": "gleicher_pfad_ohne_volume",
                        "pfad_ohne_volume": rest,
                    });
                    neu.push(r);
                }
            }
        }
        let parser = self.parser("korrelation");
        for r in neu {
            let herkunft = ProvenanceRef {
                evidence_id: self.k.evidence_id,
                artifact_id: None,
                observation_id: None,
                source_locator: None,
                parser: Some(parser.clone()),
                analysis_run_id: None,
            };
            self.relationship(r, herkunft);
        }
    }

    fn fertig(mut self) -> Modell {
        self.modell.entities = self.entities.into_values().collect();
        self.modell.relationships = self.relationships.into_values().collect();
        self.modell
    }
}

/// Ergebnis eines Mappers für einen Rohfund.
pub(crate) enum Abbildung {
    /// Abgebildet, Fundstelle vollständig.
    Vollstaendig,
    /// Abgebildet, Fundstelle unvollständig.
    FundstelleUnvollstaendig,
}

/// Bildet alle Rohfunde ab.
pub fn normalisieren(funde: &[RawFinding], k: &Kontext) -> Modell {
    let mut b = Baukasten::new(
        k,
        hilfen::Personen::aus_funden(funde),
        hilfen::Dienste::aus_funden(funde),
    );
    for f in funde {
        let ergebnis = match f.domain.as_str() {
            "eventlog" => Some(evtx::abbilden(f, &mut b)),
            "prefetch" => Some(prefetch::abbilden(f, &mut b)),
            "usb" => Some(usb::abbilden(f, &mut b)),
            "programmausfuehrung" => Some(programm::abbilden(f, &mut b)),
            "useraktivitaet" => Some(aktivitaet::abbilden(f, &mut b)),
            "persistence" => Some(persistenz::abbilden(f, &mut b)),
            // Zugangsdaten nur mit Metadaten, der Geheimwert bleibt im Report.
            "browser"
                if f.attributes.get("art").map(String::as_str) == Some("passwort_klartext") =>
            {
                Some(zugangsdaten::abbilden(f, &mut b))
            }
            "lsa" | "dpapi" => Some(zugangsdaten::abbilden(f, &mut b)),
            "browser" => Some(browser::abbilden(f, &mut b)),
            "srum" => Some(srum::abbilden(f, &mut b)),
            _ => None,
        };
        let zaehler = match ergebnis {
            None => &mut b.modell.statistik.ohne_mapper,
            Some(Abbildung::Vollstaendig) => &mut b.modell.statistik.abgebildet,
            Some(Abbildung::FundstelleUnvollstaendig) => {
                *b.modell
                    .statistik
                    .fundstelle_unvollstaendig
                    .entry(f.domain.clone())
                    .or_default() += 1;
                &mut b.modell.statistik.abgebildet
            }
        };
        *zaehler.entry(f.domain.clone()).or_default() += 1;
    }
    b.gleiche_pfade_verbinden();
    b.fertig()
}

/// Ableitungsstatus eines Objekts, das aus genau einem Rohfund gelesen wird.
pub(crate) const GELESEN: DerivationKind = DerivationKind::Parsed;

#[cfg(test)]
mod tests;
