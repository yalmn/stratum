//! Keyword- und Muster-Suche über Roh-Images.
//!
//! Gesucht wird anhand einer Begriffstabelle, die pro Fall gepflegt und
//! versioniert wird (siehe [`TermTable`]). Die Begriffe stehen bewusst nicht im
//! Code, damit im Report nachvollziehbar bleibt, wonach gesucht wurde, und
//! damit sich das Rauschen pro Fall über die aktiven Kategorien steuern lässt.
//!
//! Ein Durchlauf findet alle Begriffe gleichzeitig (Aho-Corasick), jeweils in
//! ASCII und in UTF-16LE, da Windows Text meist als UTF-16LE ablegt. Kategorien
//! im Modus [`Modus::Paar`] melden nur dann einen Treffer, wenn ein Begriff der
//! linken Seite (z. B. ein Benutzername-Feld) und einer der rechten Seite
//! (z. B. ein Passwort-Feld) nahe beieinander stehen. Das senkt die Zahl der
//! Fehltreffer bei Zugangsdaten deutlich.
//!
//! Der Suchkern arbeitet nur auf `&[u8]` und ist damit unabhängig von
//! Dateisystem und Image-Format sowie direkt fuzzbar.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod engine;
mod finding;
mod terms;

pub use engine::{SearchEngine, SearchResult};
pub use finding::{Encoding, Finding, FindingKind};
pub use terms::{Category, Meta, Modus, TermTable, TermTableError};
