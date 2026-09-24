//! Der Suchkern.

use aho_corasick::{AhoCorasick, MatchKind};
use serde::Serialize;

use crate::finding::{Encoding, Finding, FindingKind};
use crate::terms::{Category, Modus, TermTable};

/// Länge einer v3-Onion-Adresse ohne die Endung `.onion`.
const ONION_LEN: usize = 56;
/// Bytes, die links und rechts einer Fundstelle als Kontext gezeigt werden.
const CONTEXT_PAD: usize = 24;
/// Obergrenze für die Länge eines Kontextausschnitts.
const CONTEXT_MAX: usize = 200;

/// Ein vorbereiteter Suchlauf über eine Begriffstabelle.
///
/// Der Automat wird einmal gebaut und kann über mehrere Datenbereiche laufen,
/// z. B. einmal über das ganze Image und danach gezielt über einzelne Dateien.
pub struct SearchEngine {
    ac: Option<AhoCorasick>,
    patterns: Vec<Pattern>,
    categories: Vec<CatInfo>,
    max_treffer: usize,
}

/// Ergebnis eines Suchlaufs.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SearchResult {
    /// Alle Treffer in Fundreihenfolge.
    pub findings: Vec<Finding>,
    /// Auffälligkeiten, etwa das Erreichen der Treffergrenze.
    pub warnings: Vec<String>,
}

struct CatInfo {
    id: String,
    modus: Modus,
    abstand: u64,
}

struct Pattern {
    cat: usize,
    side: Side,
    enc: Encoding,
    term: String,
    is_onion: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Side {
    Simple,
    Links,
    Rechts,
}

#[derive(Clone)]
struct Seen {
    offset: u64,
    term: String,
}

#[derive(Default, Clone)]
struct PairState {
    // Index 0 = ASCII, 1 = UTF-16LE.
    last_links: [Option<Seen>; 2],
    last_rechts: [Option<Seen>; 2],
}

fn enc_index(enc: Encoding) -> usize {
    match enc {
        Encoding::Ascii => 0,
        Encoding::Utf16Le => 1,
    }
}

impl SearchEngine {
    /// Baut den Suchautomaten aus einer Begriffstabelle.
    ///
    /// Jeder Begriff wird sowohl in ASCII als auch in UTF-16LE gesucht, ohne
    /// Beachtung der Groß-/Kleinschreibung bei ASCII-Zeichen.
    pub fn new(table: &TermTable) -> Self {
        let mut patterns = Vec::new();
        let mut raw: Vec<Vec<u8>> = Vec::new();
        let mut categories = Vec::new();

        for cat in table.active() {
            let cat_idx = categories.len();
            categories.push(CatInfo {
                id: cat.id.clone(),
                modus: cat.modus,
                abstand: cat.abstand_bytes,
            });
            add_category(cat, cat_idx, &mut patterns, &mut raw);
        }

        let ac = if raw.is_empty() {
            None
        } else {
            // MatchKind::Standard erlaubt find_overlapping_iter, damit auch
            // ineinanderliegende Begriffe (z. B. "un" in "username") gefunden
            // werden. Bei ungültigen Eingaben wird der Aufbau nicht scheitern,
            // da alle Muster nichtleere Bytefolgen sind.
            AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .match_kind(MatchKind::Standard)
                .build(&raw)
                .ok()
        };

        Self {
            ac,
            patterns,
            categories,
            max_treffer: table.meta.max_treffer,
        }
    }

    /// Sucht in `data`. `base_offset` ist der absolute Offset von `data` im
    /// Image und wird auf jede Fundstelle addiert; beim Durchsuchen des ganzen
    /// Images ist er 0.
    pub fn run(&self, data: &[u8], base_offset: u64) -> SearchResult {
        let mut result = SearchResult::default();
        let Some(ac) = &self.ac else {
            return result;
        };

        let mut pair_state = vec![PairState::default(); self.categories.len()];

        for m in ac.find_overlapping_iter(data) {
            if result.findings.len() >= self.max_treffer {
                result.warnings.push(format!(
                    "Treffergrenze {} erreicht, weitere Treffer nicht erfasst",
                    self.max_treffer
                ));
                break;
            }

            let pat = &self.patterns[m.pattern().as_usize()];
            let start = m.start();

            if pat.is_onion {
                if let Some(f) = onion_finding(
                    data,
                    start,
                    m.end(),
                    base_offset,
                    &pat.term,
                    pat,
                    &self.categories,
                ) {
                    result.findings.push(f);
                }
                continue;
            }

            let cat = &self.categories[pat.cat];
            match cat.modus {
                Modus::Einfach => {
                    result.findings.push(Finding {
                        kategorie: cat.id.clone(),
                        kind: FindingKind::Term {
                            begriff: pat.term.clone(),
                        },
                        kodierung: pat.enc,
                        offset: base_offset + start as u64,
                        kontext: context(data, start, m.end(), pat.enc),
                    });
                }
                Modus::Paar => {
                    if let Some(f) =
                        pair_finding(data, pat, start, base_offset, cat, &mut pair_state[pat.cat])
                    {
                        result.findings.push(f);
                    }
                }
            }
        }

        result
    }
}

fn add_category(
    cat: &Category,
    cat_idx: usize,
    patterns: &mut Vec<Pattern>,
    raw: &mut Vec<Vec<u8>>,
) {
    let mut push = |term: &str, side: Side, is_onion: bool| {
        if term.is_empty() {
            return;
        }
        // ASCII
        patterns.push(Pattern {
            cat: cat_idx,
            side,
            enc: Encoding::Ascii,
            term: term.to_string(),
            is_onion,
        });
        raw.push(term.as_bytes().to_vec());
        // UTF-16LE, außer bei der Onion-Prüfung (Konfigurationen sind ASCII).
        if !is_onion {
            patterns.push(Pattern {
                cat: cat_idx,
                side,
                enc: Encoding::Utf16Le,
                term: term.to_string(),
                is_onion: false,
            });
            raw.push(term.encode_utf16().flat_map(u16::to_le_bytes).collect());
        }
    };

    match cat.modus {
        Modus::Einfach => {
            for t in &cat.begriffe {
                let is_onion = cat.onion_pruefung && t == ".onion";
                push(t, Side::Simple, is_onion);
            }
        }
        Modus::Paar => {
            for t in &cat.links {
                push(t, Side::Links, false);
            }
            for t in &cat.rechts {
                push(t, Side::Rechts, false);
            }
        }
    }
}

fn pair_finding(
    data: &[u8],
    pat: &Pattern,
    start: usize,
    base: u64,
    cat: &CatInfo,
    state: &mut PairState,
) -> Option<Finding> {
    let ei = enc_index(pat.enc);
    let here = Seen {
        offset: start as u64,
        term: pat.term.clone(),
    };

    let (finding, store_left) = match pat.side {
        Side::Links => {
            let f = state.last_rechts[ei].as_ref().and_then(|r| {
                let dist = here.offset.abs_diff(r.offset);
                (dist <= cat.abstand).then(|| make_pair(data, cat, pat.enc, base, &here, r))
            });
            (f, true)
        }
        Side::Rechts => {
            let f = state.last_links[ei].as_ref().and_then(|l| {
                let dist = here.offset.abs_diff(l.offset);
                (dist <= cat.abstand).then(|| make_pair(data, cat, pat.enc, base, l, &here))
            });
            (f, false)
        }
        Side::Simple => (None, false),
    };

    if store_left {
        state.last_links[ei] = Some(here);
    } else if pat.side == Side::Rechts {
        state.last_rechts[ei] = Some(here);
    }

    finding
}

/// `left` ist immer der Treffer der linken Seite, `right` der der rechten.
fn make_pair(
    data: &[u8],
    cat: &CatInfo,
    enc: Encoding,
    base: u64,
    left: &Seen,
    right: &Seen,
) -> Finding {
    let from = left.offset.min(right.offset) as usize;
    let span = right.term.len().max(left.term.len());
    let to = (left.offset.max(right.offset) as usize + span).min(data.len());
    Finding {
        kategorie: cat.id.clone(),
        kind: FindingKind::Paar {
            links: left.term.clone(),
            rechts: right.term.clone(),
            abstand: left.offset.abs_diff(right.offset),
        },
        kodierung: enc,
        offset: base + from as u64,
        kontext: context(data, from, to, enc),
    }
}

fn onion_finding(
    data: &[u8],
    start: usize,
    end: usize,
    base: u64,
    _term: &str,
    pat: &Pattern,
    categories: &[CatInfo],
) -> Option<Finding> {
    let addr_start = start.checked_sub(ONION_LEN)?;
    let addr = data.get(addr_start..start)?;
    if !addr.iter().all(|&b| is_base32(b)) {
        return None;
    }
    let full: String = data
        .get(addr_start..end)?
        .iter()
        .map(|&b| b as char)
        .collect();
    let cat = &categories[pat.cat];
    Some(Finding {
        kategorie: cat.id.clone(),
        kind: FindingKind::Term { begriff: full },
        kodierung: Encoding::Ascii,
        offset: base + addr_start as u64,
        kontext: context(data, addr_start, end, Encoding::Ascii),
    })
}

fn is_base32(b: u8) -> bool {
    b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b)
}

/// Liefert einen lesbaren Ausschnitt um `[from, to)`. Nicht darstellbare
/// Zeichen werden zu `.`, damit im Report keine Steuerzeichen landen.
fn context(data: &[u8], from: usize, to: usize, enc: Encoding) -> String {
    let lo = from.saturating_sub(CONTEXT_PAD);
    let hi = (to + CONTEXT_PAD).min(data.len());
    let slice = &data[lo..hi];

    let mut out = String::new();
    match enc {
        Encoding::Ascii => {
            for &b in slice {
                out.push(printable(b));
            }
        }
        Encoding::Utf16Le => {
            for pair in slice.chunks_exact(2) {
                let u = u16::from_le_bytes([pair[0], pair[1]]);
                match char::from_u32(u32::from(u)) {
                    Some(c) if !c.is_control() => out.push(c),
                    _ => out.push('.'),
                }
            }
        }
    }
    if out.len() > CONTEXT_MAX {
        out.truncate(CONTEXT_MAX);
    }
    out
}

fn printable(b: u8) -> char {
    if (0x20..=0x7e).contains(&b) {
        b as char
    } else {
        '.'
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine(toml: &str) -> SearchEngine {
        SearchEngine::new(&TermTable::from_str(toml).unwrap())
    }

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn einfache_suche_ascii_und_utf16() {
        let e = engine(
            r#"
            [meta]
            name = "t"
            [[kategorie]]
            id = "darknet"
            begriffe = ["torrc"]
            "#,
        );
        let mut data = b"xx torrc yy ".to_vec();
        data.extend_from_slice(&utf16("hier TORRC drin"));
        let r = e.run(&data, 1000);
        assert_eq!(r.findings.len(), 2);
        assert_eq!(r.findings[0].offset, 1003);
        assert_eq!(r.findings[0].kodierung, Encoding::Ascii);
        assert_eq!(r.findings[1].kodierung, Encoding::Utf16Le);
        for f in &r.findings {
            assert_eq!(f.kategorie, "darknet");
            assert!(matches!(&f.kind, FindingKind::Term { begriff } if begriff == "torrc"));
        }
    }

    #[test]
    fn überlappende_begriffe() {
        let e = engine(
            r#"
            [meta]
            name = "t"
            [[kategorie]]
            id = "k"
            begriffe = ["user", "username"]
            "#,
        );
        let r = e.run(b"username", 0);
        // "user" liegt in "username", beide Begriffe müssen ab Offset 0 kommen.
        let terms: Vec<_> = r
            .findings
            .iter()
            .filter(|f| f.kodierung == Encoding::Ascii)
            .filter_map(|f| match &f.kind {
                FindingKind::Term { begriff } => Some(begriff.as_str()),
                _ => None,
            })
            .collect();
        assert!(terms.contains(&"user"), "gefunden: {terms:?}");
        assert!(terms.contains(&"username"), "gefunden: {terms:?}");
    }

    #[test]
    fn paar_nur_bei_nähe() {
        let e = engine(
            r#"
            [meta]
            name = "t"
            [[kategorie]]
            id = "zugangsdaten"
            modus = "paar"
            links = ["user"]
            rechts = ["pw"]
            abstand_bytes = 20
            "#,
        );

        // Nah beieinander -> ein Paar.
        let r = e.run(b"user: alice  pw: geheim", 0);
        assert_eq!(r.findings.len(), 1);
        match &r.findings[0].kind {
            FindingKind::Paar {
                links,
                rechts,
                abstand,
            } => {
                assert_eq!(links, "user");
                assert_eq!(rechts, "pw");
                assert_eq!(*abstand, 13);
            }
            _ => panic!("kein Paar"),
        }

        // Weit auseinander -> kein Paar.
        let mut weit = b"user".to_vec();
        weit.extend(std::iter::repeat_n(b' ', 100));
        weit.extend_from_slice(b"pw");
        assert!(e.run(&weit, 0).findings.is_empty());
    }

    #[test]
    fn paar_auch_umgekehrte_reihenfolge() {
        let e = engine(
            r#"
            [meta]
            name = "t"
            [[kategorie]]
            id = "zugangsdaten"
            modus = "paar"
            links = ["user"]
            rechts = ["pass"]
            "#,
        );
        let r = e.run(b"pass=x; user=y", 0);
        assert_eq!(r.findings.len(), 1);
        assert!(matches!(&r.findings[0].kind, FindingKind::Paar { .. }));
    }

    #[test]
    fn paar_kreuzt_kodierung_nicht() {
        let e = engine(
            r#"
            [meta]
            name = "t"
            [[kategorie]]
            id = "z"
            modus = "paar"
            links = ["user"]
            rechts = ["pw"]
            "#,
        );
        // "user" als ASCII, "pw" als UTF-16LE direkt daneben: kein Paar.
        let mut data = b"user ".to_vec();
        data.extend_from_slice(&utf16("pw"));
        assert!(e.run(&data, 0).findings.is_empty());
    }

    #[test]
    fn onion_nur_bei_gültiger_adresse() {
        let e = engine(
            r#"
            [meta]
            name = "t"
            [[kategorie]]
            id = "darknet"
            begriffe = [".onion"]
            onion_pruefung = true
            "#,
        );

        let addr = "a".repeat(ONION_LEN);
        let gut = format!("URL: {addr}.onion/pfad");
        let r = e.run(gut.as_bytes(), 0);
        assert_eq!(r.findings.len(), 1);
        match &r.findings[0].kind {
            FindingKind::Term { begriff } => {
                assert_eq!(begriff, &format!("{addr}.onion"));
            }
            _ => panic!(),
        }

        // Zu kurz vor .onion -> unterdrückt.
        let schlecht = "kurz.onion";
        assert!(e.run(schlecht.as_bytes(), 0).findings.is_empty());
    }

    #[test]
    fn treffergrenze() {
        let e = engine(
            r#"
            [meta]
            name = "t"
            max_treffer = 3
            [[kategorie]]
            id = "k"
            begriffe = ["a"]
            "#,
        );
        let r = e.run(b"aaaaaaaa", 0);
        assert_eq!(r.findings.len(), 3);
        assert_eq!(r.warnings.len(), 1);
    }

    #[test]
    fn leere_tabelle_findet_nichts() {
        let e = engine("[meta]\nname = \"t\"");
        assert!(e.run(b"irgendwas", 0).findings.is_empty());
    }

    #[test]
    fn kontext_ohne_steuerzeichen() {
        let e = engine(
            r#"
            [meta]
            name = "t"
            [[kategorie]]
            id = "k"
            begriffe = ["geheim"]
            "#,
        );
        let data = b"\x00\x01geheim\x07\x1f";
        let r = e.run(data, 0);
        assert_eq!(r.findings.len(), 1);
        assert!(!r.findings[0].kontext.contains('\x00'));
        assert!(r.findings[0].kontext.contains("geheim"));
    }
}
