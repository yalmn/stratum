//! Der Keyword-Analyzer liefert Funde mit Domäne, Name und Offset.

use std::io::Write;

use stratum_analysis::{run_all, AnalysisContext, Analyzer, KeywordAnalyzer, NtfsTarget};
use stratum_core::ImageReader;
use stratum_search::TermTable;

const TABLE: &str = r#"
[meta]
name = "Test"
version = 1
[[kategorie]]
id = "zugangsdaten"
modus = "paar"
abstand_bytes = 64
links = ["user"]
rechts = ["pw"]
[[kategorie]]
id = "darknet"
begriffe = ["torrc"]
"#;

#[test]
fn keyword_findet_paar_und_term() {
    let mut data = vec![b' '; 4096];
    let text = b"config user=alice pw=Sommer2024 torrc ende";
    data[512..512 + text.len()].copy_from_slice(text);

    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(&data).unwrap();
    f.flush().unwrap();
    let img = ImageReader::open(f.path()).unwrap();

    let ctx = AnalysisContext::new(
        &img,
        vec![NtfsTarget {
            index: 0,
            offset: 0,
            size: img.len(),
        }],
    );
    let analyzers: Vec<Box<dyn Analyzer>> = vec![Box::new(KeywordAnalyzer::from_table(
        &TermTable::from_str(TABLE).unwrap(),
    ))];
    let r = run_all(&ctx, &analyzers);

    let pair = r
        .findings
        .iter()
        .find(|f| f.domain == "zugangsdaten")
        .expect("Paar fehlt");
    assert_eq!(pair.name, "user / pw");
    assert!(pair.offset.is_some());
    assert_eq!(pair.attributes.get("art").map(String::as_str), Some("paar"));

    assert!(r
        .findings
        .iter()
        .any(|f| f.domain == "darknet" && f.name == "torrc"));
}
