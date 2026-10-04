use stratum_connectors::yara::scannen;

#[test]
#[ignore = "benötigt Linux mit YARA 4.5 und prlimit"]
fn echte_yara_fixture() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("rules.yar"),
        "rule Fixture { strings: $a = \"needle\" condition: $a }",
    )
    .unwrap();
    std::fs::write(dir.path().join("target.bin"), b"xxneedle").unwrap();
    let r = scannen(dir.path(), 8, &|| false).unwrap();
    assert!(r.vollstaendig);
    assert_eq!(r.treffer[0].regel, "Fixture");
    assert_eq!(r.treffer[0].strings[0].offset, 2);
}
