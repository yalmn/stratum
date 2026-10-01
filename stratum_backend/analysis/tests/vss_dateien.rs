//! Dateibasierte Auswertung der Schattenkopien am dfvfs-Testimage `vss.raw`
//! (zwei Stores, ein Volume ohne Partitionstabelle). Die Einstufung wird
//! gegen einen vollständigen Inhaltsvergleich jeder Datei geprüft.

use std::collections::{BTreeSet, HashMap};

use stratum_analysis::{AnalysisContext, Analyzer, NtfsTarget, VssAnalyzer};
use stratum_core::ImageReader;
use stratum_ntfs::NtfsVolume;

#[test]
#[ignore = "benötigt STRATUM_VSS_REFERENCE mit vss.raw"]
fn abgleich_wie_vollvergleich() {
    let dir = std::path::PathBuf::from(std::env::var_os("STRATUM_VSS_REFERENCE").unwrap());
    let pfad = dir.join("vss.raw");
    let img = ImageReader::open(&pfad).unwrap();
    let data = img.raw_slice().unwrap();
    let ctx = AnalysisContext::build(
        &img,
        vec![NtfsTarget {
            index: 0,
            offset: 0,
            size: img.len(),
        }],
    );
    assert!(ctx.warnings.is_empty(), "{:?}", ctx.warnings);
    assert_eq!(ctx.snapshot_volumes.len(), 2);

    // Gegenprobe: jede Datei jedes Snapshots vollständig lesen.
    let vss = stratum_vss::Volume::open(data).unwrap().unwrap();
    let mut live = NtfsVolume::from_bytes(data).unwrap();
    let live_files: HashMap<String, u64> = live
        .walk()
        .unwrap()
        .into_iter()
        .filter(|e| !e.is_directory)
        .map(|e| (e.path.to_lowercase(), e.mft_record))
        .collect();
    for store in 0..vss.store_count() {
        let r = vss.reader(store).unwrap();
        let n = r.size();
        let mut v = NtfsVolume::from_reader(r, 0, n).unwrap();
        let mut erwartet = BTreeSet::new();
        for e in v.walk().unwrap().into_iter().filter(|e| !e.is_directory) {
            match live_files.get(&e.path.to_lowercase()) {
                None => {
                    erwartet.insert(("nur_im_snapshot", e.path.clone()));
                }
                Some(&lr) => {
                    let a = v.read_file_by_record(e.mft_record, &e.path).unwrap();
                    let b = live.read_file_by_record(lr, &e.path).unwrap();
                    if a.map(|f| f.data) != b.map(|f| f.data) {
                        erwartet.insert(("inhalt_abweichend", e.path.clone()));
                    }
                }
            }
        }
        let gefunden: BTreeSet<_> = ctx
            .abweichungen
            .iter()
            .filter(|a| a.store == store)
            .map(|a| (a.status.name(), a.eintrag.path.clone()))
            .collect();
        assert_eq!(gefunden, erwartet, "VSS#{}", store + 1);
        assert_eq!(gefunden.len(), 7);
    }

    let out = VssAnalyzer.run(&ctx);
    assert!(out.warnings.is_empty(), "{:?}", out.warnings);
    let dateien: Vec<_> = out
        .findings
        .iter()
        .filter(|f| f.attributes.get("art").map(String::as_str) == Some("vss_datei"))
        .collect();
    assert_eq!(dateien.len(), 14);
    for f in &dateien {
        // Image-Offset des MFT-Datensatzes im Snapshot; dort steht „FILE“.
        let o = f.offset.expect("Image-Offset") as usize;
        assert_eq!(&data[o..o + 4], b"FILE", "{}", f.source);
    }
    let snaps: Vec<_> = out
        .findings
        .iter()
        .filter(|f| f.attributes.contains_key("dateien_im_snapshot"))
        .collect();
    assert_eq!(snaps.len(), 2);
    assert_eq!(snaps[0].attributes["inhalt_abweichend"], "7");

    // Snapshot-Volume über den Kontext öffnen; die Abbildung führt die
    // Ablage einer Datei auf die Image-Stelle ihrer Bytes zurück.
    for v in &ctx.snapshot_volumes {
        let (mut vol, abbildung) = ctx.open_volume(v).unwrap();
        assert!(abbildung.ist_snapshot());
        let inhalt = vol.read_file("a_directory\\a_file").unwrap().unwrap().data;
        let layout = vol.data_stream_layout("$LogFile", "").unwrap().unwrap();
        let lauf = &layout.runs[0];
        let image = abbildung.image(lauf.image_offset.unwrap()).unwrap() as usize;
        let mut erwartet = vec![0u8; 4096];
        let reader_store = match v.herkunft {
            stratum_analysis::Herkunft::Snapshot { store, .. } => store,
            _ => unreachable!(),
        };
        vss.read_at(reader_store, lauf.image_offset.unwrap(), &mut erwartet)
            .unwrap();
        assert_eq!(&data[image..image + 4096], &erwartet[..]);
        assert_eq!(inhalt.len(), 56);
    }
}
