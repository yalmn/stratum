//! USB-Zeitpunkte aus einem synthetischen Mini-Image und optionalen Referenzdaten.

#[path = "common/builder.rs"]
mod builder;

use std::io::Write;

use builder::HiveBuilder;
use stratum_analysis::{
    build_timeline, AnalysisContext, Analyzer, Hives, NtfsTarget, Outcome, UsbAnalyzer,
    WindowsInstall,
};
use stratum_core::{hash::hash_image, ImageReader};

const GUID: &str = "{83da6326-97a6-4088-9453-a1923f573b29}";
const EPOCH: u64 = 132_539_328_000_000_000;

fn parent(b: &mut HiveBuilder, name: &str, children: &[u32]) -> u32 {
    let list = b.lh(children);
    b.key_with_list(name, list, children.len() as u32, &[])
}

fn fixture(properties: &[(&str, u32, &[u8])]) -> (Vec<u8>, Vec<u64>) {
    let mut b = HiveBuilder::new();
    let mut keys = Vec::new();
    let mut offsets = Vec::new();
    for (id, typ, data) in properties {
        let value = b.vk("", *typ, data);
        offsets.push(4096 + u64::from(value));
        keys.push(b.key(id, None, &[value]));
    }
    let group = parent(&mut b, GUID, &keys);
    let properties = parent(&mut b, "Properties", &[group]);
    let instance = parent(&mut b, "serial", &[properties]);
    let device = parent(&mut b, "Disk&Ven_Test", &[instance]);
    let usb = parent(&mut b, "USBSTOR", &[device]);
    let enumeration = parent(&mut b, "Enum", &[usb]);
    // Absichtlich nicht ControlSet001: Select muss berücksichtigt werden.
    let cs = parent(&mut b, "ControlSet002", &[enumeration]);
    let current = b.vk("Current", 4, &2u32.to_le_bytes());
    let select = b.key("Select", None, &[current]);
    let root = parent(&mut b, "ROOT", &[select, cs]);
    (b.finish(root), offsets)
}

fn analyze(img: &ImageReader, hive: &[u8], origin: &str) -> Outcome {
    let mut ctx = AnalysisContext::new(img, vec![]);
    ctx.installs = std::sync::Arc::new(vec![WindowsInstall {
        origin: origin.into(),
        target: NtfsTarget {
            index: 0,
            offset: 512,
            size: hive.len() as u64,
        },
        hives: Hives {
            system: Some(hive.to_vec()),
            ..Default::default()
        },
        computer_name: None,
        timezone: None,
        accounts: vec![],
        ntuser: vec![],
        usrclass: Vec::new(),
        ansi_codepage: None,
        hive_status: Vec::new(),
        warnings: vec![],
    }]);
    UsbAnalyzer.run(&ctx)
}

fn mini_image(hive: &[u8]) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&[0; 512]).unwrap();
    file.write_all(hive).unwrap();
    file.flush().unwrap();
    file
}

#[test]
fn vier_zeitpunkte_mit_quellen_und_timeline() {
    let (hive, offsets) = fixture(&[
        ("0064", 0xffff0010, &(EPOCH + 10_000_001).to_le_bytes()),
        ("0065", 0xffff0010, &EPOCH.to_le_bytes()),
        ("0066", 0xffff0010, &(EPOCH + 20_000_002).to_le_bytes()),
        ("0067", 0xffff0010, &(EPOCH + 30_000_003).to_le_bytes()),
    ]);
    let file = mini_image(&hive);
    let img = ImageReader::open(file.path()).unwrap();
    let hashes = hash_image(&img).unwrap();
    let out = analyze(&img, &img.raw_slice().unwrap()[512..], "VSS#1");
    assert!(out.warnings.is_empty(), "{:?}", out.warnings);
    assert_eq!(out.findings.len(), 1);
    let f = &out.findings[0];
    assert!(f.source.contains("ControlSet002\\Enum\\USBSTOR"));
    assert_eq!(f.offset, None, "Hive-Offsets sind keine Image-Offsets");
    assert_eq!(f.attributes["volume_offset"], "512");
    for ((field, id), offset) in [
        ("installation", "0064"),
        ("erste_installation", "0065"),
        ("letzte_verbindung", "0066"),
        ("letztes_trennen", "0067"),
    ]
    .into_iter()
    .zip(offsets)
    {
        assert_eq!(f.attributes[&format!("{field}_status")], "vorhanden");
        assert_eq!(
            f.attributes[&format!("{field}_hive_offset")],
            offset.to_string()
        );
        assert!(f.attributes[&format!("{field}_quelle")]
            .ends_with(&format!("{GUID}\\{id}\\(Standard)")));
        assert_eq!(&hive[offset as usize + 4..offset as usize + 6], b"vk");
    }
    assert_eq!(
        f.attributes["installation_utc"],
        "2021-01-01T00:00:01.0000001Z"
    );
    assert_eq!(
        f.attributes["erste_installation_utc"],
        "2021-01-01T00:00:00.0000000Z"
    );
    let timeline = build_timeline(&out.findings);
    assert_eq!(timeline.len(), 4);
    assert_eq!(
        timeline.iter().map(|t| t.ereignis).collect::<Vec<_>>(),
        [
            "usb_erste_installation",
            "usb_installation",
            "usb_verbunden",
            "usb_getrennt"
        ]
    );
    for (i, entry) in timeline.iter().enumerate() {
        assert_eq!(entry.unix, 1_609_459_200 + i as i64);
        assert_eq!(entry.finding_index, 0);
        assert_eq!(entry.volume.as_deref(), Some("VSS#1"));
    }
    assert_eq!(hash_image(&img).unwrap(), hashes);
}

#[test]
fn fehlende_null_und_defekte_werte_ohne_ersatzzeit() {
    let (hive, _) = fixture(&[
        ("0064", 0xffff0010, &0u64.to_le_bytes()),
        ("0065", 0xffff0010, &[1; 7]),
        ("0066", 11, &EPOCH.to_le_bytes()),
    ]);
    let file = mini_image(&hive);
    let img = ImageReader::open(file.path()).unwrap();
    hash_image(&img).unwrap();
    let out = analyze(&img, &img.raw_slice().unwrap()[512..], "live");
    assert_eq!(out.findings.len(), 1);
    let attrs = &out.findings[0].attributes;
    assert_eq!(attrs["installation_status"], "nicht_gesetzt");
    assert_eq!(attrs["erste_installation_status"], "nicht_lesbar");
    assert_eq!(attrs["letzte_verbindung_status"], "nicht_lesbar");
    assert_eq!(attrs["letztes_trennen_status"], "nicht_vorhanden");
    assert_eq!(out.warnings.len(), 2);
    assert!(out
        .warnings
        .iter()
        .all(|w| w.contains("SYSTEM\\ControlSet002\\Enum\\USBSTOR")));
    assert!(build_timeline(&out.findings).is_empty());
}

#[test]
fn beschädigter_wert_lässt_weitere_zeitpunkte_erhalten() {
    let (mut hive, offsets) = fixture(&[
        ("0064", 0xffff0010, &EPOCH.to_le_bytes()),
        ("0065", 0xffff0010, &EPOCH.to_le_bytes()),
    ]);
    hive[offsets[0] as usize + 4] = b'x';
    let file = mini_image(&hive);
    let img = ImageReader::open(file.path()).unwrap();
    hash_image(&img).unwrap();
    let out = analyze(&img, &img.raw_slice().unwrap()[512..], "live");
    assert_eq!(out.findings.len(), 1);
    assert_eq!(out.warnings.len(), 1);
    let attrs = &out.findings[0].attributes;
    assert_eq!(attrs["installation_status"], "nicht_lesbar");
    assert_eq!(attrs["erste_installation_status"], "vorhanden");
    assert_eq!(build_timeline(&out.findings).len(), 1);
}

#[test]
#[ignore = "benötigt STRATUM_USB_REFERENCE_DIR mit SYSTEM.hive und winscope_report.html"]
fn winscope_referenz() {
    let dir = std::path::PathBuf::from(
        std::env::var_os("STRATUM_USB_REFERENCE_DIR").expect("Referenzordner setzen"),
    );
    let img = ImageReader::open(dir.join("SYSTEM.hive")).unwrap();
    let hashes = hash_image(&img).unwrap();
    let html = std::fs::read_to_string(dir.join("winscope_report.html")).unwrap();
    assert!(
        html.contains(&hashes.sha256),
        "Hive-Hash stimmt nicht mit WinScope überein"
    );
    let out = analyze(&img, img.raw_slice().unwrap(), "live");
    assert!(out.warnings.is_empty(), "{:?}", out.warnings);
    let devices: Vec<_> = out
        .findings
        .iter()
        .filter(|f| f.attributes.contains_key("seriennummer"))
        .collect();
    assert_eq!(devices.len(), 1);
    let f = devices[0];
    // usbstor v.20200515 vertauscht die Beschriftungen von 0064 und 0065.
    for (field, label) in [
        ("installation", "First InstallDate"),
        ("erste_installation", "InstallDate"),
        ("letzte_verbindung", "Last Arrival"),
    ] {
        let expected = html
            .lines()
            .find_map(|line| {
                let (name, date) = line.trim().split_once(':')?;
                (name.trim() == label).then(|| date.trim())
            })
            .expect("Referenzzeit fehlt");
        let utc = &f.attributes[&format!("{field}_utc")];
        assert_eq!(format!("{}Z", utc[..19].replace('T', " ")), expected);
        // Byte-Nachweis unabhängig von der Value-API: vk verweist auf FILETIME-Daten.
        let offset: usize = f.attributes[&format!("{field}_hive_offset")]
            .parse()
            .unwrap();
        let bytes = img.raw_slice().unwrap();
        assert_eq!(&bytes[offset + 4..offset + 6], b"vk");
        let cell = u32::from_le_bytes(bytes[offset + 12..offset + 16].try_into().unwrap()) as usize;
        let ft = u64::from_le_bytes(bytes[4100 + cell..4108 + cell].try_into().unwrap());
        assert_eq!(ft.to_string(), f.attributes[&format!("{field}_filetime")]);
    }
    assert_eq!(f.attributes["letztes_trennen_status"], "nicht_vorhanden");
    assert!(!html.contains("Last Removal"));
    let timeline = build_timeline(std::slice::from_ref(f));
    assert_eq!(timeline.len(), 3);
    println!(
        "USB_REFERENZ={}",
        serde_json::json!({"hashes": hashes, "findings": devices, "timeline": timeline, "warnings": out.warnings})
    );
}
