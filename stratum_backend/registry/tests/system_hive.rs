//! Liest einen synthetischen SYSTEM-Hive so, wie es die Artefakt-Analyzer
//! später tun: aktives ControlSet bestimmen, Zeitzone und Rechnername lesen.

#[path = "common/builder.rs"]
mod builder;

use builder::HiveBuilder;
use stratum_registry::{filetime_to_unix, Hive, ValueType};

fn utf16z(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect()
}

fn system_hive() -> Vec<u8> {
    let mut b = HiveBuilder::new();

    let current = b.vk("Current", 4, &1u32.to_le_bytes());
    let select = b.key("Select", None, &[current]);

    let tz_name = b.vk("TimeZoneKeyName", 1, &utf16z("W. Europe Standard Time"));
    let bias = b.vk("ActiveTimeBias", 4, &(-60i32).to_le_bytes());
    let tz = b.key("TimeZoneInformation", None, &[tz_name, bias]);

    let cn_val = b.vk("ComputerName", 1, &utf16z("WS-01"));
    let cn_inner = b.key("ComputerName", None, &[cn_val]);
    let cn_list = b.lh(&[cn_inner]);
    let cn_outer = b.key_with_list("ComputerName", cn_list, 1, &[]);

    let control_list = b.lh(&[cn_outer, tz]);
    let control = b.key_with_list("Control", control_list, 2, &[]);
    let cs_list = b.lh(&[control]);
    let cs1 = b.key_with_list("ControlSet001", cs_list, 1, &[]);

    let root_list = b.lh(&[cs1, select]);
    let root = b.key_with_list("ROOT", root_list, 2, &[]);
    b.finish(root)
}

#[test]
fn system_hive_lesen() {
    let data = system_hive();
    let hive = Hive::parse(&data).unwrap();
    assert!(hive.warnings().is_empty());

    let current = hive
        .open_key("Select")
        .unwrap()
        .unwrap()
        .value("Current")
        .unwrap()
        .unwrap()
        .as_u32()
        .unwrap();
    let cs = format!("ControlSet{current:03}");

    let tz = hive
        .open_key(&format!("{cs}\\Control\\TimeZoneInformation"))
        .unwrap()
        .unwrap();
    let name = tz.value("TimeZoneKeyName").unwrap().unwrap();
    assert_eq!(name.value_type(), ValueType::Sz);
    assert_eq!(name.as_string().as_deref(), Some("W. Europe Standard Time"));
    assert_eq!(
        tz.value("ActiveTimeBias")
            .unwrap()
            .unwrap()
            .as_u32()
            .map(|v| v as i32),
        Some(-60)
    );
    assert_eq!(
        filetime_to_unix(tz.last_written()),
        Some((1_609_459_200, 0))
    );

    let cn = hive
        .open_key(&format!("{cs}\\control\\computername\\computername"))
        .unwrap()
        .unwrap()
        .value("ComputerName")
        .unwrap()
        .unwrap();
    assert_eq!(cn.as_string().as_deref(), Some("WS-01"));
    assert!(cn.file_offset() > 4096);

    assert!(hive.open_key("ControlSet002").unwrap().is_none());
}
