// SPDX-License-Identifier: MIT

use std::{process::Command, sync::Mutex};

use crate::tests::{NetnsGuard, with_netns};

const NETDEVSIM_BUS: &str = "/sys/bus/netdevsim";

/// Serialises all netdevsim tests so they don't race on the sysfs interface
/// and kernel module.
static NETDEVSIM_LOCK: Mutex<()> = Mutex::new(());

const NETDEVSIM_INDEX: u32 = 0;

fn netdevsim_available() -> bool {
    std::path::Path::new(NETDEVSIM_BUS).exists()
}

fn netdevsim_sysfs_path(idx: u32) -> String {
    format!("{NETDEVSIM_BUS}/devices/netdevsim{idx}")
}

fn create_netdevsim_device(idx: u32) {
    let _ =
        std::fs::write(format!("{NETDEVSIM_BUS}/del_device"), idx.to_string());
    std::fs::write(format!("{NETDEVSIM_BUS}/new_device"), idx.to_string())
        .unwrap_or_else(|e| {
            panic!("failed to create netdevsim device {idx}: {e}")
        });
}

fn destroy_netdevsim_device(idx: u32) {
    let _ =
        std::fs::write(format!("{NETDEVSIM_BUS}/del_device"), idx.to_string());
}

fn read_ifname(idx: u32) -> String {
    let net_dir = format!("{NETDEVSIM_BUS}/devices/netdevsim{idx}/net");
    for _ in 0..100 {
        if let Ok(rd) = std::fs::read_dir(&net_dir) {
            let mut entries: Vec<_> = rd
                .filter_map(|e| e.ok())
                .map(|e| e.file_name())
                .filter_map(|n| n.into_string().ok())
                .filter(|n| !n.starts_with("eth"))
                .collect();
            if !entries.is_empty() {
                return entries.pop().unwrap();
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    panic!("failed to read ifname from {net_dir}");
}

fn move_device_to_netns(idx: u32, ns: &NetnsGuard) -> String {
    let ifname = read_ifname(idx);
    for _ in 0..10 {
        let status = Command::new("ip")
            .args(["link", "set", &ifname, "netns", &ns.name])
            .status()
            .expect("failed to run ip link set netns");
        if status.success() {
            return ifname;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    panic!("failed to move (netdevsim{idx}) to test ns");
}

fn enable_vfs(idx: u32, num_vfs: u32) {
    if num_vfs == 0 {
        return;
    }
    let vf_path = format!("{}/sriov_numvfs", netdevsim_sysfs_path(idx));
    std::fs::write(&vf_path, num_vfs.to_string())
        .unwrap_or_else(|e| panic!("failed to set {num_vfs} VFs: {e}"));
}

fn with_netdevsim_vfs<F>(num_vfs: u32, test: F)
where
    F: FnOnce(&NetnsGuard, &str),
{
    let _guard = NETDEVSIM_LOCK.lock().unwrap();
    let mut loaded_module = false;
    if !netdevsim_available() {
        loaded_module = Command::new("modprobe")
            .args(["netdevsim"])
            .status()
            .is_ok_and(|s| s.success());
        if !netdevsim_available() {
            panic!("netdevsim module not available");
        }
    }

    create_netdevsim_device(NETDEVSIM_INDEX);

    with_netns(|ns| {
        let ifname = move_device_to_netns(NETDEVSIM_INDEX, ns);
        enable_vfs(NETDEVSIM_INDEX, num_vfs);
        ns.ip_rs_exec_cmd(&["link", "set", "dev", &ifname, "up"]);

        test(ns, &ifname);
    });

    destroy_netdevsim_device(NETDEVSIM_INDEX);

    if loaded_module {
        let _ = Command::new("modprobe").args(["-r", "netdevsim"]).status();
    }
}

/// Strip non-deterministic fields from detailed output (switchid, hex
/// identifiers between `portname p1` and `parentbus`).
fn normalize_vf_detailed(s: String) -> String {
    let mut result = String::new();
    for line in s.lines() {
        let mut words: Vec<&str> = line.split_whitespace().collect();
        // Strip switchid word and hex string after "portname p1"
        words.retain(|w| {
            if w.starts_with("switchid") {
                return false;
            }
            // Hex string of 32+ chars between portname p1 and parentbus
            if w.len() >= 32 && w.chars().all(|c| c.is_ascii_hexdigit()) {
                return false;
            }
            true
        });
        result.push_str(&words.join(" "));
        result.push('\n');
    }
    result.trim().to_string()
}

/// Strip vfinfo_list from JSON output to compare the non-VF portions.
fn strip_vfinfo_json(s: String) -> String {
    let v: serde_json::Value = serde_json::from_str(&s).unwrap();
    let arr = v.as_array().unwrap();
    let stripped: Vec<serde_json::Value> = arr
        .iter()
        .map(|item| {
            let mut obj = item.as_object().unwrap().clone();
            obj.remove("vfinfo_list");
            serde_json::Value::Object(obj)
        })
        .collect();
    serde_json::to_string(&stripped).unwrap()
}

#[ignore]
#[test]
fn test_netdevsim_vf_link_show() {
    with_netdevsim_vfs(2, |ns, dev| {
        ns.assert_eq_output(&["link", "show", dev]);
    });
}

#[ignore]
#[test]
fn test_netdevsim_vf_link_show_novf() {
    with_netdevsim_vfs(2, |ns, dev| {
        ns.assert_eq_output(&["link", "show", "novf", dev]);
    });
}

#[ignore]
#[test]
fn test_netdevsim_vf_json() {
    with_netdevsim_vfs(2, |ns, dev| {
        ns.assert_eq_output_map(
            &["-j", "link", "show", dev],
            strip_vfinfo_json,
        );
    });
}

#[ignore]
#[test]
fn test_netdevsim_vf_detailed_show() {
    with_netdevsim_vfs(2, |ns, dev| {
        ns.assert_eq_output_map(
            &["-d", "link", "show", dev],
            normalize_vf_detailed,
        );
    });
}

#[ignore]
#[test]
fn test_netdevsim_vf_mac() {
    with_netdevsim_vfs(2, |ns, dev| {
        ns.ip_rs_exec_cmd(&[
            "link",
            "set",
            "dev",
            dev,
            "vf",
            "0",
            "mac",
            "00:11:22:33:44:55",
        ]);
        ns.assert_eq_output(&["link", "show", dev]);
    });
}

#[ignore]
#[test]
fn test_netdevsim_vf_vlan() {
    with_netdevsim_vfs(2, |ns, dev| {
        ns.ip_rs_exec_cmd(&[
            "link", "set", "dev", dev, "vf", "0", "vlan", "100",
        ]);
        ns.assert_eq_output(&["link", "show", dev]);
    });
}

#[ignore]
#[test]
fn test_netdevsim_vf_spoofchk_off() {
    with_netdevsim_vfs(2, |ns, dev| {
        ns.ip_rs_exec_cmd(&[
            "link", "set", "dev", dev, "vf", "0", "spoofchk", "off",
        ]);
        ns.assert_eq_output(&["link", "show", dev]);
    });
}

#[ignore]
#[test]
fn test_netdevsim_vf_spoofchk_on() {
    with_netdevsim_vfs(2, |ns, dev| {
        ns.ip_rs_exec_cmd(&[
            "link", "set", "dev", dev, "vf", "0", "spoofchk", "on",
        ]);
        ns.assert_eq_output(&["link", "show", dev]);
    });
}

#[ignore]
#[test]
fn test_netdevsim_vf_link_state() {
    with_netdevsim_vfs(2, |ns, dev| {
        ns.ip_rs_exec_cmd(&[
            "link", "set", "dev", dev, "vf", "0", "state", "enable",
        ]);
        ns.assert_eq_output(&["link", "show", dev]);
    });
}

#[ignore]
#[test]
fn test_netdevsim_vf_link_state_disable() {
    with_netdevsim_vfs(2, |ns, dev| {
        ns.ip_rs_exec_cmd(&[
            "link", "set", "dev", dev, "vf", "0", "state", "disable",
        ]);
        ns.assert_eq_output(&["link", "show", dev]);
    });
}

#[ignore]
#[test]
fn test_netdevsim_vf_trust_on() {
    with_netdevsim_vfs(2, |ns, dev| {
        ns.ip_rs_exec_cmd(&[
            "link", "set", "dev", dev, "vf", "0", "trust", "on",
        ]);
        ns.assert_eq_output(&["link", "show", dev]);
    });
}

#[ignore]
#[test]
fn test_netdevsim_vf_trust_off() {
    with_netdevsim_vfs(2, |ns, dev| {
        ns.ip_rs_exec_cmd(&[
            "link", "set", "dev", dev, "vf", "0", "trust", "off",
        ]);
        ns.assert_eq_output(&["link", "show", dev]);
    });
}

#[ignore]
#[test]
fn test_netdevsim_vf_rate() {
    with_netdevsim_vfs(2, |ns, dev| {
        ns.ip_rs_exec_cmd(&[
            "link", "set", "dev", dev, "vf", "0", "rate", "500",
        ]);
        ns.assert_eq_output(&["link", "show", dev]);
    });
}

#[ignore]
#[test]
fn test_netdevsim_vf_max_tx_rate() {
    with_netdevsim_vfs(2, |ns, dev| {
        ns.ip_rs_exec_cmd(&[
            "link",
            "set",
            "dev",
            dev,
            "vf",
            "0",
            "max_tx_rate",
            "1000",
            "min_tx_rate",
            "100",
        ]);
        ns.assert_eq_output(&["link", "show", dev]);
    });
}

#[ignore]
#[test]
fn test_netdevsim_vf_multiple_options() {
    with_netdevsim_vfs(2, |ns, dev| {
        ns.ip_rs_exec_cmd(&[
            "link",
            "set",
            "dev",
            dev,
            "vf",
            "0",
            "mac",
            "00:11:22:33:44:55",
            "vlan",
            "100",
            "rate",
            "500",
            "spoofchk",
            "on",
            "trust",
            "on",
            "state",
            "enable",
        ]);
        ns.assert_eq_output(&["link", "show", dev]);
    });
}

#[ignore]
#[test]
fn test_netdevsim_vf_multiple_vfs() {
    with_netdevsim_vfs(4, |ns, dev| {
        ns.ip_rs_exec_cmd(&[
            "link",
            "set",
            "dev",
            dev,
            "vf",
            "0",
            "mac",
            "00:11:22:33:44:55",
        ]);
        ns.ip_rs_exec_cmd(&[
            "link", "set", "dev", dev, "vf", "1", "vlan", "200",
        ]);
        ns.ip_rs_exec_cmd(&[
            "link", "set", "dev", dev, "vf", "2", "spoofchk", "off",
        ]);
        ns.assert_eq_output(&["link", "show", dev]);
    });
}

#[ignore]
#[test]
fn test_netdevsim_vf_json_after_config() {
    with_netdevsim_vfs(2, |ns, dev| {
        ns.ip_rs_exec_cmd(&[
            "link",
            "set",
            "dev",
            dev,
            "vf",
            "0",
            "mac",
            "00:11:22:33:44:55",
            "vlan",
            "100",
            "rate",
            "500",
            "spoofchk",
            "on",
            "trust",
            "on",
            "state",
            "enable",
        ]);
        ns.assert_eq_output_map(
            &["-j", "link", "show", dev],
            strip_vfinfo_json,
        );
    });
}
