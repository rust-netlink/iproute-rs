// SPDX-License-Identifier: MIT

// These tests require the wwan_hwsim kernel module to be loaded and a wwan0
// device to be present. They are ignored by default.

use std::{process::Command, sync::Mutex};

use crate::tests::{NetnsGuard, with_netns};

const WWAN_NAME: &str = "test-wwan0";

/// Serialises all wwan tests so they don't race on the kernel module.
static WWAN_LOCK: Mutex<()> = Mutex::new(());

fn with_wwan_iface<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    let _guard = WWAN_LOCK.lock().unwrap();
    let mut loaded_module = false;
    if !std::path::Path::new("/sys/class/net/wwan0").exists() {
        loaded_module = Command::new("modprobe")
            .args(["wwan_hwsim"])
            .status()
            .is_ok_and(|s| s.success());
        if !std::path::Path::new("/sys/class/net/wwan0").exists() {
            panic!("wwan_hwsim module not available");
        }
    }

    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link",
            "add",
            WWAN_NAME,
            "parentdev",
            "wwan0",
            "type",
            "wwan",
            "linkid",
            "42",
        ]);
        ns.ip_rs_exec_cmd(&["link", "set", WWAN_NAME, "up"]);

        test(ns);
    });

    if loaded_module {
        let _ = Command::new("modprobe").args(["-r", "wwan_hwsim"]).status();
    }
}

#[test]
#[ignore]
fn test_link_show_wwan() {
    with_wwan_iface(|ns| {
        ns.assert_eq_output(&["link", "show", WWAN_NAME]);
    });
}

#[test]
#[ignore]
fn test_link_detailed_show_wwan() {
    with_wwan_iface(|ns| {
        ns.assert_eq_output(&["-d", "link", "show", WWAN_NAME]);
    });
}

#[test]
#[ignore]
fn test_link_show_wwan_json() {
    with_wwan_iface(|ns| {
        ns.assert_eq_output(&["-j", "link", "show", WWAN_NAME]);
    });
}

#[test]
#[ignore]
fn test_link_detailed_show_wwan_json() {
    with_wwan_iface(|ns| {
        ns.assert_eq_output(&["-d", "-j", "link", "show", WWAN_NAME]);
    });
}
