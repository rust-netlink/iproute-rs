// SPDX-License-Identifier: MIT

use std::{
    process::Command,
    sync::{LazyLock, Mutex},
};

use crate::tests::{NetnsGuard, with_netns};

/// Serialises all rmnet tests so they don't race on the kernel module.
static RMNET_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

/// Must be at most 15 characters (IFNAMSIZ - 1).
const PARENT_NAME: &str = "test-rmnet-base";
const RMNET_NAME: &str = "test-rmnet";

#[test]
fn test_link_show_rmnet() {
    with_rmnet_iface(|ns| {
        ns.assert_eq_output(&["link", "show", RMNET_NAME]);
    });
}

#[test]
fn test_link_detailed_show_rmnet() {
    with_rmnet_iface(|ns| {
        ns.assert_eq_output(&["-d", "link", "show", RMNET_NAME]);
    });
}

#[test]
fn test_link_show_rmnet_json() {
    with_rmnet_iface(|ns| {
        ns.assert_eq_output(&["-j", "link", "show", RMNET_NAME]);
    });
}

#[test]
fn test_link_detailed_show_rmnet_json() {
    with_rmnet_iface(|ns| {
        ns.assert_eq_output(&["-d", "-j", "link", "show", RMNET_NAME]);
    });
}

fn with_rmnet_iface<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    let _guard = RMNET_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !std::path::Path::new("/sys/module/rmnet").exists() {
        let _ = Command::new("modprobe").args(["rmnet"]).status();
        if !std::path::Path::new("/sys/module/rmnet").exists() {
            panic!("rmnet kernel module not available");
        }
    }

    with_netns(|ns| {
        // Create parent dummy interface
        ns.ip_rs_exec_cmd(&["link", "add", PARENT_NAME, "type", "dummy"]);
        ns.ip_rs_exec_cmd(&["link", "set", PARENT_NAME, "up"]);

        // Create rmnet interface on top of the dummy
        ns.ip_rs_exec_cmd(&[
            "link",
            "add",
            "link",
            PARENT_NAME,
            "name",
            RMNET_NAME,
            "type",
            "rmnet",
            "mux_id",
            "10",
        ]);
        ns.ip_rs_exec_cmd(&["link", "set", RMNET_NAME, "up"]);

        test(ns);
    });
}
