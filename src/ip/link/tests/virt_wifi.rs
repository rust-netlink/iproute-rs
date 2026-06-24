// SPDX-License-Identifier: MIT

use crate::tests::{NetnsGuard, with_netns};

const VIRT_WIFI_NAME: &str = "test-virt-wifi";

#[test]
fn test_link_show_virt_wifi() {
    with_virt_wifi_iface(|ns| {
        ns.assert_eq_output(&["link", "show", VIRT_WIFI_NAME]);
    });
}

#[test]
fn test_link_detailed_show_virt_wifi() {
    with_virt_wifi_iface(|ns| {
        ns.assert_eq_output(&["-d", "link", "show", VIRT_WIFI_NAME]);
    });
}

#[test]
fn test_link_show_virt_wifi_json() {
    with_virt_wifi_iface(|ns| {
        ns.assert_eq_output(&["-j", "link", "show", VIRT_WIFI_NAME]);
    });
}

#[test]
fn test_link_detailed_show_virt_wifi_json() {
    with_virt_wifi_iface(|ns| {
        ns.assert_eq_output(&["-d", "-j", "link", "show", VIRT_WIFI_NAME]);
    });
}

fn with_virt_wifi_iface<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link",
            "add",
            VIRT_WIFI_NAME,
            "link",
            "lo",
            "type",
            "virt_wifi",
        ]);
        ns.ip_rs_exec_cmd(&["link", "set", VIRT_WIFI_NAME, "up"]);

        test(ns);
    });
}
