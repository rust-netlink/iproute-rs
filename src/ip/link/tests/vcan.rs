// SPDX-License-Identifier: MIT

use crate::tests::{NetnsGuard, with_netns};

const VCAN_NAME: &str = "test-vcan";

#[test]
fn test_link_show_vcan() {
    with_vcan_iface(|ns| {
        ns.assert_eq_output(&["link", "show", VCAN_NAME]);
    });
}

#[test]
fn test_link_detailed_show_vcan() {
    with_vcan_iface(|ns| {
        ns.assert_eq_output(&["-d", "link", "show", VCAN_NAME]);
    });
}

#[test]
fn test_link_show_vcan_json() {
    with_vcan_iface(|ns| {
        ns.assert_eq_output(&["-j", "link", "show", VCAN_NAME]);
    });
}

#[test]
fn test_link_detailed_show_vcan_json() {
    with_vcan_iface(|ns| {
        ns.assert_eq_output(&["-d", "-j", "link", "show", VCAN_NAME]);
    });
}

fn with_vcan_iface<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&["link", "add", VCAN_NAME, "type", "vcan"]);
        ns.exec_cmd(&["ip", "link", "set", VCAN_NAME, "up"]);

        test(ns);
    });
}
