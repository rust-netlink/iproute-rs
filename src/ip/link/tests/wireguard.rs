// SPDX-License-Identifier: MIT

use crate::tests::{NetnsGuard, with_netns};

const WG_NAME: &str = "test-wg0";

#[test]
fn test_link_show_wireguard() {
    with_wireguard_iface(|ns| {
        ns.assert_eq_output(&["link", "show", WG_NAME]);
    });
}

#[test]
fn test_link_detailed_show_wireguard() {
    with_wireguard_iface(|ns| {
        ns.assert_eq_output(&["-d", "link", "show", WG_NAME]);
    });
}

#[test]
fn test_link_show_wireguard_json() {
    with_wireguard_iface(|ns| {
        ns.assert_eq_output(&["-j", "link", "show", WG_NAME]);
    });
}

#[test]
fn test_link_detailed_show_wireguard_json() {
    with_wireguard_iface(|ns| {
        ns.assert_eq_output(&["-d", "-j", "link", "show", WG_NAME]);
    });
}

fn with_wireguard_iface<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&["link", "add", WG_NAME, "type", "wireguard"]);
        ns.ip_rs_exec_cmd(&["link", "set", WG_NAME, "up"]);

        test(ns);
    });
}
