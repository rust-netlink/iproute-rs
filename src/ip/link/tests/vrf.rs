// SPDX-License-Identifier: MIT

use crate::tests::{NetnsGuard, with_netns};

const VRF_NAME: &str = "tdvrf";

#[test]
fn test_link_add_vrf() {
    with_vrf_iface(|ns| {
        ns.assert_eq_output(&["link", "show", VRF_NAME]);
    });
}

#[test]
fn test_link_detailed_show_vrf() {
    with_vrf_iface(|ns| {
        ns.assert_eq_output(&["-d", "link", "show", VRF_NAME]);
    });
}

#[test]
fn test_link_show_vrf_json() {
    with_vrf_iface(|ns| {
        ns.assert_eq_output(&["-j", "link", "show", VRF_NAME]);
    });
}

#[test]
fn test_link_detailed_show_vrf_json() {
    with_vrf_iface(|ns| {
        ns.assert_eq_output(&["-d", "-j", "link", "show", VRF_NAME]);
    });
}

fn with_vrf_iface<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link", "add", VRF_NAME, "type", "vrf", "table", "10",
        ]);
        ns.exec_cmd(&["ip", "link", "set", VRF_NAME, "up"]);

        test(ns);
    });
}
