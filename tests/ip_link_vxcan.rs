// SPDX-License-Identifier: MIT

mod common;
use self::common::{NetnsGuard, with_netns};

const VXCAN_NAME: &str = "test-vxcan";
const VXCAN_PEER_NAME: &str = "test-vxcan-peer";

#[test]
fn test_link_show_vxcan() {
    with_vxcan_iface(|ns| {
        ns.assert_eq_output(&["link", "show", VXCAN_NAME]);
    });
}

#[test]
fn test_link_detailed_show_vxcan() {
    with_vxcan_iface(|ns| {
        ns.assert_eq_output(&["-d", "link", "show", VXCAN_NAME]);
    });
}

#[test]
fn test_link_show_vxcan_json() {
    with_vxcan_iface(|ns| {
        ns.assert_eq_output(&["-j", "link", "show", VXCAN_NAME]);
    });
}

#[test]
fn test_link_detailed_show_vxcan_json() {
    with_vxcan_iface(|ns| {
        ns.assert_eq_output(&["-d", "-j", "link", "show", VXCAN_NAME]);
    });
}

fn with_vxcan_iface<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link",
            "add",
            VXCAN_NAME,
            "type",
            "vxcan",
            "peer",
            "name",
            VXCAN_PEER_NAME,
        ]);
        ns.ip_rs_exec_cmd(&["link", "set", VXCAN_NAME, "up"]);
        ns.ip_rs_exec_cmd(&["link", "set", VXCAN_PEER_NAME, "up"]);

        test(ns);
    });
}
