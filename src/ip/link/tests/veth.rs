// SPDX-License-Identifier: MIT

use crate::tests::{NetnsGuard, with_netns};

const VETH_NAME: &str = "test-veth";
const VETH_PEER_NAME: &str = "test-veth-peer";

#[test]
fn test_link_show_veth() {
    with_veth_iface(|ns| {
        ns.assert_eq_output(&["link", "show", VETH_NAME]);
    });
}

#[test]
fn test_link_detailed_show_veth() {
    with_veth_iface(|ns| {
        ns.assert_eq_output(&["-d", "link", "show", VETH_NAME]);
    });
}

#[test]
fn test_link_show_veth_json() {
    with_veth_iface(|ns| {
        ns.assert_eq_output(&["-j", "link", "show", VETH_NAME]);
    });
}

#[test]
fn test_link_detailed_show_veth_json() {
    with_veth_iface(|ns| {
        ns.assert_eq_output(&["-d", "-j", "link", "show", VETH_NAME]);
    });
}

fn with_veth_iface<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link",
            "add",
            VETH_NAME,
            "type",
            "veth",
            "peer",
            VETH_PEER_NAME,
        ]);
        ns.exec_cmd(&["ip", "link", "set", VETH_NAME, "up"]);
        ns.exec_cmd(&["ip", "link", "set", VETH_PEER_NAME, "up"]);

        test(ns);
    });
}
