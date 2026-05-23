// SPDX-License-Identifier: MIT

use crate::tests::{NetnsGuard, with_netns};

const BOND_NAME: &str = "test-bond";
const DUMMY_NAME: &str = "test-bnd-dummy";

#[test]
fn test_link_detailed_show_bond() {
    with_bond_iface(|ns| {
        ns.assert_eq_output(&["-d", "link", "show", BOND_NAME]);
    });
}

#[test]
fn test_link_detailed_show_json_bond() {
    with_bond_iface(|ns| {
        ns.assert_eq_output(&["-d", "-j", "link", "show", BOND_NAME]);
    });
}

#[test]
fn test_link_detailed_show_bond_port() {
    with_bond_iface(|ns| {
        ns.assert_eq_output(&["-d", "link", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_link_detailed_show_json_bond_port() {
    with_bond_iface(|ns| {
        ns.assert_eq_output(&["-d", "-j", "link", "show", DUMMY_NAME]);
    })
}

fn with_bond_iface<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        ns.exec_cmd(&["ip", "link", "add", DUMMY_NAME, "type", "dummy"]);
        ns.exec_cmd(&["ip", "link", "add", BOND_NAME, "type", "bond"]);
        ns.exec_cmd(&[
            "ip", "link", "set", "dev", DUMMY_NAME, "master", BOND_NAME,
        ]);

        ns.exec_cmd(&["ip", "link", "set", DUMMY_NAME, "up"]);
        ns.exec_cmd(&["ip", "link", "set", BOND_NAME, "up"]);

        test(ns);
    })
}
