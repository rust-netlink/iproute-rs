// SPDX-License-Identifier: MIT

use crate::tests::{NetnsGuard, with_netns};

#[test]
fn test_link_detailed_show_bond() {
    with_netns(|ns| {
        let bond_name = "test-bnd0";
        let dummy_name = "test-bnd-dummy0";

        with_bond_iface(ns, bond_name, dummy_name, || {
            let expected_output =
                ns.exec_cmd(&["ip", "-d", "link", "show", bond_name]);
            let our_output =
                ns.ip_rs_exec_cmd(&["-d", "link", "show", bond_name]);
            pretty_assertions::assert_eq!(&expected_output, &our_output);
        });
    })
}

#[test]
fn test_link_detailed_show_json_bond() {
    with_netns(|ns| {
        let bond_name = "test-bond1";
        let dummy_name = "test-bnd-dummy1";
        with_bond_iface(ns, bond_name, dummy_name, || {
            let expected_output =
                ns.exec_cmd(&["ip", "-d", "-j", "link", "show", bond_name]);
            let our_output =
                ns.ip_rs_exec_cmd(&["-d", "-j", "link", "show", bond_name]);
            pretty_assertions::assert_eq!(&expected_output, &our_output);
        })
    })
}

#[test]
fn test_link_detailed_show_bond_port() {
    with_netns(|ns| {
        let bond_name = "test-bond2";
        let dummy_name = "test-bnd-dummy2";

        with_bond_iface(ns, bond_name, dummy_name, || {
            let expected_output =
                ns.exec_cmd(&["ip", "-d", "link", "show", dummy_name]);
            let our_output =
                ns.ip_rs_exec_cmd(&["-d", "link", "show", dummy_name]);
            pretty_assertions::assert_eq!(&expected_output, &our_output);
        })
    })
}

#[test]
fn test_link_detailed_show_json_bond_port() {
    with_netns(|ns| {
        let bond_name = "test-bond3";
        let dummy_name = "test-bnd-dummy3";
        with_bond_iface(ns, bond_name, dummy_name, || {
            let expected_output =
                ns.exec_cmd(&["ip", "-d", "-j", "link", "show", dummy_name]);
            let our_output =
                ns.ip_rs_exec_cmd(&["-d", "-j", "link", "show", dummy_name]);
            pretty_assertions::assert_eq!(&expected_output, &our_output);
        })
    })
}

fn with_bond_iface<T>(
    ns: &NetnsGuard,
    bond_name: &str,
    dummy_name: &str,
    test: T,
) where
    T: FnOnce(),
{
    ns.exec_cmd(&["ip", "link", "add", dummy_name, "type", "dummy"]);
    ns.exec_cmd(&["ip", "link", "add", bond_name, "type", "bond"]);
    ns.exec_cmd(&["ip", "link", "set", "dev", dummy_name, "master", bond_name]);

    ns.exec_cmd(&["ip", "link", "set", dummy_name, "up"]);
    ns.exec_cmd(&["ip", "link", "set", bond_name, "up"]);

    test();
}
