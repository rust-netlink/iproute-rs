// SPDX-License-Identifier: MIT

use crate::tests::{NetnsGuard, with_netns};

const DUMMY_NAME: &str = "test-dummy";

fn with_dummy_iface<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        ns.exec_cmd(&["ip", "link", "add", DUMMY_NAME, "type", "dummy"]);
        ns.exec_cmd(&["ip", "link", "set", DUMMY_NAME, "up"]);

        ns.exec_cmd(&[
            "ip",
            "addr",
            "add",
            "192.168.1.1/24",
            "dev",
            DUMMY_NAME,
        ]);
        ns.exec_cmd(&[
            "ip",
            "addr",
            "add",
            "192.168.1.2/24",
            "dev",
            DUMMY_NAME,
        ]);
        ns.exec_cmd(&["ip", "addr", "add", "ff::ab:cd/64", "dev", DUMMY_NAME]);
        ns.exec_cmd(&[
            "ip",
            "addr",
            "add",
            "2001:db8:beef::1/64",
            "dev",
            DUMMY_NAME,
            "valid_lft",
            "21384",
            "preferred_lft",
            "21384",
            "scope",
            "global",
            "mngtmpaddr",
            "proto",
            "kernel_ra",
        ]);
        ns.exec_cmd(&[
            "ip",
            "addr",
            "add",
            "2001:db8:beef::2/64",
            "dev",
            DUMMY_NAME,
            "valid_lft",
            "21381",
            "preferred_lft",
            "21381",
            "scope",
            "global",
            "home",
            "proto",
            "kernel_ra",
        ]);

        // Wait 2 seconds for interface to be up and addresses to be assigned
        std::thread::sleep(std::time::Duration::from_secs(2));

        test(ns);
    });
}

#[test]
fn test_address_show() {
    with_dummy_iface(|ns| {
        ns.assert_eq_output(&["address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_detailed_show() {
    with_dummy_iface(|ns| {
        ns.assert_eq_output(&["-d", "address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_show_json() {
    with_dummy_iface(|ns| {
        ns.assert_eq_output(&["-j", "address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_detailed_show_json() {
    with_dummy_iface(|ns| {
        ns.assert_eq_output(&["-d", "-j", "address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_alias_a_s() {
    with_netns(|ns| {
        ns.assert_alias_output(&["address", "show", "lo"], &["a", "s", "lo"]);
    });
}

#[test]
fn test_address_alias_addr_show() {
    with_netns(|ns| {
        ns.assert_alias_output(
            &["address", "show", "lo"],
            &["addr", "show", "lo"],
        );
    });
}

#[test]
fn test_address_alias_address_s() {
    with_netns(|ns| {
        ns.assert_alias_output(
            &["address", "show", "lo"],
            &["address", "s", "lo"],
        );
    });
}

#[test]
fn test_address_alias_add_ls() {
    with_netns(|ns| {
        ns.assert_alias_output(
            &["address", "show", "lo"],
            &["add", "ls", "lo"],
        );
    });
}
