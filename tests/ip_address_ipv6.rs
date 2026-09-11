// SPDX-License-Identifier: MIT

mod common;

use self::common::{DUMMY_NAME, with_dummy_iface_empty};

fn wait_for_dad() {
    // The tests run iproute2 and ip-rs show commands sequentially. Without
    // waiting for DAD to finish, the address may be reported as tentative
    // only by the first command.
    std::thread::sleep(std::time::Duration::from_secs(2));
}

#[test]
fn test_address_add_simple_ipv6() {
    with_dummy_iface_empty(|ns| {
        ns.ip_rs_exec_cmd(&[
            "address",
            "add",
            "2001:db8::1/64",
            "dev",
            DUMMY_NAME,
        ]);
        wait_for_dad();
        ns.assert_eq_output(&["address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_add_ipv6_with_all_options() {
    with_dummy_iface_empty(|ns| {
        ns.ip_rs_exec_cmd(&[
            "address",
            "add",
            "2001:db8::1/64",
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
        wait_for_dad();
        ns.assert_eq_output(&["address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_add_home_flag() {
    with_dummy_iface_empty(|ns| {
        ns.ip_rs_exec_cmd(&[
            "address",
            "add",
            "2001:db8::1/64",
            "dev",
            DUMMY_NAME,
            "scope",
            "global",
            "home",
            "proto",
            "kernel_ra",
        ]);
        wait_for_dad();
        ns.assert_eq_output(&["address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_add_without_prefix_v6() {
    with_dummy_iface_empty(|ns| {
        ns.ip_rs_exec_cmd(&[
            "address",
            "add",
            "2001:db8::1",
            "dev",
            DUMMY_NAME,
        ]);
        wait_for_dad();
        ns.assert_eq_output(&["address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_add_alias_a_ad() {
    with_dummy_iface_empty(|ns| {
        ns.ip_rs_exec_cmd(&["a", "ad", "2001:db8::1/64", "dev", DUMMY_NAME]);
        wait_for_dad();
        ns.assert_eq_output(&["address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_change_ipv6_scope() {
    with_dummy_iface_empty(|ns| {
        ns.exec_cmd(&[
            "ip",
            "addr",
            "add",
            "2001:db8::1/64",
            "dev",
            DUMMY_NAME,
        ]);
        wait_for_dad();
        ns.ip_rs_exec_cmd(&[
            "address",
            "change",
            "2001:db8::1/64",
            "dev",
            DUMMY_NAME,
            "scope",
            "host",
        ]);
        ns.assert_eq_output(&["address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_delete_ipv6() {
    with_dummy_iface_empty(|ns| {
        ns.exec_cmd(&[
            "ip",
            "addr",
            "add",
            "2001:db8::1/64",
            "dev",
            DUMMY_NAME,
        ]);
        wait_for_dad();
        ns.ip_rs_exec_cmd(&[
            "address",
            "delete",
            "2001:db8::1/64",
            "dev",
            DUMMY_NAME,
        ]);
        ns.assert_eq_output(&["address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_replace_ipv6_create_new() {
    with_dummy_iface_empty(|ns| {
        ns.ip_rs_exec_cmd(&[
            "address",
            "replace",
            "2001:db8::1/64",
            "dev",
            DUMMY_NAME,
        ]);
        wait_for_dad();
        ns.assert_eq_output(&["address", "show", DUMMY_NAME]);
    });
}
