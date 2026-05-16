// SPDX-License-Identifier: MIT

use crate::tests::{NetnsGuard, with_netns};

fn with_dummy_iface<T>(ns: &NetnsGuard, dummy_name: &str, test: T) -> T::Output
where
    T: FnOnce(),
{
    ns.exec_cmd(&["ip", "link", "add", dummy_name, "type", "dummy"]);
    ns.exec_cmd(&["ip", "link", "set", dummy_name, "up"]);

    ns.exec_cmd(&["ip", "addr", "add", "192.168.1.1/24", "dev", dummy_name]);
    ns.exec_cmd(&["ip", "addr", "add", "192.168.1.2/24", "dev", dummy_name]);
    ns.exec_cmd(&["ip", "addr", "add", "ff::ab:cd/64", "dev", dummy_name]);
    ns.exec_cmd(&[
        "ip",
        "addr",
        "add",
        "2001:db8:beef::1/64",
        "dev",
        dummy_name,
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
        dummy_name,
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

    test();
}

#[test]
fn test_address_show() {
    with_netns(|ns| {
        let dummy_name = "atest-dummy1";

        with_dummy_iface(ns, dummy_name, || {
            let expected_output =
                ns.exec_cmd(&["ip", "address", "show", dummy_name]);
            let our_output =
                ns.ip_rs_exec_cmd(&["address", "show", dummy_name]);

            pretty_assertions::assert_eq!(expected_output, our_output);
        });
    });
}

#[test]
fn test_address_detailed_show() {
    with_netns(|ns| {
        let dummy_name = "atest-dummy2";

        with_dummy_iface(ns, dummy_name, || {
            let expected_output =
                ns.exec_cmd(&["ip", "-d", "address", "show", dummy_name]);
            let our_output =
                ns.ip_rs_exec_cmd(&["-d", "address", "show", dummy_name]);

            pretty_assertions::assert_eq!(expected_output, our_output);
        });
    });
}

#[test]
fn test_address_show_json() {
    with_netns(|ns| {
        let dummy_name = "atest-dummy3";

        with_dummy_iface(ns, dummy_name, || {
            let expected_output =
                ns.exec_cmd(&["ip", "-j", "address", "show", dummy_name]);
            let our_output =
                ns.ip_rs_exec_cmd(&["-j", "address", "show", dummy_name]);

            pretty_assertions::assert_eq!(expected_output, our_output);
        });
    });
}

#[test]
fn test_address_detailed_show_json() {
    with_netns(|ns| {
        let dummy_name = "atest-dummy4";

        with_dummy_iface(ns, dummy_name, || {
            let expected_output =
                ns.exec_cmd(&["ip", "-d", "-j", "address", "show", dummy_name]);
            let our_output =
                ns.ip_rs_exec_cmd(&["-d", "-j", "address", "show", dummy_name]);

            pretty_assertions::assert_eq!(expected_output, our_output);
        });
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
