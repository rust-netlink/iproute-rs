// SPDX-License-Identifier: MIT

use crate::tests::{assert_alias_output, exec_cmd, ip_rs_exec_cmd};

#[test]
fn test_address_show() {
    let dummy_name = "atest-dummy1";

    with_dummy_iface(dummy_name, || {
        let expected_output = exec_cmd(&["ip", "address", "show", dummy_name]);
        let our_output = ip_rs_exec_cmd(&["address", "show", dummy_name]);

        pretty_assertions::assert_eq!(expected_output, our_output);
    });
}

#[test]
fn test_address_detailed_show() {
    let dummy_name = "atest-dummy2";

    with_dummy_iface(dummy_name, || {
        let expected_output =
            exec_cmd(&["ip", "-d", "address", "show", dummy_name]);
        let our_output = ip_rs_exec_cmd(&["-d", "address", "show", dummy_name]);

        pretty_assertions::assert_eq!(expected_output, our_output);
    });
}

#[test]
fn test_address_show_json() {
    let dummy_name = "atest-dummy3";

    with_dummy_iface(dummy_name, || {
        let expected_output =
            exec_cmd(&["ip", "-j", "address", "show", dummy_name]);
        let our_output = ip_rs_exec_cmd(&["-j", "address", "show", dummy_name]);

        pretty_assertions::assert_eq!(expected_output, our_output);
    });
}

#[test]
fn test_address_detailed_show_json() {
    let dummy_name = "atest-dummy4";

    with_dummy_iface(dummy_name, || {
        let expected_output =
            exec_cmd(&["ip", "-d", "-j", "address", "show", dummy_name]);
        let our_output =
            ip_rs_exec_cmd(&["-d", "-j", "address", "show", dummy_name]);

        pretty_assertions::assert_eq!(expected_output, our_output);
    });
}

#[test]
fn test_address_alias_a_s() {
    assert_alias_output(&["address", "show", "lo"], &["a", "s", "lo"]);
}

#[test]
fn test_address_alias_addr_show() {
    assert_alias_output(&["address", "show", "lo"], &["addr", "show", "lo"]);
}

#[test]
fn test_address_alias_address_s() {
    assert_alias_output(&["address", "show", "lo"], &["address", "s", "lo"]);
}

#[test]
fn test_address_alias_add_ls() {
    assert_alias_output(&["address", "show", "lo"], &["add", "ls", "lo"]);
}

fn with_dummy_iface<T>(dummy_name: &str, test: T)
where
    T: FnOnce() + std::panic::UnwindSafe,
{
    exec_cmd(&["ip", "link", "add", dummy_name, "type", "dummy"]);
    exec_cmd(&["ip", "link", "set", dummy_name, "up"]);

    exec_cmd(&["ip", "addr", "add", "192.168.1.1/24", "dev", dummy_name]);
    exec_cmd(&["ip", "addr", "add", "ff::ab:cd/64", "dev", dummy_name]);

    // Wait 2 seconds for interface to be up and addresses to be assigned
    std::thread::sleep(std::time::Duration::from_secs(2));

    let result = std::panic::catch_unwind(|| {
        test();
    });

    // clean up
    exec_cmd(&["ip", "link", "del", dummy_name]);
    assert!(result.is_ok())
}
