// SPDX-License-Identifier: MIT

use crate::tests::{exec_cmd, ip_rs_exec_cmd};

#[test]
fn test_link_detailed_show_bond() {
    let bond_name = "test-bnd0";
    let dummy_name = "test-bnd-dummy0";

    with_bond_iface(bond_name, dummy_name, || {
        let expected_output =
            exec_cmd(&["ip", "-d", "link", "show", bond_name]);

        let our_output = ip_rs_exec_cmd(&["-d", "link", "show", bond_name]);

        pretty_assertions::assert_eq!(&expected_output, &our_output);
    })
}

#[test]
fn test_link_detailed_show_json_bond() {
    let bond_name = "test-bond1";
    let dummy_name = "test-bnd-dummy1";
    with_bond_iface(bond_name, dummy_name, || {
        let expected_output =
            exec_cmd(&["ip", "-d", "-j", "link", "show", bond_name]);

        let our_output =
            ip_rs_exec_cmd(&["-d", "-j", "link", "show", bond_name]);

        pretty_assertions::assert_eq!(&expected_output, &our_output);
    })
}

#[test]
fn test_link_detailed_show_bond_port() {
    let bond_name = "test-bond2";
    let dummy_name = "test-bnd-dummy2";

    with_bond_iface(bond_name, dummy_name, || {
        let expected_output =
            exec_cmd(&["ip", "-d", "link", "show", dummy_name]);

        let our_output = ip_rs_exec_cmd(&["-d", "link", "show", dummy_name]);

        pretty_assertions::assert_eq!(&expected_output, &our_output);
    })
}

#[test]
fn test_link_detailed_show_json_bond_port() {
    let bond_name = "test-bond3";
    let dummy_name = "test-bnd-dummy3";
    with_bond_iface(bond_name, dummy_name, || {
        let expected_output =
            exec_cmd(&["ip", "-d", "-j", "link", "show", dummy_name]);

        let our_output =
            ip_rs_exec_cmd(&["-d", "-j", "link", "show", dummy_name]);

        pretty_assertions::assert_eq!(&expected_output, &our_output);
    })
}

fn with_bond_iface<T>(bond_name: &str, dummy_name: &str, test: T)
where
    T: FnOnce() + std::panic::UnwindSafe,
{
    // create bridge using dummy interface
    exec_cmd(&["ip", "link", "add", dummy_name, "type", "dummy"]);
    exec_cmd(&["ip", "link", "add", bond_name, "type", "bond"]);
    exec_cmd(&["ip", "link", "set", "dev", dummy_name, "master", bond_name]);

    exec_cmd(&["ip", "link", "set", dummy_name, "up"]);
    exec_cmd(&["ip", "link", "set", bond_name, "up"]);

    // Wait 1 second for bridge ID to be stable
    std::thread::sleep(std::time::Duration::from_secs(1));

    let result = std::panic::catch_unwind(|| {
        test();
    });

    // clean up
    exec_cmd(&["ip", "link", "del", dummy_name]);
    exec_cmd(&["ip", "link", "del", bond_name]);
    assert!(result.is_ok())
}
