// SPDX-License-Identifier: MIT

use crate::tests::{exec_cmd, ip_rs_exec_cmd};

#[test]
fn test_address_show() {
    let bond_name = "atest-bond1";
    let dummy_name = "atest-bnd-dum1";

    with_bond_iface(bond_name, dummy_name, || {
        let expected_output = exec_cmd(&["ip", "address", "show", bond_name]);
        let our_output = ip_rs_exec_cmd(&["address", "show", bond_name]);

        pretty_assertions::assert_eq!(expected_output, our_output);
    });
}

#[test]
fn test_address_detailed_show() {
    let bond_name = "atest-bond2";
    let dummy_name = "atest-bnd-dum2";

    with_bond_iface(bond_name, dummy_name, || {
        let expected_output =
            exec_cmd(&["ip", "-d", "address", "show", bond_name]);
        let our_output = ip_rs_exec_cmd(&["-d", "address", "show", bond_name]);

        pretty_assertions::assert_eq!(expected_output, our_output);
    });
}

#[test]
fn test_address_show_json() {
    let bond_name = "atest-bond3";
    let dummy_name = "atest-bnd-dum3";

    with_bond_iface(bond_name, dummy_name, || {
        let expected_output =
            exec_cmd(&["ip", "-j", "address", "show", bond_name]);
        let our_output = ip_rs_exec_cmd(&["-j", "address", "show", bond_name]);

        pretty_assertions::assert_eq!(expected_output, our_output);
    });
}

#[test]
fn test_address_detailed_show_json() {
    let bond_name = "atest-bond4";
    let dummy_name = "atest-bnd-dum4";

    with_bond_iface(bond_name, dummy_name, || {
        let expected_output =
            exec_cmd(&["ip", "-d", "-j", "address", "show", bond_name]);
        let our_output =
            ip_rs_exec_cmd(&["-d", "-j", "address", "show", bond_name]);

        pretty_assertions::assert_eq!(expected_output, our_output);
    });
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

    exec_cmd(&["ip", "addr", "add", "192.168.1.1/24", "dev", bond_name]);
    exec_cmd(&["ip", "addr", "add", "ff::ab:cd/64", "dev", bond_name]);

    // Wait 2 seconds for bond to be up and addresses to be assigned
    std::thread::sleep(std::time::Duration::from_secs(2));

    let result = std::panic::catch_unwind(|| {
        test();
    });

    // clean up
    exec_cmd(&["ip", "link", "del", dummy_name]);
    exec_cmd(&["ip", "link", "del", bond_name]);
    assert!(result.is_ok())
}
