// SPDX-License-Identifier: MIT

use crate::tests::{exec_cmd, ip_rs_exec_cmd};

#[test]
fn test_link_show_dummy() {
    let ifname = "tdmy0";

    with_dummy_iface(ifname, || {
        let expected_output = exec_cmd(&["ip", "link", "show", ifname]);

        let our_output = ip_rs_exec_cmd(&["link", "show", ifname]);

        pretty_assertions::assert_eq!(expected_output, our_output);
    })
}

#[test]
fn test_link_detailed_show_dummy() {
    let ifname = "tdmy1";

    with_dummy_iface(ifname, || {
        let expected_output = exec_cmd(&["ip", "-d", "link", "show", ifname]);

        let our_output = ip_rs_exec_cmd(&["-d", "link", "show", ifname]);

        pretty_assertions::assert_eq!(expected_output, our_output);
    })
}

#[test]
fn test_link_show_dummy_json() {
    let ifname = "tdmy2";

    with_dummy_iface(ifname, || {
        let expected_output = exec_cmd(&["ip", "-j", "link", "show", ifname]);

        let our_output = ip_rs_exec_cmd(&["-j", "link", "show", ifname]);

        pretty_assertions::assert_eq!(expected_output, our_output);
    })
}

#[test]
fn test_link_detailed_show_dummy_json() {
    let ifname = "tdmy3";

    with_dummy_iface(ifname, || {
        let expected_output =
            exec_cmd(&["ip", "-d", "-j", "link", "show", ifname]);

        let our_output = ip_rs_exec_cmd(&["-d", "-j", "link", "show", ifname]);

        pretty_assertions::assert_eq!(expected_output, our_output);
    })
}

fn with_dummy_iface<T>(name: &str, test: T)
where
    T: FnOnce() + std::panic::UnwindSafe,
{
    ip_rs_exec_cmd(&[
        "link",
        "add",
        name,
        "address",
        "12:26:8a:bb:b4:2c",
        "type",
        "dummy",
    ]);
    exec_cmd(&["ip", "link", "set", name, "up"]);

    let result = std::panic::catch_unwind(|| {
        test();
    });

    // clean up
    exec_cmd(&["ip", "link", "del", name]);
    assert!(result.is_ok())
}
