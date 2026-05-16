// SPDX-License-Identifier: MIT

use crate::tests::{NetnsGuard, with_netns};

#[test]
fn test_link_show_dummy() {
    with_netns(|ns| {
        let ifname = "tdmy0";

        with_dummy_iface(ns, ifname, || {
            let expected_output = ns.exec_cmd(&["ip", "link", "show", ifname]);

            let our_output = ns.ip_rs_exec_cmd(&["link", "show", ifname]);

            pretty_assertions::assert_eq!(expected_output, our_output);
        })
    });
}

#[test]
fn test_link_detailed_show_dummy() {
    with_netns(|ns| {
        let ifname = "tdmy1";

        with_dummy_iface(ns, ifname, || {
            let expected_output =
                ns.exec_cmd(&["ip", "-d", "link", "show", ifname]);

            let our_output = ns.ip_rs_exec_cmd(&["-d", "link", "show", ifname]);

            pretty_assertions::assert_eq!(expected_output, our_output);
        })
    });
}

#[test]
fn test_link_show_dummy_json() {
    with_netns(|ns| {
        let ifname = "tdmy2";

        with_dummy_iface(ns, ifname, || {
            let expected_output =
                ns.exec_cmd(&["ip", "-j", "link", "show", ifname]);

            let our_output = ns.ip_rs_exec_cmd(&["-j", "link", "show", ifname]);

            pretty_assertions::assert_eq!(expected_output, our_output);
        })
    });
}

#[test]
fn test_link_detailed_show_dummy_json() {
    with_netns(|ns| {
        let ifname = "tdmy3";

        with_dummy_iface(ns, ifname, || {
            let expected_output =
                ns.exec_cmd(&["ip", "-d", "-j", "link", "show", ifname]);

            let our_output =
                ns.ip_rs_exec_cmd(&["-d", "-j", "link", "show", ifname]);

            pretty_assertions::assert_eq!(expected_output, our_output);
        })
    });
}

fn with_dummy_iface<T>(ns: &NetnsGuard, name: &str, test: T)
where
    T: FnOnce(),
{
    ns.ip_rs_exec_cmd(&[
        "link",
        "add",
        name,
        "address",
        "12:26:8a:bb:b4:2c",
        "type",
        "dummy",
    ]);
    ns.exec_cmd(&["ip", "link", "set", name, "up"]);

    test();
}
