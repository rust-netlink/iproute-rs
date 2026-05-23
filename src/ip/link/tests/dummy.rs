// SPDX-License-Identifier: MIT

use crate::tests::{NetnsGuard, with_netns};

const DUMMY_NAME: &str = "test-dummy";

#[test]
fn test_link_show_dummy() {
    with_dummy_iface(|ns| {
        ns.assert_eq_output(&["link", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_link_detailed_show_dummy() {
    with_dummy_iface(|ns| {
        ns.assert_eq_output(&["-d", "link", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_link_show_dummy_json() {
    with_dummy_iface(|ns| {
        ns.assert_eq_output(&["-j", "link", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_link_detailed_show_dummy_json() {
    with_dummy_iface(|ns| {
        ns.assert_eq_output(&["-d", "-j", "link", "show", DUMMY_NAME]);
    });
}

fn with_dummy_iface<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link",
            "add",
            DUMMY_NAME,
            "address",
            "12:26:8a:bb:b4:2c",
            "type",
            "dummy",
        ]);
        ns.exec_cmd(&["ip", "link", "set", DUMMY_NAME, "up"]);

        test(ns);
    });
}
