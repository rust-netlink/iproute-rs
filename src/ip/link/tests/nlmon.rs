// SPDX-License-Identifier: MIT

use crate::tests::{NetnsGuard, with_netns};

const NLMON_NAME: &str = "test-nlmon";

#[test]
fn test_link_show_nlmon() {
    with_nlmon_iface(|ns| {
        ns.assert_eq_output(&["link", "show", NLMON_NAME]);
    });
}

#[test]
fn test_link_detailed_show_nlmon() {
    with_nlmon_iface(|ns| {
        ns.assert_eq_output(&["-d", "link", "show", NLMON_NAME]);
    });
}

#[test]
fn test_link_show_nlmon_json() {
    with_nlmon_iface(|ns| {
        ns.assert_eq_output(&["-j", "link", "show", NLMON_NAME]);
    });
}

#[test]
fn test_link_detailed_show_nlmon_json() {
    with_nlmon_iface(|ns| {
        ns.assert_eq_output(&["-d", "-j", "link", "show", NLMON_NAME]);
    });
}

fn with_nlmon_iface<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&["link", "add", NLMON_NAME, "type", "nlmon"]);
        ns.exec_cmd(&["ip", "link", "set", NLMON_NAME, "up"]);

        test(ns);
    });
}
