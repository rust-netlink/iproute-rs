// SPDX-License-Identifier: MIT

mod common;
use self::common::{NetnsGuard, with_netns};

const IFB_NAME: &str = "ifb0";

#[test]
fn test_link_show_ifb() {
    with_ifb_iface(|ns| {
        ns.assert_eq_output(&["link", "show", IFB_NAME]);
    });
}

#[test]
fn test_link_detailed_show_ifb() {
    with_ifb_iface(|ns| {
        ns.assert_eq_output(&["-d", "link", "show", IFB_NAME]);
    });
}

#[test]
fn test_link_show_ifb_json() {
    with_ifb_iface(|ns| {
        ns.assert_eq_output(&["-j", "link", "show", IFB_NAME]);
    });
}

#[test]
fn test_link_detailed_show_ifb_json() {
    with_ifb_iface(|ns| {
        ns.assert_eq_output(&["-d", "-j", "link", "show", IFB_NAME]);
    });
}

fn with_ifb_iface<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&["link", "add", IFB_NAME, "type", "ifb"]);
        ns.ip_rs_exec_cmd(&["link", "set", IFB_NAME, "up"]);

        test(ns);
    });
}
