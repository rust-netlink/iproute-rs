// SPDX-License-Identifier: MIT

mod common;
use self::common::{NetnsGuard, with_netns};

const XFRM_NAME: &str = "test-xfrm";

#[test]
fn test_link_show_xfrm() {
    with_xfrm_iface(|ns| {
        ns.assert_eq_output(&["link", "show", XFRM_NAME]);
    });
}

#[test]
fn test_link_detailed_show_xfrm() {
    with_xfrm_iface(|ns| {
        ns.assert_eq_output(&["-d", "link", "show", XFRM_NAME]);
    });
}

#[test]
fn test_link_show_xfrm_json() {
    with_xfrm_iface(|ns| {
        ns.assert_eq_output(&["-j", "link", "show", XFRM_NAME]);
    });
}

#[test]
fn test_link_detailed_show_xfrm_json() {
    with_xfrm_iface(|ns| {
        ns.assert_eq_output(&["-d", "-j", "link", "show", XFRM_NAME]);
    });
}

fn with_xfrm_iface<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link", "add", XFRM_NAME, "type", "xfrm", "dev", "lo", "if_id",
            "0x2a",
        ]);
        ns.ip_rs_exec_cmd(&["link", "set", XFRM_NAME, "up"]);

        test(ns);
    });
}
