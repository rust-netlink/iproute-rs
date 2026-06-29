// SPDX-License-Identifier: MIT

use crate::tests::{NetnsGuard, with_netns};

const PFCP_NAME: &str = "test-pfcp";

#[ignore]
#[test]
fn test_link_show_pfcp() {
    with_pfcp_iface(|ns| {
        ns.assert_eq_output(&["link", "show", PFCP_NAME]);
    });
}

#[ignore]
#[test]
fn test_link_detailed_show_pfcp() {
    with_pfcp_iface(|ns| {
        ns.assert_eq_output(&["-d", "link", "show", PFCP_NAME]);
    });
}

#[ignore]
#[test]
fn test_link_show_pfcp_json() {
    with_pfcp_iface(|ns| {
        ns.assert_eq_output(&["-j", "link", "show", PFCP_NAME]);
    });
}

#[ignore]
#[test]
fn test_link_detailed_show_pfcp_json() {
    with_pfcp_iface(|ns| {
        ns.assert_eq_output(&["-d", "-j", "link", "show", PFCP_NAME]);
    });
}

fn with_pfcp_iface<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&["link", "add", PFCP_NAME, "type", "pfcp"]);
        ns.ip_rs_exec_cmd(&["link", "set", PFCP_NAME, "up"]);

        test(ns);
    });
}
