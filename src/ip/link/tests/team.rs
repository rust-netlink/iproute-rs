// SPDX-License-Identifier: MIT

use crate::tests::{NetnsGuard, with_netns};

const TEAM_NAME: &str = "test-team";

#[test]
fn test_link_show_team() {
    with_team_iface(|ns| {
        ns.assert_eq_output(&["link", "show", TEAM_NAME]);
    });
}

#[test]
fn test_link_detailed_show_team() {
    with_team_iface(|ns| {
        ns.assert_eq_output(&["-d", "link", "show", TEAM_NAME]);
    });
}

#[test]
fn test_link_show_team_json() {
    with_team_iface(|ns| {
        ns.assert_eq_output(&["-j", "link", "show", TEAM_NAME]);
    });
}

#[test]
fn test_link_detailed_show_team_json() {
    with_team_iface(|ns| {
        ns.assert_eq_output(&["-d", "-j", "link", "show", TEAM_NAME]);
    });
}

fn with_team_iface<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&["link", "add", TEAM_NAME, "type", "team"]);
        ns.ip_rs_exec_cmd(&["link", "set", TEAM_NAME, "up"]);

        test(ns);
    });
}
