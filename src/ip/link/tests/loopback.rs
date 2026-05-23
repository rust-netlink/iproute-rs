// SPDX-License-Identifier: MIT

use crate::tests::with_netns;

#[test]
fn test_link_show_lo() {
    with_netns(|ns| {
        ns.assert_eq_output(&["link", "show", "lo"]);
    });
}

#[test]
fn test_link_show_lo_json() {
    with_netns(|ns| {
        ns.assert_eq_output(&["-j", "link", "show", "lo"]);
    });
}

#[test]
fn test_link_alias_l_l() {
    with_netns(|ns| {
        ns.assert_alias_output(&["link", "show", "lo"], &["l", "l", "lo"]);
    });
}

#[test]
fn test_link_alias_lin_show() {
    with_netns(|ns| {
        ns.assert_alias_output(&["link", "show", "lo"], &["lin", "show", "lo"]);
    });
}

#[test]
fn test_link_alias_link_ls() {
    with_netns(|ns| {
        ns.assert_alias_output(&["link", "show", "lo"], &["link", "ls", "lo"]);
    });
}

#[test]
fn test_link_alias_li_l() {
    with_netns(|ns| {
        ns.assert_alias_output(&["link", "show", "lo"], &["li", "l", "lo"]);
    });
}
