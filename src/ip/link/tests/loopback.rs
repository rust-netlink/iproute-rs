// SPDX-License-Identifier: MIT

use crate::tests::{assert_alias_output, exec_cmd, ip_rs_exec_cmd};

#[test]
fn test_link_show_lo() {
    let expected_output = exec_cmd(&["ip", "link", "show", "lo"]);

    let our_output = ip_rs_exec_cmd(&["link", "show", "lo"]);

    pretty_assertions::assert_eq!(expected_output, our_output);
}

#[test]
fn test_link_show_lo_json() {
    let expected_output = exec_cmd(&["ip", "-j", "link", "show", "lo"]);

    let our_output = ip_rs_exec_cmd(&["-j", "link", "show", "lo"]);

    pretty_assertions::assert_eq!(expected_output, our_output);
}

#[test]
fn test_link_alias_l_l() {
    assert_alias_output(&["link", "show", "lo"], &["l", "l", "lo"]);
}

#[test]
fn test_link_alias_lin_show() {
    assert_alias_output(&["link", "show", "lo"], &["lin", "show", "lo"]);
}

#[test]
fn test_link_alias_link_ls() {
    assert_alias_output(&["link", "show", "lo"], &["link", "ls", "lo"]);
}

#[test]
fn test_link_alias_li_l() {
    assert_alias_output(&["link", "show", "lo"], &["li", "l", "lo"]);
}
