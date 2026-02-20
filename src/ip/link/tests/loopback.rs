// SPDX-License-Identifier: MIT

use crate::tests::{exec_cmd, ip_rs_exec_cmd};

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
