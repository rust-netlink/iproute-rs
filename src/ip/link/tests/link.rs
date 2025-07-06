// SPDX-License-Identifier: Apache-2.0

use crate::tests::{exec_cmd, get_ip_cli_path};

#[test]
fn test_link_show() {
    let cli_path = get_ip_cli_path();

    let expected_output = exec_cmd(&["ip", "link", "show"]);

    let our_output = exec_cmd(&[cli_path.as_str(), "link", "show"]);

    pretty_assertions::assert_eq!(expected_output, our_output);
}

#[test]
fn test_link_show_json() {
    let cli_path = get_ip_cli_path();

    let expected_output = exec_cmd(&["ip", "-j", "link", "show"]);

    let our_output = exec_cmd(&[cli_path.as_str(), "-j", "link", "show"]);

    pretty_assertions::assert_eq!(expected_output, our_output);
}
