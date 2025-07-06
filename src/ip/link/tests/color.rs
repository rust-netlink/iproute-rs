// SPDX-License-Identifier: MIT

use crate::tests::{exec_cmd, get_ip_cli_path};

const COLOR_CLEAR: &str = "\x1b[0m";

#[test]
fn test_ip_link_show_color_always() {
    let cli_path = get_ip_cli_path();

    let expected_output = exec_cmd(&["ip", "-c=always", "link", "show"]);

    let our_output =
        exec_cmd(&[cli_path.as_str(), "-c=always", "link", "show"]);

    assert!(our_output.contains(COLOR_CLEAR));

    assert_eq!(expected_output, our_output);
}

#[test]
fn test_ip_link_show_color_auto_without_terminal() {
    let cli_path = get_ip_cli_path();

    let expected_output = exec_cmd(&["ip", "-c=auto", "link", "show"]);

    let our_output = exec_cmd(&[cli_path.as_str(), "-c=auto", "link", "show"]);

    assert!(!our_output.contains(COLOR_CLEAR));

    assert_eq!(expected_output, our_output);
}

#[test]
fn test_ip_link_show_color_never() {
    let cli_path = get_ip_cli_path();

    let expected_output = exec_cmd(&["ip", "-c=never", "link", "show"]);

    let our_output = exec_cmd(&[cli_path.as_str(), "-c=never", "link", "show"]);

    assert!(!our_output.contains(COLOR_CLEAR));

    assert_eq!(expected_output, our_output);
}
