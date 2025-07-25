// SPDX-License-Identifier: MIT

use crate::tests::{exec_cmd, get_ip_cli_path};

#[cfg(test)]
#[ctor::ctor]
fn setup() {
    println!("setup for interfaces for tests");

    // Add vlan over dummy interface
    exec_cmd(&["ip", "link", "add", "link", "dummy0", "type", "dummy"]);
    exec_cmd(&[
        "ip", "link", "add", "link", "dummy0", "name", "dummy0.1", "type",
        "vlan", "id", "1",
    ]);

    exec_cmd(&["ip", "link", "set", "dummy0", "up"]);
    exec_cmd(&["ip", "link", "set", "dummy0.1", "up"]);
}

#[test]
fn test_link_show() {
    let cli_path = get_ip_cli_path();

    let expected_output = exec_cmd(&["ip", "link", "show"]);

    let our_output = exec_cmd(&[cli_path.as_str(), "link", "show"]);

    pretty_assertions::assert_eq!(expected_output, our_output);
}

#[test]
fn test_link_detailed_show() {
    let cli_path = get_ip_cli_path();

    let expected_output = exec_cmd(&["ip", "-d", "link", "show"]);

    let our_output = exec_cmd(&[cli_path.as_str(), "-d", "link", "show"]);

    pretty_assertions::assert_eq!(expected_output, our_output);
}

#[test]
fn test_link_show_json() {
    let cli_path = get_ip_cli_path();

    let expected_output = exec_cmd(&["ip", "-j", "link", "show"]);

    let our_output = exec_cmd(&[cli_path.as_str(), "-j", "link", "show"]);

    pretty_assertions::assert_eq!(expected_output, our_output);
}

#[test]
fn test_link_detailed_show_json() {
    let cli_path = get_ip_cli_path();

    let expected_output = exec_cmd(&["ip", "-d", "-j", "link", "show"]);

    let our_output = exec_cmd(&[cli_path.as_str(), "-d", "-j", "link", "show"]);

    pretty_assertions::assert_eq!(expected_output, our_output);
}
