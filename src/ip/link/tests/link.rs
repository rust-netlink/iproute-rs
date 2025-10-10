// SPDX-License-Identifier: MIT

use crate::tests::{exec_cmd, get_ip_cli_path};

const TEST_NETNS: &str = "iproute-rs-test";

/// Execute a command inside the test network namespace
fn exec_in_netns(args: &[&str]) -> String {
    let mut full_args = vec!["ip", "netns", "exec", TEST_NETNS];
    full_args.extend_from_slice(args);
    exec_cmd(&full_args)
}

#[cfg(test)]
#[ctor::ctor]
fn setup() {
    println!("setup network namespace and interfaces for tests");

    // Create network namespace (delete first if it exists)
    let netns_list = exec_cmd(&["ip", "netns", "list"]);
    if netns_list.contains(TEST_NETNS) {
        exec_cmd(&["ip", "netns", "del", TEST_NETNS]);
    }
    exec_cmd(&["ip", "netns", "add", TEST_NETNS]);

    // Add vlan over dummy interface
    exec_in_netns(&["ip", "link", "add", "link", "dummy0", "type", "dummy"]);
    exec_in_netns(&[
        "ip", "link", "add", "link", "dummy0", "name", "dummy0.1", "type",
        "vlan", "id", "1",
    ]);

    exec_in_netns(&["ip", "link", "set", "dummy0", "up"]);
    exec_in_netns(&["ip", "link", "set", "dummy0.1", "up"]);
}

#[cfg(test)]
#[ctor::dtor]
fn teardown() {
    println!("teardown network namespace for tests");

    // Delete network namespace
    exec_cmd(&["ip", "netns", "del", TEST_NETNS]);
}

#[test]
fn test_link_show() {
    let cli_path = get_ip_cli_path();

    let expected_output = exec_in_netns(&["ip", "link", "show"]);

    let our_output = exec_in_netns(&[cli_path.as_str(), "link", "show"]);

    pretty_assertions::assert_eq!(expected_output, our_output);
}

#[test]
fn test_link_detailed_show() {
    let cli_path = get_ip_cli_path();

    let expected_output = exec_in_netns(&["ip", "-d", "link", "show"]);

    let our_output = exec_in_netns(&[cli_path.as_str(), "-d", "link", "show"]);

    pretty_assertions::assert_eq!(expected_output, our_output);
}

#[test]
fn test_link_show_json() {
    let cli_path = get_ip_cli_path();

    let expected_output = exec_in_netns(&["ip", "-j", "link", "show"]);

    let our_output = exec_in_netns(&[cli_path.as_str(), "-j", "link", "show"]);

    pretty_assertions::assert_eq!(expected_output, our_output);
}

#[test]
fn test_link_detailed_show_json() {
    let cli_path = get_ip_cli_path();

    let expected_output = exec_in_netns(&["ip", "-d", "-j", "link", "show"]);

    let our_output =
        exec_in_netns(&[cli_path.as_str(), "-d", "-j", "link", "show"]);

    pretty_assertions::assert_eq!(expected_output, our_output);
}
