// SPDX-License-Identifier: MIT

use crate::tests::{exec_cmd, get_ip_cli_path};

const TEST_NETNS: &str = "iproute-rs-test";

/// Execute a command inside the test network namespace
fn exec_in_netns(args: &[&str]) -> String {
    let mut full_args = vec!["ip", "netns", "exec", TEST_NETNS];
    full_args.extend_from_slice(args);
    exec_cmd(&full_args)
}

/// Normalize timer values in output to avoid test flakiness
/// Timer values can vary slightly between consecutive calls due to kernel timing
fn normalize_timers(output: &str) -> String {
    let timer_names = [
        "hello_timer",
        "tcn_timer",
        "topology_change_timer",
        "gc_timer",
        "hold_timer",
        "message_age_timer",
        "forward_delay_timer",
    ];

    let mut result = output.to_string();
    for timer_name in timer_names {
        // Find and replace timer values like "gc_timer    0.05" with "gc_timer    0.00"
        let mut new_result = String::new();
        let mut remaining = result.as_str();

        while let Some(pos) = remaining.find(timer_name) {
            new_result.push_str(&remaining[..pos]);
            new_result.push_str(timer_name);

            remaining = &remaining[pos + timer_name.len()..];

            // Skip whitespace
            let whitespace_len =
                remaining.chars().take_while(|c| c.is_whitespace()).count();
            new_result.push_str(&remaining[..whitespace_len]);
            remaining = &remaining[whitespace_len..];

            // Skip the number (format: digits.digits)
            let number_len = remaining
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .count();

            // Replace with 0.00
            new_result.push_str("0.00");
            remaining = &remaining[number_len..];
        }
        new_result.push_str(remaining);
        result = new_result;
    }

    result
}

/// Normalize timer values in JSON output to avoid test flakiness
fn normalize_timers_json(output: &str) -> String {
    let timer_names = [
        "hello_timer",
        "tcn_timer",
        "topology_change_timer",
        "gc_timer",
        "hold_timer",
        "message_age_timer",
        "forward_delay_timer",
    ];

    let mut result = output.to_string();
    for timer_name in timer_names {
        // Find and replace JSON timer values like "\"gc_timer\":5" or "\"gc_timer\":0.05" with "\"gc_timer\":0"
        let search_pattern = format!("\"{}\":", timer_name);
        let mut new_result = String::new();
        let mut remaining = result.as_str();

        while let Some(pos) = remaining.find(&search_pattern) {
            new_result.push_str(&remaining[..pos]);
            new_result.push_str(&search_pattern);

            remaining = &remaining[pos + search_pattern.len()..];

            // Skip the number (can be integer or floating point)
            let number_len = remaining
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .count();

            // Replace with 0
            new_result.push('0');
            remaining = &remaining[number_len..];
        }
        new_result.push_str(remaining);
        result = new_result;
    }

    result
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
    exec_in_netns(&["ip", "link", "add", "dummy0", "type", "dummy"]);
    exec_in_netns(&[
        "ip",
        "link",
        "property",
        "add",
        "dev",
        "dummy0",
        "altname",
        "dmmy-zero",
    ]);
    exec_in_netns(&["ip", "link", "add", "br0", "type", "bridge"]);
    exec_in_netns(&[
        "ip", "link", "add", "link", "dummy0", "name", "dummy0.1", "type",
        "vlan", "id", "1",
    ]);
    exec_in_netns(&["ip", "link", "set", "dev", "dummy0.1", "master", "br0"]);

    exec_in_netns(&["ip", "link", "set", "dummy0", "up"]);
    exec_in_netns(&["ip", "link", "set", "dummy0.1", "up"]);
    exec_in_netns(&["ip", "link", "set", "br0", "up"]);
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

    pretty_assertions::assert_eq!(
        normalize_timers(&expected_output),
        normalize_timers(&our_output)
    );
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

    pretty_assertions::assert_eq!(
        normalize_timers_json(&expected_output),
        normalize_timers_json(&our_output)
    );
}
