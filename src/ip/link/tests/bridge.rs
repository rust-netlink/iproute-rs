// SPDX-License-Identifier: MIT

use crate::tests::{NetnsGuard, with_netns};

/// Normalize timer values in output to avoid test flakiness
/// Timer values can vary slightly between consecutive calls due to kernel
/// timing
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
        // Find and replace timer values like "gc_timer    0.05" with "gc_timer
        // 0.00"
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
        // Find and replace JSON timer values like "\"gc_timer\":5" or
        // "\"gc_timer\":0.05" with "\"gc_timer\":0"
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

#[test]
fn test_link_detailed_show_bridge() {
    with_netns(|ns| {
        let br_name = "test-br0";
        let dummy_name = "test-dummy0";

        with_bridge_iface(ns, br_name, dummy_name, || {
            let expected_output =
                ns.exec_cmd(&["ip", "-d", "link", "show", br_name]);
            let our_output =
                ns.ip_rs_exec_cmd(&["-d", "link", "show", br_name]);
            pretty_assertions::assert_eq!(
                normalize_timers(&expected_output),
                normalize_timers(&our_output)
            );
        })
    })
}

#[test]
fn test_link_detailed_show_json_bridge() {
    with_netns(|ns| {
        let br_name = "test-br1";
        let dummy_name = "test-dummy1";
        with_bridge_iface(ns, br_name, dummy_name, || {
            let expected_output =
                ns.exec_cmd(&["ip", "-d", "-j", "link", "show", br_name]);
            let our_output =
                ns.ip_rs_exec_cmd(&["-d", "-j", "link", "show", br_name]);
            pretty_assertions::assert_eq!(
                normalize_timers_json(&expected_output),
                normalize_timers_json(&our_output)
            );
        })
    })
}

#[test]
fn test_link_detailed_show_bridge_port() {
    with_netns(|ns| {
        let br_name = "test-br2";
        let dummy_name = "test-dummy2";

        with_bridge_iface(ns, br_name, dummy_name, || {
            let expected_output =
                ns.exec_cmd(&["ip", "-d", "link", "show", dummy_name]);
            let our_output =
                ns.ip_rs_exec_cmd(&["-d", "link", "show", dummy_name]);
            pretty_assertions::assert_eq!(
                normalize_timers(&expected_output),
                normalize_timers(&our_output)
            );
        })
    })
}

#[test]
fn test_link_detailed_show_json_bridge_port() {
    with_netns(|ns| {
        let br_name = "test-br3";
        let dummy_name = "test-dummy3";
        with_bridge_iface(ns, br_name, dummy_name, || {
            let expected_output =
                ns.exec_cmd(&["ip", "-d", "-j", "link", "show", dummy_name]);
            let our_output =
                ns.ip_rs_exec_cmd(&["-d", "-j", "link", "show", dummy_name]);
            pretty_assertions::assert_eq!(
                normalize_timers_json(&expected_output),
                normalize_timers_json(&our_output)
            );
        })
    })
}

fn with_bridge_iface<T>(
    ns: &NetnsGuard,
    br_name: &str,
    dummy_name: &str,
    test: T,
) where
    T: FnOnce(),
{
    ns.exec_cmd(&["ip", "link", "add", dummy_name, "type", "dummy"]);
    ns.exec_cmd(&[
        "ip",
        "link",
        "add",
        br_name,
        "type",
        "bridge",
        "stp_state",
        "0",
    ]);
    ns.exec_cmd(&["ip", "link", "set", "dev", dummy_name, "master", br_name]);

    ns.exec_cmd(&["ip", "link", "set", dummy_name, "up"]);
    ns.exec_cmd(&["ip", "link", "set", br_name, "up"]);

    test();
}
