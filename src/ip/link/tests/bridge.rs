// SPDX-License-Identifier: MIT

use crate::tests::{NetnsGuard, with_netns};

const BRIDGE_NAME: &str = "test-br";
const DUMMY_NAME: &str = "test-dummy";

/// Normalize timer values in output to avoid test flakiness
/// Timer values can vary slightly between consecutive calls due to kernel
/// timing
fn normalize_timers(output: String) -> String {
    let timer_names = [
        "hello_timer",
        "tcn_timer",
        "topology_change_timer",
        "gc_timer",
        "hold_timer",
        "message_age_timer",
        "forward_delay_timer",
    ];

    let mut result = output;
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
fn normalize_timers_json(output: String) -> String {
    let timer_names = [
        "hello_timer",
        "tcn_timer",
        "topology_change_timer",
        "gc_timer",
        "hold_timer",
        "message_age_timer",
        "forward_delay_timer",
    ];

    let mut result = output;
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
    with_bridge_iface(|ns| {
        ns.assert_eq_output_map(
            &["-d", "link", "show", BRIDGE_NAME],
            normalize_timers,
        );
    });
}

#[test]
fn test_link_detailed_show_json_bridge() {
    with_bridge_iface(|ns| {
        ns.assert_eq_output_map(
            &["-d", "-j", "link", "show", BRIDGE_NAME],
            normalize_timers_json,
        );
    });
}

#[test]
fn test_link_detailed_show_bridge_port() {
    with_bridge_iface(|ns| {
        ns.assert_eq_output_map(
            &["-d", "link", "show", DUMMY_NAME],
            normalize_timers,
        );
    });
}

#[test]
fn test_link_detailed_show_json_bridge_port() {
    with_bridge_iface(|ns| {
        ns.assert_eq_output_map(
            &["-d", "-j", "link", "show", DUMMY_NAME],
            normalize_timers_json,
        );
    });
}

fn with_bridge_iface<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        ns.exec_cmd(&["ip", "link", "add", DUMMY_NAME, "type", "dummy"]);
        ns.exec_cmd(&[
            "ip",
            "link",
            "add",
            BRIDGE_NAME,
            "type",
            "bridge",
            "stp_state",
            "0",
        ]);
        ns.exec_cmd(&[
            "ip",
            "link",
            "set",
            "dev",
            DUMMY_NAME,
            "master",
            BRIDGE_NAME,
        ]);

        ns.exec_cmd(&["ip", "link", "set", DUMMY_NAME, "up"]);
        ns.exec_cmd(&["ip", "link", "set", BRIDGE_NAME, "up"]);

        test(ns);
    });
}
