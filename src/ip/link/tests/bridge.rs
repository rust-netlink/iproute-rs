// SPDX-License-Identifier: MIT

use crate::tests::{NetnsGuard, with_netns};

const BRIDGE_NAME: &str = "test-br";
const BRIDGE_NAME2: &str = "test-br2";
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

#[test]
fn test_bridge_create_default() {
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&["link", "add", BRIDGE_NAME2, "type", "bridge"]);
        ns.exec_cmd(&["ip", "link", "set", BRIDGE_NAME2, "up"]);

        ns.assert_eq_output_map(
            &["-d", "link", "show", BRIDGE_NAME2],
            normalize_timers,
        );
    });
}

#[test]
fn test_bridge_create_stp_state() {
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link",
            "add",
            BRIDGE_NAME2,
            "type",
            "bridge",
            "stp_state",
            "1",
        ]);
        ns.exec_cmd(&["ip", "link", "set", BRIDGE_NAME2, "up"]);

        let outputs = ns.assert_eq_output_map(
            &["-d", "link", "show", BRIDGE_NAME2],
            normalize_timers,
        );
        assert!(outputs.expected.contains("stp_state 1"));
        assert!(!outputs.expected.contains("stp_state 0"));
    });
}

#[test]
fn test_bridge_create_vlan_filtering() {
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link",
            "add",
            BRIDGE_NAME2,
            "type",
            "bridge",
            "vlan_filtering",
            "1",
        ]);
        ns.exec_cmd(&["ip", "link", "set", BRIDGE_NAME2, "up"]);

        let outputs = ns.assert_eq_output_map(
            &["-d", "link", "show", BRIDGE_NAME2],
            normalize_timers,
        );
        assert!(outputs.expected.contains("vlan_filtering 1"));
        assert!(!outputs.expected.contains("vlan_filtering 0"));
    });
}

#[test]
fn test_bridge_create_vlan_filtering_off() {
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link",
            "add",
            BRIDGE_NAME2,
            "type",
            "bridge",
            "vlan_filtering",
            "off",
        ]);
        ns.exec_cmd(&["ip", "link", "set", BRIDGE_NAME2, "up"]);

        let outputs = ns.assert_eq_output_map(
            &["-d", "link", "show", BRIDGE_NAME2],
            normalize_timers,
        );
        assert!(outputs.expected.contains("vlan_filtering 0"));
        assert!(!outputs.expected.contains("vlan_filtering 1"));
    });
}

#[test]
fn test_bridge_create_forward_delay() {
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link",
            "add",
            BRIDGE_NAME2,
            "type",
            "bridge",
            "forward_delay",
            "2000",
        ]);
        ns.exec_cmd(&["ip", "link", "set", BRIDGE_NAME2, "up"]);

        let outputs = ns.assert_eq_output_map(
            &["-d", "link", "show", BRIDGE_NAME2],
            normalize_timers,
        );
        assert!(outputs.expected.contains("forward_delay 2000"));
    });
}

#[test]
fn test_bridge_create_priority() {
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link",
            "add",
            BRIDGE_NAME2,
            "type",
            "bridge",
            "priority",
            "32768",
        ]);
        ns.exec_cmd(&["ip", "link", "set", BRIDGE_NAME2, "up"]);

        let outputs = ns.assert_eq_output_map(
            &["-d", "link", "show", BRIDGE_NAME2],
            normalize_timers,
        );
        assert!(outputs.expected.contains("priority 32768"));
    });
}

#[test]
fn test_bridge_create_mcast_snooping() {
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link",
            "add",
            BRIDGE_NAME2,
            "type",
            "bridge",
            "mcast_snooping",
            "0",
        ]);
        ns.exec_cmd(&["ip", "link", "set", BRIDGE_NAME2, "up"]);

        let outputs = ns.assert_eq_output_map(
            &["-d", "link", "show", BRIDGE_NAME2],
            normalize_timers,
        );
        assert!(outputs.expected.contains("mcast_snooping 0"));
        assert!(!outputs.expected.contains("mcast_snooping 1"));
    });
}

#[test]
fn test_bridge_create_mcast_querier() {
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link",
            "add",
            BRIDGE_NAME2,
            "type",
            "bridge",
            "mcast_querier",
            "on",
        ]);
        ns.exec_cmd(&["ip", "link", "set", BRIDGE_NAME2, "up"]);

        let outputs = ns.assert_eq_output_map(
            &["-d", "link", "show", BRIDGE_NAME2],
            normalize_timers,
        );
        assert!(outputs.expected.contains("mcast_querier 1"));

        // MulticastQuerierState rendering: field names and ordering must
        // match iproute2 exactly (position between mcast_querier and
        // mcast_hash_elasticity).
        assert!(outputs.expected.contains(
            "mcast_querier 1 mcast_querier_ipv4_addr 0.0.0.0 \
             mcast_querier_ipv6_addr :: mcast_hash_elasticity 16"
        ));
    });
}

#[test]
fn test_bridge_create_group_fwd_mask() {
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link",
            "add",
            BRIDGE_NAME2,
            "type",
            "bridge",
            "group_fwd_mask",
            "16384",
        ]);
        ns.exec_cmd(&["ip", "link", "set", BRIDGE_NAME2, "up"]);

        let outputs = ns.assert_eq_output_map(
            &["-d", "link", "show", BRIDGE_NAME2],
            normalize_timers,
        );
        assert!(outputs.expected.contains("group_fwd_mask 0x4000"));
    });
}

#[test]
fn test_bridge_create_nf_call_iptables() {
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link",
            "add",
            BRIDGE_NAME2,
            "type",
            "bridge",
            "nf_call_iptables",
            "1",
        ]);
        ns.exec_cmd(&["ip", "link", "set", BRIDGE_NAME2, "up"]);

        let outputs = ns.assert_eq_output_map(
            &["-d", "link", "show", BRIDGE_NAME2],
            normalize_timers,
        );
        assert!(outputs.expected.contains("nf_call_iptables 1"));
    });
}

#[test]
fn test_bridge_create_multiple_options() {
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link",
            "add",
            BRIDGE_NAME2,
            "type",
            "bridge",
            "stp_state",
            "1",
            "forward_delay",
            "2500",
            "hello_time",
            "300",
            "max_age",
            "2500",
            "ageing_time",
            "12345",
            "priority",
            "16384",
            "vlan_filtering",
            "on",
            "vlan_default_pvid",
            "100",
            "group_fwd_mask",
            "16384",
            "mcast_snooping",
            "0",
            "mcast_querier",
            "1",
            "nf_call_iptables",
            "on",
            "nf_call_ip6tables",
            "on",
        ]);
        ns.exec_cmd(&["ip", "link", "set", BRIDGE_NAME2, "up"]);

        let outputs = ns.assert_eq_output_map(
            &["-d", "link", "show", BRIDGE_NAME2],
            normalize_timers,
        );
        assert!(outputs.expected.contains("stp_state 1"));
        assert!(outputs.expected.contains("forward_delay 2500"));
        assert!(outputs.expected.contains("hello_time 300"));
        assert!(outputs.expected.contains("max_age 2500"));
        assert!(outputs.expected.contains("ageing_time 12345"));
        assert!(outputs.expected.contains("priority 16384"));
        assert!(outputs.expected.contains("vlan_filtering 1"));
        assert!(outputs.expected.contains("vlan_default_pvid 100"));
        assert!(outputs.expected.contains("group_fwd_mask 0x4000"));
        assert!(outputs.expected.contains("mcast_snooping 0"));
        assert!(outputs.expected.contains("mcast_querier 1"));
        assert!(outputs.expected.contains("nf_call_iptables 1"));
        assert!(outputs.expected.contains("nf_call_ip6tables 1"));
    });
}
