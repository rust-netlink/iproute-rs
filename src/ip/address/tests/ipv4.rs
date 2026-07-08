// SPDX-License-Identifier: MIT

use super::address::with_dummy_iface_empty;

const DUMMY_NAME: &str = "test-dummy";

fn strip_metric(output: String) -> String {
    output
        .lines()
        .map(|line| {
            let mut result = String::new();
            let mut words = line.split_whitespace();
            while let Some(word) = words.next() {
                if word == "metric" {
                    words.next();
                    continue;
                }
                if !result.is_empty() {
                    result.push(' ');
                }
                result.push_str(word);
            }
            result
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn test_address_add_simple_ipv4() {
    with_dummy_iface_empty(|ns| {
        ns.ip_rs_exec_cmd(&["address", "add", "10.0.0.1/24", "dev", DUMMY_NAME]);
        ns.assert_eq_output(&["address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_add_ipv4_with_label() {
    with_dummy_iface_empty(|ns| {
        ns.ip_rs_exec_cmd(&[
            "address", "add", "10.0.0.1/24", "dev", DUMMY_NAME, "label",
            "test-label",
        ]);
        ns.assert_eq_output(&["address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_add_ipv4_with_all_options() {
    with_dummy_iface_empty(|ns| {
        ns.ip_rs_exec_cmd(&[
            "address",
            "add",
            "10.0.0.1/24",
            "dev",
            DUMMY_NAME,
            "valid_lft",
            "21384",
            "preferred_lft",
            "21384",
            "scope",
            "global",
            "mngtmpaddr",
            "proto",
            "kernel_ra",
        ]);
        ns.assert_eq_output(&["address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_add_noprefixroute_flag() {
    with_dummy_iface_empty(|ns| {
        ns.ip_rs_exec_cmd(&[
            "address", "add", "10.0.0.1/24", "dev", DUMMY_NAME,
            "noprefixroute",
        ]);
        ns.assert_eq_output(&["address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_add_with_scope_link() {
    with_dummy_iface_empty(|ns| {
        ns.ip_rs_exec_cmd(&[
            "address", "add", "169.254.0.1/16", "dev", DUMMY_NAME, "scope",
            "link",
        ]);
        ns.assert_eq_output(&["address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_add_metric() {
    with_dummy_iface_empty(|ns| {
        ns.ip_rs_exec_cmd(&[
            "address", "add", "10.0.0.1/24", "dev", DUMMY_NAME, "metric", "42",
        ]);
        ns.assert_eq_output_map(&["address", "show", DUMMY_NAME], strip_metric);
    });
}

#[test]
fn test_address_add_priority_alias() {
    with_dummy_iface_empty(|ns| {
        ns.ip_rs_exec_cmd(&[
            "address", "add", "10.0.0.2/24", "dev", DUMMY_NAME, "priority",
            "100",
        ]);
        ns.assert_eq_output_map(&["address", "show", DUMMY_NAME], strip_metric);
    });
}

#[test]
fn test_address_add_preference_alias() {
    with_dummy_iface_empty(|ns| {
        ns.ip_rs_exec_cmd(&[
            "address", "add", "10.0.0.3/24", "dev", DUMMY_NAME, "preference",
            "200",
        ]);
        ns.assert_eq_output_map(&["address", "show", DUMMY_NAME], strip_metric);
    });
}

#[test]
fn test_address_add_peer() {
    with_dummy_iface_empty(|ns| {
        ns.ip_rs_exec_cmd(&[
            "address", "add", "10.0.0.1/24", "peer", "10.0.0.2", "dev",
            DUMMY_NAME,
        ]);
    });
}

#[test]
fn test_address_add_peer_remote_alias() {
    with_dummy_iface_empty(|ns| {
        ns.ip_rs_exec_cmd(&[
            "address", "add", "10.0.0.3/24", "remote", "10.0.0.4", "dev",
            DUMMY_NAME,
        ]);
    });
}

#[test]
fn test_address_add_multiple_options_combined() {
    with_dummy_iface_empty(|ns| {
        ns.ip_rs_exec_cmd(&[
            "address",
            "add",
            "10.0.0.1/24",
            "dev",
            DUMMY_NAME,
            "broadcast",
            "10.0.0.255",
            "metric",
            "50",
            "scope",
            "global",
            "proto",
            "kernel_ra",
            "noprefixroute",
        ]);
        ns.assert_eq_output_map(&["address", "show", DUMMY_NAME], strip_metric);
    });
}

#[test]
fn test_address_add_local_keyword() {
    with_dummy_iface_empty(|ns| {
        ns.ip_rs_exec_cmd(&[
            "address", "add", "local", "10.0.0.1/24", "dev", DUMMY_NAME,
        ]);
        ns.assert_eq_output(&["address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_add_without_prefix_v4() {
    with_dummy_iface_empty(|ns| {
        ns.ip_rs_exec_cmd(&["address", "add", "10.0.0.1", "dev", DUMMY_NAME]);
        ns.assert_eq_output(&["address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_add_broadcast_plus() {
    with_dummy_iface_empty(|ns| {
        ns.ip_rs_exec_cmd(&[
            "address", "add", "10.0.0.0/24", "dev", DUMMY_NAME, "broadcast",
            "+",
        ]);
        ns.assert_eq_output(&["address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_add_broadcast_minus() {
    with_dummy_iface_empty(|ns| {
        ns.ip_rs_exec_cmd(&[
            "address", "add", "10.0.0.0/24", "dev", DUMMY_NAME, "broadcast",
            "-",
        ]);
        ns.assert_eq_output(&["address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_add_explicit_broadcast() {
    with_dummy_iface_empty(|ns| {
        ns.ip_rs_exec_cmd(&[
            "address", "add", "10.0.0.1/24", "dev", DUMMY_NAME, "brd",
            "10.0.0.255",
        ]);
        ns.assert_eq_output(&["address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_change_scope() {
    with_dummy_iface_empty(|ns| {
        ns.exec_cmd(&["ip", "addr", "add", "10.0.0.1/24", "dev", DUMMY_NAME]);
        ns.ip_rs_exec_cmd(&[
            "address", "change", "10.0.0.1/24", "dev", DUMMY_NAME, "scope",
            "host",
        ]);
        ns.assert_eq_output(&["address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_change_chg_alias() {
    with_dummy_iface_empty(|ns| {
        ns.exec_cmd(&["ip", "addr", "add", "10.0.0.2/24", "dev", DUMMY_NAME]);
        ns.ip_rs_exec_cmd(&[
            "address", "chg", "10.0.0.2/24", "dev", DUMMY_NAME, "scope",
            "host",
        ]);
        ns.assert_eq_output(&["address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_change_label() {
    with_dummy_iface_empty(|ns| {
        ns.exec_cmd(&["ip", "addr", "add", "10.0.0.3/24", "dev", DUMMY_NAME]);
        ns.ip_rs_exec_cmd(&[
            "address", "change", "10.0.0.3/24", "dev", DUMMY_NAME, "label",
            "changed-label",
        ]);
        ns.assert_eq_output(&["address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_replace_create_new() {
    with_dummy_iface_empty(|ns| {
        ns.ip_rs_exec_cmd(&[
            "address", "replace", "10.0.0.1/24", "dev", DUMMY_NAME,
        ]);
        ns.assert_eq_output(&["address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_replace_modify_existing() {
    with_dummy_iface_empty(|ns| {
        ns.exec_cmd(&["ip", "addr", "add", "10.0.0.1/24", "dev", DUMMY_NAME]);
        ns.ip_rs_exec_cmd(&[
            "address",
            "replace",
            "10.0.0.1/24",
            "dev",
            DUMMY_NAME,
            "scope",
            "host",
            "noprefixroute",
        ]);
        ns.assert_eq_output(&["address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_delete() {
    with_dummy_iface_empty(|ns| {
        ns.exec_cmd(&["ip", "addr", "add", "10.0.0.1/24", "dev", DUMMY_NAME]);
        ns.ip_rs_exec_cmd(&[
            "address", "delete", "10.0.0.1/24", "dev", DUMMY_NAME,
        ]);
        ns.assert_eq_output(&["address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_delete_del_alias() {
    with_dummy_iface_empty(|ns| {
        ns.exec_cmd(&["ip", "addr", "add", "10.0.0.2/24", "dev", DUMMY_NAME]);
        ns.ip_rs_exec_cmd(&["address", "del", "10.0.0.2/24", "dev", DUMMY_NAME]);
        ns.assert_eq_output(&["address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_delete_d_alias() {
    with_dummy_iface_empty(|ns| {
        ns.exec_cmd(&["ip", "addr", "add", "10.0.0.3/24", "dev", DUMMY_NAME]);
        ns.ip_rs_exec_cmd(&["address", "d", "10.0.0.3/24", "dev", DUMMY_NAME]);
        ns.assert_eq_output(&["address", "show", DUMMY_NAME]);
    });
}
