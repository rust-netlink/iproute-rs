// SPDX-License-Identifier: MIT

mod common;
use self::common::{
    DUMMY_NAME, NetnsGuard, with_dummy_iface_empty, with_dummy_iface_static_ip,
    with_netns,
};

const VETH0_NAME: &str = "tshow-veth0";
const VETH1_NAME: &str = "tshow-veth1";

/// Add addresses with and without an `IFA_PROTO` attribute to a dummy
/// interface: only the first address carries the unknown protocol 99.
fn with_protocol_addresses<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_dummy_iface_empty(|ns| {
        ns.exec_cmd(&[
            "ip",
            "address",
            "add",
            "192.0.2.1/24",
            "dev",
            DUMMY_NAME,
            "proto",
            "99",
        ]);
        ns.exec_cmd(&[
            "ip",
            "address",
            "add",
            "192.0.2.2/24",
            "dev",
            DUMMY_NAME,
        ]);
        ns.exec_cmd(&["ip", "address", "add", "fd00::1/64", "dev", DUMMY_NAME]);
        test(ns);
    });
}

/// Add addresses used by the filter tests: the first IPv4 address carries
/// `IFA_PROTO` 99, the second one is a plain primary IPv4 address and the
/// IPv6 address is global. The kernel also adds a link-local IPv6 address
/// with the `kernel_ll` protocol to the interface.
fn with_filter_addresses<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_dummy_iface_empty(|ns| {
        ns.exec_cmd(&[
            "ip",
            "address",
            "add",
            "192.0.2.1/24",
            "dev",
            DUMMY_NAME,
            "proto",
            "99",
        ]);
        ns.exec_cmd(&[
            "ip",
            "address",
            "add",
            "192.0.2.2/24",
            "dev",
            DUMMY_NAME,
        ]);
        ns.exec_cmd(&["ip", "address", "add", "fd00::1/64", "dev", DUMMY_NAME]);
        test(ns);
    });
}

#[test]
fn test_address_show_link_json() {
    with_dummy_iface_empty(|ns| {
        // The link family output carries no `addr_info` key.
        ns.assert_eq_output(&["-j", "-0", "address", "show"]);
        ns.assert_eq_output(&["-j", "-0", "address", "show", DUMMY_NAME]);
        ns.assert_eq_output(&["-j", "-f", "link", "address", "show"]);
    });
}

#[test]
fn test_address_show_empty_addr_info_json() {
    with_dummy_iface_empty(|ns| {
        // An interface without addresses keeps the empty `addr_info` array
        // when no address family is requested.
        ns.assert_eq_output(&["-j", "address", "show", DUMMY_NAME]);
        ns.assert_eq_output(&["-j", "address", "show"]);
    });
}

#[test]
fn test_address_show_metric_json() {
    with_dummy_iface_empty(|ns| {
        // iproute2 prints the `metric` JSON key right after `prefixlen`.
        ns.exec_cmd(&[
            "ip",
            "address",
            "add",
            "192.0.2.1/24",
            "dev",
            DUMMY_NAME,
            "metric",
            "100",
        ]);
        ns.assert_eq_output(&["-j", "address", "show", DUMMY_NAME]);
        ns.assert_eq_output(&["address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_show_filter_rejected_text() {
    with_filter_addresses(|ns| {
        // Rejected addresses are not printed in text mode.
        ns.assert_eq_output(&[
            "address", "show", DUMMY_NAME, "scope", "global",
        ]);
        ns.assert_eq_output(&["address", "show", DUMMY_NAME, "scope", "link"]);
        ns.assert_eq_output(&["address", "show", DUMMY_NAME, "proto", "99"]);
        ns.assert_eq_output(&["address", "show", DUMMY_NAME, "secondary"]);
        ns.assert_eq_output(&[
            "-br", "address", "show", DUMMY_NAME, "scope", "link",
        ]);
    });
}

#[test]
fn test_address_show_filter_rejected_json() {
    with_filter_addresses(|ns| {
        // Each address rejected by a filter is serialized as an empty JSON
        // object of its link.
        ns.assert_eq_output(&[
            "-j", "address", "show", DUMMY_NAME, "scope", "global",
        ]);
        ns.assert_eq_output(&[
            "-j", "address", "show", DUMMY_NAME, "scope", "link",
        ]);
        ns.assert_eq_output(&[
            "-j", "address", "show", DUMMY_NAME, "proto", "99",
        ]);
        // `to` also restricts the family, so the IPv6 addresses are not
        // listed at all.
        ns.assert_eq_output(&[
            "-j",
            "address",
            "show",
            DUMMY_NAME,
            "to",
            "192.0.2.1",
        ]);
        ns.assert_eq_output(&[
            "-j",
            "address",
            "show",
            DUMMY_NAME,
            "secondary",
        ]);
    });
}

#[test]
fn test_address_show_filter_rejected_oneline() {
    with_filter_addresses(|ns| {
        ns.assert_eq_output(&[
            "-j", "-o", "address", "show", DUMMY_NAME, "proto", "99",
        ]);
        ns.assert_eq_output(&[
            "-o", "address", "show", DUMMY_NAME, "proto", "99",
        ]);
        ns.assert_eq_output(&[
            "-o", "address", "show", DUMMY_NAME, "scope", "link",
        ]);
    });
}

#[test]
fn test_address_show_protocol_filter() {
    with_protocol_addresses(|ns| {
        ns.assert_eq_output(&[
            "address", "show", "dev", DUMMY_NAME, "proto", "99",
        ]);
    });
}

#[test]
fn test_address_show_protocol_filter_hex() {
    with_protocol_addresses(|ns| {
        ns.assert_eq_output(&[
            "address", "show", "dev", DUMMY_NAME, "proto", "0x63",
        ]);
    });
}

#[test]
fn test_address_show_oneline() {
    with_dummy_iface_static_ip(|ns| {
        ns.assert_eq_output(&["-o", "address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_show_oneline_all_links() {
    with_dummy_iface_static_ip(|ns| {
        ns.assert_eq_output(&["-o", "address", "show"]);
    });
}

#[test]
fn test_address_show_oneline_interface_without_address() {
    with_dummy_iface_empty(|ns| {
        ns.assert_eq_output(&["-o", "address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_show_oneline_json() {
    with_dummy_iface_static_ip(|ns| {
        ns.assert_eq_output(&["-j", "-o", "address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_show_oneline_json_interface_without_address() {
    with_dummy_iface_empty(|ns| {
        ns.assert_eq_output(&["-j", "-o", "address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_show_stats() {
    with_dummy_iface_static_ip(|ns| {
        ns.assert_eq_output(&["-s", "address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_show_stats_all_links() {
    with_dummy_iface_static_ip(|ns| {
        ns.assert_eq_output(&["-s", "address", "show"]);
    });
}

#[test]
fn test_address_show_stats_detailed() {
    with_dummy_iface_static_ip(|ns| {
        ns.assert_eq_output(&["-s", "-s", "address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_show_stats_json() {
    with_dummy_iface_static_ip(|ns| {
        ns.assert_eq_output(&["-j", "-s", "address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_show_stats_detailed_json() {
    with_dummy_iface_static_ip(|ns| {
        ns.assert_eq_output(&["-j", "-s", "-s", "address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_show_stats_oneline() {
    with_dummy_iface_static_ip(|ns| {
        ns.assert_eq_output(&["-o", "-s", "address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_show_stats_brief() {
    with_dummy_iface_static_ip(|ns| {
        ns.assert_eq_output(&["--brief", "-s", "address", "show", DUMMY_NAME]);
    });
}

fn with_veth_pair<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        ns.exec_cmd(&[
            "ip", "link", "add", VETH0_NAME, "type", "veth", "peer", "name",
            VETH1_NAME,
        ]);
        ns.exec_cmd(&[
            "ip",
            "address",
            "add",
            "192.0.2.1/24",
            "dev",
            VETH0_NAME,
        ]);
        ns.exec_cmd(&["ip", "address", "add", "fd00::1/64", "dev", VETH1_NAME]);
        ns.exec_cmd(&["ip", "link", "set", VETH0_NAME, "up"]);
        ns.exec_cmd(&["ip", "link", "set", VETH1_NAME, "up"]);
        ns.wait_for_ipv6_dad();
        test(ns);
    });
}

#[test]
fn test_address_show_brief_link_suffix() {
    with_veth_pair(|ns| {
        // iproute2 appends the lower link name to the interface name, e.g.
        // `tshow-veth0@tshow-veth1`.
        ns.assert_eq_output(&["-br", "address", "show"]);
    });
}

#[test]
fn test_address_show_family() {
    with_dummy_iface_static_ip(|ns| {
        // The `link/...` line is not printed when an address family is
        // requested, but the rest of the link information is.
        ns.assert_eq_output(&["-4", "address", "show", DUMMY_NAME]);
        ns.assert_eq_output(&["-6", "address", "show", DUMMY_NAME]);
        ns.assert_eq_output(&["-j", "-4", "address", "show", DUMMY_NAME]);
        ns.assert_eq_output(&["-j", "-6", "address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_show_family_details() {
    with_dummy_iface_static_ip(|ns| {
        // `-d` restores the `link/...` line of the family filtered output.
        ns.assert_eq_output(&["-4", "-d", "address", "show", DUMMY_NAME]);
        ns.assert_eq_output(&["-6", "-d", "address", "show", DUMMY_NAME]);
        ns.assert_eq_output(&["-j", "-4", "-d", "address", "show", DUMMY_NAME]);
        ns.assert_eq_output(&["-j", "-6", "-d", "address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_show_filter_scope() {
    with_dummy_iface_static_ip(|ns| {
        // No interface has a host scope address, so iproute2 drops every
        // interface from the output.
        ns.assert_eq_output(&["address", "show", "scope", "host"]);
    });
}

#[test]
fn test_address_show_filter_json_oneline() {
    with_dummy_iface_static_ip(|ns| {
        ns.assert_eq_output(&["-j", "-o", "-4", "address", "show"]);
    });
}

#[test]
fn test_address_show_filter_json_oneline_ipv6() {
    with_dummy_iface_static_ip(|ns| {
        ns.assert_eq_output(&["-j", "-o", "-6", "address", "show"]);
    });
}

#[test]
fn test_address_show_unknown_protocol() {
    with_protocol_addresses(|ns| {
        ns.assert_eq_output(&["address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_show_unknown_protocol_json() {
    with_protocol_addresses(|ns| {
        ns.assert_eq_output(&["-j", "address", "show", DUMMY_NAME]);
    });
}
