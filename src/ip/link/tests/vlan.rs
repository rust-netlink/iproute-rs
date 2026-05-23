// SPDX-License-Identifier: MIT

use crate::tests::{NetnsGuard, with_netns};

const VLAN_NAME: &str = "test-vlan";

#[test]
fn test_link_show_vlan() {
    with_vlan_iface(&[], |ns| {
        ns.assert_eq_output(&["link", "show", VLAN_NAME]);
    });
}

#[test]
fn test_link_detailed_show_vlan() {
    with_vlan_iface(&[], |ns| {
        ns.assert_eq_output(&["-d", "link", "show", VLAN_NAME]);
    });
}

#[test]
fn test_vlan_protocol() {
    with_vlan_iface(&["protocol", "802.1ad"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", VLAN_NAME]);
        assert!(outputs.expected.contains("protocol 802.1ad"));
    });
}

#[test]
fn test_vlan_reorder_hdr_on() {
    with_vlan_iface(&["reorder_hdr", "on"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", VLAN_NAME]);
        assert!(outputs.expected.contains("REORDER_HDR"));
    });
}

#[test]
fn test_vlan_reorder_hdr_off() {
    with_vlan_iface(&["reorder_hdr", "off"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", VLAN_NAME]);
        assert!(!outputs.expected.contains("REORDER_HDR"));
    });
}

#[test]
fn test_vlan_gvrp_on() {
    with_vlan_iface(&["gvrp", "on"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", VLAN_NAME]);
        assert!(outputs.expected.contains("GVRP"));
    });
}

#[test]
fn test_vlan_gvrp_off() {
    with_vlan_iface(&["gvrp", "off"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", VLAN_NAME]);
        assert!(!outputs.expected.contains("GVRP"));
    });
}

#[test]
fn test_vlan_mvrp_on() {
    with_vlan_iface(&["mvrp", "on"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", VLAN_NAME]);
        assert!(outputs.expected.contains("MVRP"));
    });
}

#[test]
fn test_vlan_mvrp_off() {
    with_vlan_iface(&["mvrp", "off"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", VLAN_NAME]);
        assert!(!outputs.expected.contains("MVRP"));
    });
}

#[test]
fn test_vlan_loose_binding_on() {
    with_vlan_iface(&["loose_binding", "on"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", VLAN_NAME]);
        assert!(outputs.expected.contains("LOOSE_BINDING"));
    });
}

#[test]
fn test_vlan_loose_binding_off() {
    with_vlan_iface(&["loose_binding", "off"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", VLAN_NAME]);
        assert!(!outputs.expected.contains("LOOSE_BINDING"));
    });
}

#[test]
fn test_vlan_bridge_binding_on() {
    with_vlan_iface(&["bridge_binding", "on"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", VLAN_NAME]);
        assert!(outputs.expected.contains("BRIDGE_BINDING"));
    });
}

#[test]
fn test_vlan_bridge_binding_off() {
    with_vlan_iface(&["bridge_binding", "off"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", VLAN_NAME]);
        assert!(!outputs.expected.contains("BRIDGE_BINDING"));
    });
}

#[test]
fn test_vlan_all_flags_on() {
    with_vlan_iface(
        &[
            "protocol",
            "802.1ad",
            "reorder_hdr",
            "on",
            "gvrp",
            "on",
            "loose_binding",
            "on",
            "bridge_binding",
            "on",
        ],
        |ns| {
            let outputs =
                ns.assert_eq_output(&["-d", "link", "show", VLAN_NAME]);

            assert!(outputs.expected.contains("protocol 802.1ad"));
            assert!(outputs.expected.contains("REORDER_HDR"));
            assert!(outputs.expected.contains("GVRP"));
            assert!(outputs.expected.contains("LOOSE_BINDING"));
            assert!(outputs.expected.contains("BRIDGE_BINDING"));
        },
    );
}

fn with_vlan_iface<T>(opts: &[&str], test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        let parent_name = format!("p{VLAN_NAME}");

        // create parent dummy interface using ip-rs
        ns.ip_rs_exec_cmd(&[
            "link",
            "add",
            &parent_name,
            "address",
            "0e:d1:49:08:27:84",
            "type",
            "dummy",
        ]);
        ns.exec_cmd(&["ip", "link", "set", &parent_name, "up"]);

        let mut args = vec![
            "link",
            "add",
            "link",
            &parent_name,
            "name",
            VLAN_NAME,
            "type",
            "vlan",
            "id",
            "100",
        ];

        args.extend_from_slice(opts);

        ns.ip_rs_exec_cmd(&args);
        ns.exec_cmd(&["ip", "link", "set", VLAN_NAME, "up"]);

        test(ns);
    });
}
