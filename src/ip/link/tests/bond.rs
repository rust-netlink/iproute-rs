// SPDX-License-Identifier: MIT

use crate::tests::{NetnsGuard, with_netns};

const BOND_NAME: &str = "test-bond";
const DUMMY_NAME: &str = "test-bnd-dummy";

#[test]
fn test_link_detailed_show_bond() {
    with_bond_iface(|ns| {
        ns.assert_eq_output(&["-d", "link", "show", BOND_NAME]);
    });
}

#[test]
fn test_link_detailed_show_json_bond() {
    with_bond_iface(|ns| {
        ns.assert_eq_output(&["-d", "-j", "link", "show", BOND_NAME]);
    });
}

#[test]
fn test_link_detailed_show_bond_port() {
    with_bond_iface(|ns| {
        ns.assert_eq_output(&["-d", "link", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_link_detailed_show_json_bond_port() {
    with_bond_iface(|ns| {
        ns.assert_eq_output(&["-d", "-j", "link", "show", DUMMY_NAME]);
    })
}

#[test]
fn test_link_create_bond_default() {
    with_bond_creation_iface(&[], |ns| {
        ns.assert_eq_output(&["-d", "link", "show", BOND_NAME]);
    });
}

#[test]
fn test_link_create_bond_mode() {
    with_bond_creation_iface(&["mode", "active-backup"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", BOND_NAME]);
        assert!(outputs.expected.contains("mode active-backup"));
    });
}

#[test]
fn test_link_create_bond_miimon() {
    with_bond_creation_iface(&["miimon", "200"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", BOND_NAME]);
        assert!(outputs.expected.contains("miimon 200"));
    });
}

#[test]
fn test_link_create_bond_arp_interval() {
    with_bond_creation_iface(
        &["arp_interval", "500", "arp_validate", "active"],
        |ns| {
            let outputs =
                ns.assert_eq_output(&["-d", "link", "show", BOND_NAME]);
            assert!(outputs.expected.contains("arp_interval 500"));
            assert!(outputs.expected.contains("arp_validate active"));
        },
    );
}

#[test]
fn test_link_create_bond_xmit_hash_policy() {
    with_bond_creation_iface(&["xmit_hash_policy", "layer3+4"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", BOND_NAME]);
        assert!(outputs.expected.contains("xmit_hash_policy layer3+4"));
    });
}

#[test]
fn test_link_create_bond_balance_rr_multiopts() {
    with_bond_creation_iface(
        &[
            "mode",
            "balance-rr",
            "miimon",
            "200",
            "xmit_hash_policy",
            "layer3+4",
            "min_links",
            "2",
            "arp_missed_max",
            "3",
            "num_grat_arp",
            "5",
            "resend_igmp",
            "3",
            "primary_reselect",
            "better",
            "fail_over_mac",
            "active",
        ],
        |ns| {
            let outputs =
                ns.assert_eq_output(&["-d", "link", "show", BOND_NAME]);
            assert!(outputs.expected.contains("mode balance-rr"));
            assert!(outputs.expected.contains("miimon 200"));
            assert!(outputs.expected.contains("xmit_hash_policy layer3+4"));
            assert!(outputs.expected.contains("min_links 2"));
            assert!(outputs.expected.contains("arp_missed_max 3"));
            assert!(outputs.expected.contains("num_grat_arp 5"));
            assert!(outputs.expected.contains("resend_igmp 3"));
            assert!(outputs.expected.contains("primary_reselect better"));
            assert!(outputs.expected.contains("fail_over_mac active"));
        },
    );
}

#[test]
fn test_link_create_bond_802_3ad() {
    with_bond_creation_iface(
        &[
            "mode",
            "802.3ad",
            "ad_select",
            "bandwidth",
            "min_links",
            "2",
        ],
        |ns| {
            let outputs =
                ns.assert_eq_output(&["-d", "link", "show", BOND_NAME]);
            assert!(outputs.expected.contains("mode 802.3ad"));
            assert!(outputs.expected.contains("ad_select bandwidth"));
            assert!(outputs.expected.contains("min_links 2"));
        },
    );
}

fn with_bond_iface<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        ns.exec_cmd(&["ip", "link", "add", DUMMY_NAME, "type", "dummy"]);
        ns.exec_cmd(&["ip", "link", "add", BOND_NAME, "type", "bond"]);
        ns.exec_cmd(&[
            "ip", "link", "set", "dev", DUMMY_NAME, "master", BOND_NAME,
        ]);

        ns.exec_cmd(&["ip", "link", "set", DUMMY_NAME, "up"]);
        ns.exec_cmd(&["ip", "link", "set", BOND_NAME, "up"]);

        test(ns);
    })
}

fn with_bond_creation_iface<T>(opts: &[&str], test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        let mut args = vec!["link", "add", BOND_NAME, "type", "bond"];
        args.extend_from_slice(opts);

        ns.ip_rs_exec_cmd(&args);
        ns.exec_cmd(&["ip", "link", "set", BOND_NAME, "up"]);

        test(ns);
    })
}
