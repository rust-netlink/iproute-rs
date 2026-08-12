// SPDX-License-Identifier: MIT

mod common;
use self::common::{NetnsGuard, with_netns};

const IPVLAN_NAME: &str = "tipvln";
const IPVTAP_NAME: &str = "tipvtp";

// ---------------------------------------------------------------------------
// ipvlan tests
// ---------------------------------------------------------------------------

#[test]
fn test_link_show_ipvlan() {
    with_ipvlan_iface(&[], |ns| {
        ns.assert_eq_output(&["link", "show", IPVLAN_NAME]);
    });
}

#[test]
fn test_link_detailed_show_ipvlan() {
    with_ipvlan_iface(&[], |ns| {
        ns.assert_eq_output(&["-d", "link", "show", IPVLAN_NAME]);
    });
}

#[test]
fn test_link_detailed_show_json_ipvlan() {
    with_ipvlan_iface(&[], |ns| {
        ns.assert_eq_output(&["-d", "-j", "link", "show", IPVLAN_NAME]);
    });
}

#[test]
fn test_ipvlan_mode_l2() {
    with_ipvlan_iface(&["mode", "l2"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", IPVLAN_NAME]);
        assert!(outputs.expected.contains("mode l2"));
    });
}

#[test]
fn test_ipvlan_mode_l3() {
    with_ipvlan_iface(&["mode", "l3"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", IPVLAN_NAME]);
        assert!(outputs.expected.contains("mode l3"));
    });
}

#[test]
fn test_ipvlan_mode_l3s() {
    with_ipvlan_iface(&["mode", "l3s"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", IPVLAN_NAME]);
        assert!(outputs.expected.contains("mode l3s"));
    });
}

#[test]
fn test_ipvlan_flag_private() {
    with_ipvlan_iface(&["flag", "private"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", IPVLAN_NAME]);
        assert!(outputs.expected.contains("private"));
    });
}

#[test]
fn test_ipvlan_flag_bridge() {
    with_ipvlan_iface(&["flag", "bridge"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", IPVLAN_NAME]);
        assert!(outputs.expected.contains("bridge"));
    });
}

#[test]
fn test_ipvlan_flag_vepa() {
    with_ipvlan_iface(&["flag", "vepa"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", IPVLAN_NAME]);
        assert!(outputs.expected.contains("vepa"));
    });
}

// ---------------------------------------------------------------------------
// ipvtap tests
// ---------------------------------------------------------------------------

#[test]
fn test_link_show_ipvtap() {
    with_ipvtap_iface(&[], |ns| {
        ns.assert_eq_output(&["link", "show", IPVTAP_NAME]);
    });
}

#[test]
fn test_link_detailed_show_ipvtap() {
    with_ipvtap_iface(&[], |ns| {
        ns.assert_eq_output(&["-d", "link", "show", IPVTAP_NAME]);
    });
}

#[test]
fn test_link_detailed_show_json_ipvtap() {
    with_ipvtap_iface(&[], |ns| {
        ns.assert_eq_output(&["-d", "-j", "link", "show", IPVTAP_NAME]);
    });
}

#[test]
fn test_ipvtap_mode_l3() {
    with_ipvtap_iface(&["mode", "l3"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", IPVTAP_NAME]);
        assert!(outputs.expected.contains("mode l3"));
    });
}

#[test]
fn test_ipvtap_flag_private() {
    with_ipvtap_iface(&["flag", "private"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", IPVTAP_NAME]);
        assert!(outputs.expected.contains("private"));
    });
}

#[test]
fn test_ipvtap_flag_bridge() {
    with_ipvtap_iface(&["flag", "bridge"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", IPVTAP_NAME]);
        assert!(outputs.expected.contains("bridge"));
    });
}

#[test]
fn test_ipvtap_flag_vepa() {
    with_ipvtap_iface(&["flag", "vepa"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", IPVTAP_NAME]);
        assert!(outputs.expected.contains("vepa"));
    });
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn with_ipvlan_iface<T>(opts: &[&str], test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        let parent_name = format!("p{IPVLAN_NAME}");

        ns.ip_rs_exec_cmd(&[
            "link",
            "add",
            &parent_name,
            "address",
            "0e:d1:49:08:27:84",
            "type",
            "dummy",
        ]);
        ns.ip_rs_exec_cmd(&["link", "set", &parent_name, "up"]);

        let mut args = vec![
            "link",
            "add",
            "link",
            &parent_name,
            "name",
            IPVLAN_NAME,
            "type",
            "ipvlan",
        ];
        args.extend_from_slice(opts);

        ns.ip_rs_exec_cmd(&args);
        ns.ip_rs_exec_cmd(&["link", "set", IPVLAN_NAME, "up"]);

        test(ns);
    });
}

fn with_ipvtap_iface<T>(opts: &[&str], test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        let parent_name = format!("p{IPVTAP_NAME}");

        ns.ip_rs_exec_cmd(&[
            "link",
            "add",
            &parent_name,
            "address",
            "0e:d1:49:08:27:84",
            "type",
            "dummy",
        ]);
        ns.ip_rs_exec_cmd(&["link", "set", &parent_name, "up"]);

        let mut args = vec![
            "link",
            "add",
            "link",
            &parent_name,
            "name",
            IPVTAP_NAME,
            "type",
            "ipvtap",
        ];
        args.extend_from_slice(opts);

        ns.ip_rs_exec_cmd(&args);
        ns.ip_rs_exec_cmd(&["link", "set", IPVTAP_NAME, "up"]);

        test(ns);
    });
}
