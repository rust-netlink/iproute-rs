// SPDX-License-Identifier: MIT

mod common;
use self::common::{NetnsGuard, with_netns};

const MACVLAN_NAME: &str = "tmcvln";
const MACVTAP_NAME: &str = "tmcvtp";

// ---------------------------------------------------------------------------
// macvlan tests
// ---------------------------------------------------------------------------

#[test]
fn test_link_show_macvlan() {
    with_macvlan_iface(&[], |ns| {
        ns.assert_eq_output(&["link", "show", MACVLAN_NAME]);
    });
}

#[test]
fn test_link_detailed_show_macvlan() {
    with_macvlan_iface(&[], |ns| {
        ns.assert_eq_output(&["-d", "link", "show", MACVLAN_NAME]);
    });
}

#[test]
fn test_link_detailed_show_json_macvlan() {
    with_macvlan_iface(&[], |ns| {
        ns.assert_eq_output(&["-d", "-j", "link", "show", MACVLAN_NAME]);
    });
}

#[test]
fn test_macvlan_mode_private() {
    with_macvlan_iface(&["mode", "private"], |ns| {
        let outputs =
            ns.assert_eq_output(&["-d", "link", "show", MACVLAN_NAME]);
        assert!(outputs.expected.contains("mode private"));
    });
}

#[test]
fn test_macvlan_mode_vepa() {
    with_macvlan_iface(&["mode", "vepa"], |ns| {
        let outputs =
            ns.assert_eq_output(&["-d", "link", "show", MACVLAN_NAME]);
        assert!(outputs.expected.contains("mode vepa"));
    });
}

#[test]
fn test_macvlan_mode_bridge() {
    with_macvlan_iface(&["mode", "bridge"], |ns| {
        let outputs =
            ns.assert_eq_output(&["-d", "link", "show", MACVLAN_NAME]);
        assert!(outputs.expected.contains("mode bridge"));
    });
}

#[test]
fn test_macvlan_mode_passthru() {
    with_macvlan_iface(&["mode", "passthru"], |ns| {
        let outputs =
            ns.assert_eq_output(&["-d", "link", "show", MACVLAN_NAME]);
        assert!(outputs.expected.contains("mode passthru"));
    });
}

#[test]
fn test_macvlan_mode_source() {
    with_macvlan_iface(&["mode", "source"], |ns| {
        let outputs =
            ns.assert_eq_output(&["-d", "link", "show", MACVLAN_NAME]);
        assert!(outputs.expected.contains("mode source"));
    });
}

#[test]
fn test_macvlan_flag_nodst() {
    with_macvlan_iface(&["mode", "private", "flag", "nodst"], |ns| {
        let outputs =
            ns.assert_eq_output(&["-d", "link", "show", MACVLAN_NAME]);
        assert!(outputs.expected.contains("nodst"));
    });
}

#[test]
fn test_macvlan_passthru_nopromisc() {
    with_macvlan_iface(&["mode", "passthru", "nopromisc"], |ns| {
        let outputs =
            ns.assert_eq_output(&["-d", "link", "show", MACVLAN_NAME]);
        assert!(outputs.expected.contains("nopromisc"));
    });
}

// ---------------------------------------------------------------------------
// macvtap tests
// ---------------------------------------------------------------------------

#[test]
fn test_link_show_macvtap() {
    with_macvtap_iface(&[], |ns| {
        ns.assert_eq_output(&["link", "show", MACVTAP_NAME]);
    });
}

#[test]
fn test_link_detailed_show_macvtap() {
    with_macvtap_iface(&[], |ns| {
        ns.assert_eq_output(&["-d", "link", "show", MACVTAP_NAME]);
    });
}

#[test]
fn test_link_detailed_show_json_macvtap() {
    with_macvtap_iface(&[], |ns| {
        ns.assert_eq_output(&["-d", "-j", "link", "show", MACVTAP_NAME]);
    });
}

#[test]
fn test_macvtap_mode_private() {
    with_macvtap_iface(&["mode", "private"], |ns| {
        let outputs =
            ns.assert_eq_output(&["-d", "link", "show", MACVTAP_NAME]);
        assert!(outputs.expected.contains("mode private"));
    });
}

#[test]
fn test_macvtap_mode_bridge() {
    with_macvtap_iface(&["mode", "bridge"], |ns| {
        let outputs =
            ns.assert_eq_output(&["-d", "link", "show", MACVTAP_NAME]);
        assert!(outputs.expected.contains("mode bridge"));
    });
}

#[test]
fn test_macvtap_flag_nodst() {
    with_macvtap_iface(&["mode", "private", "flag", "nodst"], |ns| {
        let outputs =
            ns.assert_eq_output(&["-d", "link", "show", MACVTAP_NAME]);
        assert!(outputs.expected.contains("nodst"));
    });
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn with_macvlan_iface<T>(opts: &[&str], test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        let parent_name = format!("p{MACVLAN_NAME}");

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
            MACVLAN_NAME,
            "type",
            "macvlan",
        ];
        args.extend_from_slice(opts);

        ns.ip_rs_exec_cmd(&args);
        ns.ip_rs_exec_cmd(&["link", "set", MACVLAN_NAME, "up"]);

        test(ns);
    });
}

fn with_macvtap_iface<T>(opts: &[&str], test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        let parent_name = format!("p{MACVTAP_NAME}");

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
            MACVTAP_NAME,
            "type",
            "macvtap",
        ];
        args.extend_from_slice(opts);

        ns.ip_rs_exec_cmd(&args);
        ns.ip_rs_exec_cmd(&["link", "set", MACVTAP_NAME, "up"]);

        test(ns);
    });
}
