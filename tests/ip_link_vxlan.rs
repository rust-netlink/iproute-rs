// SPDX-License-Identifier: MIT

mod common;
use self::common::{NetnsGuard, with_netns};

const VXLAN_NAME: &str = "tvxln";

#[test]
fn test_link_show_vxlan() {
    with_vxlan_iface(&[], |ns| {
        ns.assert_eq_output(&["link", "show", VXLAN_NAME]);
    });
}

#[test]
fn test_link_detailed_show_vxlan() {
    with_vxlan_iface(&[], |ns| {
        ns.assert_eq_output(&["-d", "link", "show", VXLAN_NAME]);
    });
}

#[test]
fn test_vxlan_ttl_inherit() {
    with_vxlan_iface(&["ttl", "inherit"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", VXLAN_NAME]);
        assert!(outputs.expected.contains("ttl inherit"));
    });
}

#[test]
fn test_vxlan_tos_inherit() {
    with_vxlan_iface(&["tos", "inherit"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", VXLAN_NAME]);
        assert!(outputs.expected.contains("tos inherit"));
    });
}

#[test]
fn test_vxlan_df_set() {
    with_vxlan_iface(&["df", "set"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", VXLAN_NAME]);
        assert!(outputs.expected.contains("df set"));
    });
}

#[test]
fn test_vxlan_df_inherit() {
    with_vxlan_iface(&["df", "inherit"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", VXLAN_NAME]);
        assert!(outputs.expected.contains("df inherit"));
    });
}

#[test]
fn test_vxlan_nolearning() {
    with_vxlan_iface(&["nolearning"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", VXLAN_NAME]);
        assert!(outputs.expected.contains("nolearning"));
    });
}

#[test]
fn test_vxlan_noudp_csum() {
    with_vxlan_iface(&["noudpcsum"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", VXLAN_NAME]);
        assert!(outputs.expected.contains("noudp_csum"));
    });
}

#[test]
fn test_vxlan_dstport() {
    with_vxlan_iface(&["dstport", "4789"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", VXLAN_NAME]);
        assert!(outputs.expected.contains("dstport 4789"));
    });
}

#[test]
fn test_vxlan_proxy() {
    with_vxlan_iface(&["proxy"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", VXLAN_NAME]);
        assert!(outputs.expected.contains("proxy"));
    });
}

#[test]
fn test_vxlan_gbp() {
    with_vxlan_iface(&["gbp"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", VXLAN_NAME]);
        assert!(outputs.expected.contains("gbp"));
    });
}

#[test]
fn test_vxlan_ageing() {
    with_vxlan_iface(&["ageing", "600"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", VXLAN_NAME]);
        assert!(outputs.expected.contains("ageing 600"));
    });
}

fn with_vxlan_iface<T>(opts: &[&str], test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        let parent_name = format!("p{VXLAN_NAME}");

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
        ns.ip_rs_exec_cmd(&["link", "set", &parent_name, "up"]);

        let mut args = vec![
            "link",
            "add",
            "link",
            &parent_name,
            "name",
            VXLAN_NAME,
            "type",
            "vxlan",
            "id",
            "100",
        ];

        args.extend_from_slice(opts);

        ns.ip_rs_exec_cmd(&args);
        ns.ip_rs_exec_cmd(&["link", "set", VXLAN_NAME, "up"]);

        test(ns);
    });
}

fn with_vxlan_set_iface<T>(set_args: &[&str], test: T)
where
    T: FnOnce(&NetnsGuard),
{
    // Create a default VXLAN then apply ip link set
    with_vxlan_iface(&[], |ns| {
        let mut args = vec!["link", "set", "dev", VXLAN_NAME, "type", "vxlan"];
        args.extend_from_slice(set_args);
        ns.ip_rs_exec_cmd(&args);
        test(ns);
    });
}

#[test]
fn test_set_vxlan_nolearning() {
    with_vxlan_set_iface(&["nolearning"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", VXLAN_NAME]);
        assert!(outputs.expected.contains("nolearning"));
    });
}

#[test]
fn test_set_vxlan_nolocalbypass() {
    with_vxlan_set_iface(&["nolocalbypass"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", VXLAN_NAME]);
        assert!(outputs.expected.contains("nolocalbypass"));
    });
}

#[test]
fn test_set_vxlan_ttl_value() {
    with_vxlan_set_iface(&["ttl", "100"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", VXLAN_NAME]);
        assert!(outputs.expected.contains("ttl 100"));
    });
}

#[test]
fn test_set_vxlan_tos_inherit() {
    with_vxlan_set_iface(&["tos", "inherit"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", VXLAN_NAME]);
        assert!(outputs.expected.contains("tos inherit"));
    });
}

#[test]
fn test_set_vxlan_ageing() {
    with_vxlan_set_iface(&["ageing", "600"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", VXLAN_NAME]);
        assert!(outputs.expected.contains("ageing 600"));
    });
}
