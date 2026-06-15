// SPDX-License-Identifier: MIT

use crate::tests::{NetnsGuard, with_netns};

const GRE_NAME: &str = "test-gre";

#[test]
fn test_link_show_gre() {
    with_gre_iface(&[], |ns| {
        ns.assert_eq_output(&["link", "show", GRE_NAME]);
    });
}

#[test]
fn test_link_detailed_show_gre() {
    with_gre_iface(&[], |ns| {
        ns.assert_eq_output(&["-d", "link", "show", GRE_NAME]);
    });
}

#[test]
fn test_gre_ttl_inherit() {
    with_gre_iface(&["ttl", "inherit"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", GRE_NAME]);
        assert!(outputs.expected.contains("ttl inherit"));
    });
}

#[test]
fn test_gre_tos_inherit() {
    with_gre_iface(&["tos", "inherit"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", GRE_NAME]);
        assert!(outputs.expected.contains("tos inherit"));
    });
}

#[test]
fn test_gre_key() {
    with_gre_iface(&["key", "42"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", GRE_NAME]);
        assert!(outputs.expected.contains("ikey 0.0.0.42"));
        assert!(outputs.expected.contains("okey 0.0.0.42"));
    });
}

#[test]
fn test_gre_fwmark() {
    with_gre_iface(&["fwmark", "0x1234"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", GRE_NAME]);
        assert!(outputs.expected.contains("fwmark 0x1234"));
    });
}

fn with_gre_iface<T>(opts: &[&str], test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        let parent_name = format!("p{GRE_NAME}");

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
            GRE_NAME,
            "type",
            "gre",
            "remote",
            "10.0.0.1",
        ];

        args.extend_from_slice(opts);

        ns.ip_rs_exec_cmd(&args);
        ns.exec_cmd(&["ip", "link", "set", GRE_NAME, "up"]);

        test(ns);
    });
}
