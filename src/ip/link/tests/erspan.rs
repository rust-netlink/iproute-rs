// SPDX-License-Identifier: MIT

// ERSPAN integration tests. Requires kernel ERSPAN support (ip_gre module).
// ERSPAN v1 with non-zero index may fail on some kernel versions.

use crate::tests::{NetnsGuard, with_netns};

const ERSPAN4_NAME: &str = "test-erspan4";
const ERSPAN6_NAME: &str = "test-erspan6";

#[test]
fn test_link_show_erspan() {
    with_erspan_iface(&[], |ns| {
        ns.assert_eq_output(&["link", "show", ERSPAN4_NAME]);
    });
}

#[test]
fn test_link_detailed_show_erspan() {
    with_erspan_iface(&[], |ns| {
        ns.assert_eq_output(&["-d", "link", "show", ERSPAN4_NAME]);
    });
}

#[test]
fn test_erspan_v2_ingress() {
    with_erspan_iface(
        &[
            "erspan_ver",
            "2",
            "erspan_dir",
            "ingress",
            "erspan_hwid",
            "26",
        ],
        |ns| {
            let outputs =
                ns.assert_eq_output(&["-d", "link", "show", ERSPAN4_NAME]);
            assert!(outputs.expected.contains("erspan_ver 2"));
            assert!(outputs.expected.contains("erspan_dir ingress"));
            assert!(outputs.expected.contains("erspan_hwid 0x1a"));
        },
    );
}

#[test]
fn test_link_show_ip6erspan() {
    with_ip6erspan_iface(&[], |ns| {
        ns.assert_eq_output(&["link", "show", ERSPAN6_NAME]);
    });
}

#[test]
fn test_link_detailed_show_ip6erspan() {
    with_ip6erspan_iface(&[], |ns| {
        ns.assert_eq_output(&["-d", "link", "show", ERSPAN6_NAME]);
    });
}

#[test]
fn test_ip6erspan_v2() {
    with_ip6erspan_iface(
        &[
            "erspan_ver",
            "2",
            "erspan_dir",
            "ingress",
            "erspan_hwid",
            "43",
        ],
        |ns| {
            let outputs =
                ns.assert_eq_output(&["-d", "link", "show", ERSPAN6_NAME]);
            assert!(outputs.expected.contains("erspan_ver 2"));
            assert!(outputs.expected.contains("erspan_dir ingress"));
            assert!(outputs.expected.contains("erspan_hwid 0x2b"));
        },
    );
}

fn with_erspan_iface<T>(opts: &[&str], test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        let parent_name = format!("p{ERSPAN4_NAME}");

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
            ERSPAN4_NAME,
            "type",
            "erspan",
            "remote",
            "10.0.0.1",
        ];

        args.extend_from_slice(opts);

        ns.ip_rs_exec_cmd(&args);
        ns.ip_rs_exec_cmd(&["link", "set", ERSPAN4_NAME, "up"]);

        test(ns);
    });
}

fn with_ip6erspan_iface<T>(opts: &[&str], test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        let parent_name = format!("p{ERSPAN6_NAME}");

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
            ERSPAN6_NAME,
            "type",
            "ip6erspan",
            "remote",
            "::1",
        ];

        args.extend_from_slice(opts);

        ns.ip_rs_exec_cmd(&args);
        ns.ip_rs_exec_cmd(&["link", "set", ERSPAN6_NAME, "up"]);

        test(ns);
    });
}
