// SPDX-License-Identifier: MIT

use crate::tests::{NetnsGuard, with_netns};

const IPIP_NAME: &str = "tdmy-ipip0";

/// Creating an ipip tunnel without explicit local/remote fails with
/// "File exists" because the kernel creates a default `tunl0` device
/// with those default parameters. All ipip test cases must specify at
/// least `local` and `remote`, or use `external`.

#[test]
fn test_ipip_create_and_show_with_local_remote() {
    with_ipip_iface(&["local", "192.168.1.1", "remote", "10.0.0.1"], |ns| {
        ns.assert_eq_output(&["-d", "link", "show", IPIP_NAME]);
    });
}

#[test]
fn test_ipip_create_and_show_with_ttl_tos() {
    with_ipip_iface(
        &[
            "local",
            "192.168.1.1",
            "remote",
            "10.0.0.1",
            "ttl",
            "64",
            "tos",
            "0x10",
        ],
        |ns| {
            ns.assert_eq_output(&["-d", "link", "show", IPIP_NAME]);
        },
    );
}

#[test]
fn test_ipip_create_and_show_with_external() {
    with_ipip_iface(&["external"], |ns| {
        ns.assert_eq_output(&["-d", "link", "show", IPIP_NAME]);
    });
}

#[test]
fn test_ipip_create_and_show_with_pmtudisc() {
    with_ipip_iface(
        &["local", "192.168.1.1", "remote", "10.0.0.1", "pmtudisc"],
        |ns| {
            ns.assert_eq_output(&["-d", "link", "show", IPIP_NAME]);
        },
    );
}

#[test]
fn test_ipip_create_and_show_with_ttl_inherit() {
    with_ipip_iface(
        &[
            "local",
            "192.168.1.1",
            "remote",
            "10.0.0.1",
            "ttl",
            "inherit",
        ],
        |ns| {
            ns.assert_eq_output(&["-d", "link", "show", IPIP_NAME]);
        },
    );
}

#[test]
fn test_ipip_create_and_show_with_tos_inherit() {
    with_ipip_iface(
        &[
            "local",
            "192.168.1.1",
            "remote",
            "10.0.0.1",
            "tos",
            "inherit",
        ],
        |ns| {
            ns.assert_eq_output(&["-d", "link", "show", IPIP_NAME]);
        },
    );
}

#[test]
fn test_ipip_create_and_show_with_mode_mplsip() {
    with_ipip_iface(
        &[
            "local",
            "192.168.1.1",
            "remote",
            "10.0.0.1",
            "mode",
            "mplsip",
        ],
        |ns| {
            ns.assert_eq_output(&["-d", "link", "show", IPIP_NAME]);
        },
    );
}

#[test]
fn test_ipip_create_and_show_with_mode_any() {
    with_ipip_iface(
        &["local", "192.168.1.1", "remote", "10.0.0.1", "mode", "any"],
        |ns| {
            ns.assert_eq_output(&["-d", "link", "show", IPIP_NAME]);
        },
    );
}

#[test]
fn test_ipip_create_and_show_with_dev() {
    with_ipip_iface(
        &["local", "192.168.1.1", "remote", "10.0.0.1", "dev", "lo"],
        |ns| {
            ns.assert_eq_output(&["-d", "link", "show", IPIP_NAME]);
        },
    );
}

#[test]
fn test_ipip_create_and_show_with_fwmark() {
    with_ipip_iface(
        &[
            "local",
            "192.168.1.1",
            "remote",
            "10.0.0.1",
            "fwmark",
            "0x1234",
        ],
        |ns| {
            ns.assert_eq_output(&["-d", "link", "show", IPIP_NAME]);
        },
    );
}

#[test]
fn test_ipip_create_and_show_nopmtudisc() {
    with_ipip_iface(
        &["local", "192.168.1.1", "remote", "10.0.0.1", "nopmtudisc"],
        |ns| {
            ns.assert_eq_output(&["-d", "link", "show", IPIP_NAME]);
        },
    );
}

fn with_ipip_iface<T>(opts: &[&str], test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        ns.exec_cmd(&["ip", "link", "set", "lo", "up"]);
        // Create ipip interface via ip-rs
        let mut args = vec!["link", "add", IPIP_NAME, "type", "ipip"];
        args.extend_from_slice(opts);

        ns.ip_rs_exec_cmd(&args);
        ns.exec_cmd(&["ip", "link", "set", IPIP_NAME, "up"]);

        test(ns);
    });
}
