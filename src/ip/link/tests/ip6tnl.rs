// SPDX-License-Identifier: MIT

use crate::tests::{NetnsGuard, with_netns};

const IP6TNL_NAME: &str = "tdmy-ip6tnl0";

/// ip6tnl requires at least `local` and `remote` IPv6 addresses,
/// or `external`.

#[test]
fn test_ip6tnl_create_and_show_with_local_remote() {
    with_ip6tnl_iface(
        &["local", "2001:db8::1", "remote", "2001:db8::2"],
        |ns| {
            ns.assert_eq_output(&["-d", "link", "show", IP6TNL_NAME]);
        },
    );
}

#[test]
fn test_ip6tnl_create_and_show_with_ttl_tos() {
    with_ip6tnl_iface(
        &[
            "local",
            "2001:db8::1",
            "remote",
            "2001:db8::2",
            "ttl",
            "64",
            "tos",
            "0x10",
        ],
        |ns| {
            ns.assert_eq_output(&["-d", "link", "show", IP6TNL_NAME]);
        },
    );
}

#[test]
fn test_ip6tnl_create_and_show_with_external() {
    with_ip6tnl_iface(&["external"], |ns| {
        ns.assert_eq_output(&["-d", "link", "show", IP6TNL_NAME]);
    });
}

#[test]
fn test_ip6tnl_create_and_show_with_pmtudisc() {
    with_ip6tnl_iface(
        &["local", "2001:db8::1", "remote", "2001:db8::2", "pmtudisc"],
        |ns| {
            ns.assert_eq_output(&["-d", "link", "show", IP6TNL_NAME]);
        },
    );
}

#[test]
fn test_ip6tnl_create_and_show_with_ttl_inherit() {
    with_ip6tnl_iface(
        &[
            "local",
            "2001:db8::1",
            "remote",
            "2001:db8::2",
            "ttl",
            "inherit",
        ],
        |ns| {
            ns.assert_eq_output(&["-d", "link", "show", IP6TNL_NAME]);
        },
    );
}

#[test]
fn test_ip6tnl_create_and_show_with_tos_inherit() {
    with_ip6tnl_iface(
        &[
            "local",
            "2001:db8::1",
            "remote",
            "2001:db8::2",
            "tos",
            "inherit",
        ],
        |ns| {
            ns.assert_eq_output(&["-d", "link", "show", IP6TNL_NAME]);
        },
    );
}

#[test]
fn test_ip6tnl_create_and_show_with_fwmark() {
    with_ip6tnl_iface(
        &[
            "local",
            "2001:db8::1",
            "remote",
            "2001:db8::2",
            "fwmark",
            "0x1234",
        ],
        |ns| {
            ns.assert_eq_output(&["-d", "link", "show", IP6TNL_NAME]);
        },
    );
}

#[test]
fn test_ip6tnl_create_and_show_nopmtudisc() {
    with_ip6tnl_iface(
        &[
            "local",
            "2001:db8::1",
            "remote",
            "2001:db8::2",
            "nopmtudisc",
        ],
        |ns| {
            ns.assert_eq_output(&["-d", "link", "show", IP6TNL_NAME]);
        },
    );
}

#[test]
fn test_ip6tnl_create_and_show_with_encaplimit_numeric() {
    with_ip6tnl_iface(
        &[
            "local",
            "2001:db8::1",
            "remote",
            "2001:db8::2",
            "encaplimit",
            "4",
        ],
        |ns| {
            ns.assert_eq_output(&["-d", "link", "show", IP6TNL_NAME]);
        },
    );
}

#[test]
fn test_ip6tnl_create_and_show_with_encaplimit_none() {
    with_ip6tnl_iface(
        &[
            "local",
            "2001:db8::1",
            "remote",
            "2001:db8::2",
            "encaplimit",
            "none",
        ],
        |ns| {
            ns.assert_eq_output(&["-d", "link", "show", IP6TNL_NAME]);
        },
    );
}

#[test]
fn test_ip6tnl_create_and_show_with_tclass_numeric() {
    with_ip6tnl_iface(
        &[
            "local",
            "2001:db8::1",
            "remote",
            "2001:db8::2",
            "tclass",
            "0x10",
        ],
        |ns| {
            ns.assert_eq_output(&["-d", "link", "show", IP6TNL_NAME]);
        },
    );
}

#[test]
fn test_ip6tnl_create_and_show_with_tclass_inherit() {
    with_ip6tnl_iface(
        &[
            "local",
            "2001:db8::1",
            "remote",
            "2001:db8::2",
            "tclass",
            "inherit",
        ],
        |ns| {
            ns.assert_eq_output(&["-d", "link", "show", IP6TNL_NAME]);
        },
    );
}

#[test]
fn test_ip6tnl_create_and_show_with_flowlabel_numeric() {
    with_ip6tnl_iface(
        &[
            "local",
            "2001:db8::1",
            "remote",
            "2001:db8::2",
            "flowlabel",
            "0x12345",
        ],
        |ns| {
            ns.assert_eq_output(&["-d", "link", "show", IP6TNL_NAME]);
        },
    );
}

#[test]
fn test_ip6tnl_create_and_show_with_flowlabel_inherit() {
    with_ip6tnl_iface(
        &[
            "local",
            "2001:db8::1",
            "remote",
            "2001:db8::2",
            "flowlabel",
            "inherit",
        ],
        |ns| {
            ns.assert_eq_output(&["-d", "link", "show", IP6TNL_NAME]);
        },
    );
}

#[test]
fn test_ip6tnl_create_and_show_with_dscp_inherit() {
    with_ip6tnl_iface(
        &[
            "local",
            "2001:db8::1",
            "remote",
            "2001:db8::2",
            "dscp",
            "inherit",
        ],
        |ns| {
            ns.assert_eq_output(&["-d", "link", "show", IP6TNL_NAME]);
        },
    );
}

#[test]
fn test_ip6tnl_create_and_show_with_allow_localremote() {
    with_ip6tnl_iface(
        &[
            "local",
            "2001:db8::1",
            "remote",
            "2001:db8::2",
            "allow-localremote",
        ],
        |ns| {
            ns.assert_eq_output(&["-d", "link", "show", IP6TNL_NAME]);
        },
    );
}

#[test]
fn test_ip6tnl_create_and_show_with_noallow_localremote() {
    with_ip6tnl_iface(
        &[
            "local",
            "2001:db8::1",
            "remote",
            "2001:db8::2",
            "noallow-localremote",
        ],
        |ns| {
            ns.assert_eq_output(&["-d", "link", "show", IP6TNL_NAME]);
        },
    );
}

#[test]
fn test_ip6tnl_create_and_show_with_mode_ip6ip6() {
    with_ip6tnl_iface(
        &[
            "local",
            "2001:db8::1",
            "remote",
            "2001:db8::2",
            "mode",
            "ip6ip6",
        ],
        |ns| {
            ns.assert_eq_output(&["-d", "link", "show", IP6TNL_NAME]);
        },
    );
}

#[test]
fn test_ip6tnl_create_and_show_with_mode_ipip6() {
    with_ip6tnl_iface(
        &[
            "local",
            "2001:db8::1",
            "remote",
            "2001:db8::2",
            "mode",
            "ipip6",
        ],
        |ns| {
            ns.assert_eq_output(&["-d", "link", "show", IP6TNL_NAME]);
        },
    );
}

#[test]
fn test_ip6tnl_create_and_show_with_mode_any() {
    with_ip6tnl_iface(
        &[
            "local",
            "2001:db8::1",
            "remote",
            "2001:db8::2",
            "mode",
            "any",
        ],
        |ns| {
            ns.assert_eq_output(&["-d", "link", "show", IP6TNL_NAME]);
        },
    );
}

#[test]
fn test_ip6tnl_create_and_show_with_fwmark_inherit() {
    with_ip6tnl_iface(
        &[
            "local",
            "2001:db8::1",
            "remote",
            "2001:db8::2",
            "fwmark",
            "inherit",
        ],
        |ns| {
            ns.assert_eq_output(&["-d", "link", "show", IP6TNL_NAME]);
        },
    );
}

#[test]
fn test_ip6tnl_create_and_show_with_dev() {
    with_ip6tnl_iface(
        &["local", "2001:db8::1", "remote", "2001:db8::2", "dev", "lo"],
        |ns| {
            ns.assert_eq_output(&["-d", "link", "show", IP6TNL_NAME]);
        },
    );
}

fn with_ip6tnl_iface<T>(opts: &[&str], test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        ns.exec_cmd(&["ip", "link", "set", "lo", "up"]);
        let mut args = vec!["link", "add", IP6TNL_NAME, "type", "ip6tnl"];
        args.extend_from_slice(opts);

        ns.ip_rs_exec_cmd(&args);
        ns.exec_cmd(&["ip", "link", "set", IP6TNL_NAME, "up"]);

        test(ns);
    });
}
