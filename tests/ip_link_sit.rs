// SPDX-License-Identifier: MIT

mod common;
use self::common::{NetnsGuard, with_netns};

const SIT_NAME: &str = "tdmy-sit0";

/// Creating a SIT tunnel without explicit local/remote fails with
/// "File exists" because the kernel creates a default `sit0` device
/// with those default parameters. All SIT test cases must specify at
/// least `local` and `remote`.
///
/// The `external` (collect_metadata) mode cannot be tested because the
/// kernel allows only one collect_metadata tunnel per netns, and sit0
/// already occupies that slot.

#[test]
fn test_sit_create_and_show_with_local_remote() {
    with_sit_iface(&["local", "192.168.1.1", "remote", "10.0.0.1"], |ns| {
        ns.assert_eq_output(&["-d", "link", "show", SIT_NAME]);
    });
}

#[test]
fn test_sit_create_and_show_with_ttl_tos() {
    with_sit_iface(
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
            ns.assert_eq_output(&["-d", "link", "show", SIT_NAME]);
        },
    );
}

#[test]
fn test_sit_create_and_show_with_6rd() {
    with_sit_iface(
        &[
            "local",
            "192.168.1.1",
            "remote",
            "10.0.0.1",
            "6rd-prefix",
            "2001:db8::/32",
            "6rd-relay_prefix",
            "172.16.0.0/12",
        ],
        |ns| {
            ns.assert_eq_output(&["-d", "link", "show", SIT_NAME]);
        },
    );
}

#[test]
fn test_sit_create_and_show_with_pmtudisc() {
    with_sit_iface(
        &["local", "192.168.1.1", "remote", "10.0.0.1", "pmtudisc"],
        |ns| {
            ns.assert_eq_output(&["-d", "link", "show", SIT_NAME]);
        },
    );
}

#[test]
fn test_sit_create_and_show_with_ttl_inherit() {
    with_sit_iface(
        &[
            "local",
            "192.168.1.1",
            "remote",
            "10.0.0.1",
            "ttl",
            "inherit",
        ],
        |ns| {
            ns.assert_eq_output(&["-d", "link", "show", SIT_NAME]);
        },
    );
}

#[test]
fn test_sit_create_and_show_with_tos_inherit() {
    with_sit_iface(
        &[
            "local",
            "192.168.1.1",
            "remote",
            "10.0.0.1",
            "tos",
            "inherit",
        ],
        |ns| {
            ns.assert_eq_output(&["-d", "link", "show", SIT_NAME]);
        },
    );
}

#[test]
fn test_sit_create_and_show_with_mode_ip6ip() {
    with_sit_iface(
        &[
            "local",
            "192.168.1.1",
            "remote",
            "10.0.0.1",
            "mode",
            "ip6ip",
        ],
        |ns| {
            ns.assert_eq_output(&["-d", "link", "show", SIT_NAME]);
        },
    );
}

#[test]
fn test_sit_create_and_show_with_mode_any() {
    with_sit_iface(
        &["local", "192.168.1.1", "remote", "10.0.0.1", "mode", "any"],
        |ns| {
            ns.assert_eq_output(&["-d", "link", "show", SIT_NAME]);
        },
    );
}

#[test]
fn test_sit_create_and_show_with_dev() {
    with_sit_iface(
        &["local", "192.168.1.1", "remote", "10.0.0.1", "dev", "lo"],
        |ns| {
            ns.assert_eq_output(&["-d", "link", "show", SIT_NAME]);
        },
    );
}

#[test]
fn test_sit_create_and_show_with_fwmark() {
    with_sit_iface(
        &[
            "local",
            "192.168.1.1",
            "remote",
            "10.0.0.1",
            "fwmark",
            "0x1234",
        ],
        |ns| {
            ns.assert_eq_output(&["-d", "link", "show", SIT_NAME]);
        },
    );
}

#[test]
fn test_sit_create_and_show_nopmtudisc() {
    with_sit_iface(
        &["local", "192.168.1.1", "remote", "10.0.0.1", "nopmtudisc"],
        |ns| {
            ns.assert_eq_output(&["-d", "link", "show", SIT_NAME]);
        },
    );
}

fn with_sit_iface<T>(opts: &[&str], test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&["link", "set", "lo", "up"]);
        let mut args = vec!["link", "add", SIT_NAME, "type", "sit"];
        args.extend_from_slice(opts);

        ns.ip_rs_exec_cmd(&args);
        ns.ip_rs_exec_cmd(&["link", "set", SIT_NAME, "up"]);

        test(ns);
    });
}
