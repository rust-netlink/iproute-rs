// SPDX-License-Identifier: MIT

mod common;

use std::process::Command;

use self::common::{NetnsGuard, with_netns};

/// The `l2tp` generic netlink family does auto-load, but the `l2tp_eth`
/// module of the sessions does not, therefore both are loaded before the
/// reference implementation is used.
fn load_l2tp_modules(ns: &NetnsGuard) {
    for module in ["l2tp_netlink", "l2tp_eth"] {
        let output = Command::new("ip")
            .args(["netns", "exec", &ns.name, "modprobe", module])
            .output()
            .expect("failed to run modprobe");
        assert!(
            output.status.success(),
            "modprobe {module} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

fn with_l2tp_netns<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        load_l2tp_modules(ns);
        // An L2TP tunnel needs a reachable peer, a tunnel between the
        // loopback addresses of a fresh namespace needs `lo` up.
        ns.exec_cmd(&["ip", "link", "set", "lo", "up"]);
        test(ns);
    });
}

/// The tunnel of `ip l2tp add tunnel tunnel_id 1000 peer_tunnel_id 2000
/// encap udp local 127.0.0.1 remote 127.0.0.2 udp_sport 1701 udp_dport
/// 1702`.
const UDP_TUNNEL: &[&str] = &[
    "l2tp",
    "add",
    "tunnel",
    "tunnel_id",
    "1000",
    "peer_tunnel_id",
    "2000",
    "encap",
    "udp",
    "local",
    "127.0.0.1",
    "remote",
    "127.0.0.2",
    "udp_sport",
    "1701",
    "udp_dport",
    "1702",
];

#[test]
fn test_l2tp_show_empty() {
    with_l2tp_netns(|ns| {
        ns.assert_eq_output(&["l2tp", "show", "tunnel"]);
        ns.assert_eq_output(&["-j", "l2tp", "show", "tunnel"]);
        ns.assert_eq_output(&["l2tp", "show", "session"]);
        ns.assert_eq_output(&["-j", "l2tp", "show", "session"]);
    });
}

#[test]
fn test_l2tp_tunnel_udp() {
    with_l2tp_netns(|ns| {
        ns.ip_rs_exec_cmd(UDP_TUNNEL);
        ns.assert_eq_output(&["l2tp", "show", "tunnel"]);
        ns.assert_eq_output(&["-j", "l2tp", "show", "tunnel"]);

        ns.ip_rs_exec_cmd(&["l2tp", "del", "tunnel", "tunnel_id", "1000"]);
        ns.assert_eq_output(&["l2tp", "show", "tunnel"]);
        ns.assert_eq_output(&["-j", "l2tp", "show", "tunnel"]);
    });
}

#[test]
fn test_l2tp_tunnel_ip() {
    with_l2tp_netns(|ns| {
        ns.ip_rs_exec_cmd(&[
            "l2tp",
            "add",
            "tunnel",
            "tunnel_id",
            "1001",
            "peer_tunnel_id",
            "2001",
            "encap",
            "ip",
            "local",
            "127.0.0.1",
            "remote",
            "127.0.0.2",
        ]);
        ns.assert_eq_output(&["l2tp", "show", "tunnel"]);
        ns.assert_eq_output(&["-j", "l2tp", "show", "tunnel"]);

        ns.ip_rs_exec_cmd(&["l2tp", "del", "tunnel", "tunnel_id", "1001"]);
        ns.assert_eq_output(&["l2tp", "show", "tunnel"]);
    });
}

#[test]
fn test_l2tp_tunnel_ipv6() {
    with_l2tp_netns(|ns| {
        ns.ip_rs_exec_cmd(&[
            "l2tp",
            "add",
            "tunnel",
            "tunnel_id",
            "1002",
            "peer_tunnel_id",
            "2002",
            "encap",
            "udp",
            "local",
            "::1",
            "remote",
            "::1",
            "udp_sport",
            "1701",
            "udp_dport",
            "1702",
            "udp6_csum_tx",
            "off",
        ]);
        ns.assert_eq_output(&["l2tp", "show", "tunnel"]);
        ns.assert_eq_output(&["-j", "l2tp", "show", "tunnel"]);
    });
}

#[test]
fn test_l2tp_session_with_options() {
    with_l2tp_netns(|ns| {
        ns.ip_rs_exec_cmd(UDP_TUNNEL);
        ns.ip_rs_exec_cmd(&[
            "l2tp",
            "add",
            "session",
            "name",
            "l2tpeth0",
            "tunnel_id",
            "1000",
            "session_id",
            "5",
            "peer_session_id",
            "6",
            "cookie",
            "01020304",
            "peer_cookie",
            "05060708",
            "seq",
            "both",
            "l2spec_type",
            "none",
        ]);
        ns.assert_eq_output(&["l2tp", "show", "session"]);
        ns.assert_eq_output(&["-j", "l2tp", "show", "session"]);

        ns.ip_rs_exec_cmd(&[
            "l2tp",
            "del",
            "session",
            "tunnel_id",
            "1000",
            "session_id",
            "5",
        ]);
        ns.assert_eq_output(&["l2tp", "show", "session"]);
    });
}

#[test]
fn test_l2tp_oneline() {
    with_l2tp_netns(|ns| {
        ns.ip_rs_exec_cmd(UDP_TUNNEL);
        ns.ip_rs_exec_cmd(&[
            "l2tp",
            "add",
            "session",
            "name",
            "l2tpeth0",
            "tunnel_id",
            "1000",
            "session_id",
            "5",
            "peer_session_id",
            "6",
            "seq",
            "both",
        ]);
        ns.assert_eq_output(&["-o", "l2tp", "show", "tunnel"]);
        ns.assert_eq_output(&["-o", "-j", "l2tp", "show", "tunnel"]);
        ns.assert_eq_output(&["-o", "l2tp", "show", "session"]);
    });
}

#[test]
fn test_l2tp_show_filter() {
    with_l2tp_netns(|ns| {
        ns.ip_rs_exec_cmd(UDP_TUNNEL);
        ns.ip_rs_exec_cmd(&[
            "l2tp",
            "add",
            "tunnel",
            "tunnel_id",
            "1001",
            "peer_tunnel_id",
            "2001",
            "encap",
            "ip",
            "local",
            "127.0.0.1",
            "remote",
            "127.0.0.2",
        ]);
        ns.ip_rs_exec_cmd(&[
            "l2tp",
            "add",
            "session",
            "name",
            "l2tpeth0",
            "tunnel_id",
            "1000",
            "session_id",
            "5",
            "peer_session_id",
            "6",
        ]);

        ns.assert_eq_output(&["l2tp", "show", "tunnel", "tunnel_id", "1001"]);
        ns.assert_eq_output(&[
            "-j",
            "l2tp",
            "show",
            "tunnel",
            "tunnel_id",
            "1000",
        ]);
        ns.assert_eq_output(&[
            "l2tp",
            "show",
            "session",
            "tunnel_id",
            "1000",
            "session_id",
            "5",
        ]);
        ns.assert_eq_output(&[
            "-j",
            "l2tp",
            "show",
            "session",
            "tunnel_id",
            "1000",
            "session_id",
            "5",
        ]);
    });
}

#[test]
fn test_l2tp_prefix_aliases() {
    with_l2tp_netns(|ns| {
        let mut add = vec!["l2tp", "a"];
        add.extend_from_slice(&UDP_TUNNEL[2..]);
        ns.ip_rs_exec_cmd(&add);
        ns.assert_eq_output(&["l2tp", "sh", "tunnel"]);
        ns.assert_eq_output(&["l2tp", "lst", "tunnel"]);
        ns.assert_eq_output(&["-j", "l2tp", "s", "tunnel"]);
        ns.ip_rs_exec_cmd(&["l2tp", "dele", "tunnel", "tunnel_id", "1000"]);
        ns.assert_eq_output(&["l2tp", "list", "tunnel"]);
    });
}

#[test]
fn test_l2tp_help() {
    with_netns(|ns| {
        let (expected_stderr, expected_code) =
            ns.exec_cmd_expect_failure(&["ip", "l2tp", "help"]);
        let (stderr, code) =
            ns.ip_rs_exec_cmd_expect_failure_with_code(&["l2tp", "help"]);
        pretty_assertions::assert_eq!(expected_stderr, stderr);
        assert_eq!(expected_code, code);
    });
}

#[test]
fn test_l2tp_no_subcommand() {
    with_netns(|ns| {
        let (expected_stderr, expected_code) =
            ns.exec_cmd_expect_failure(&["ip", "l2tp"]);
        let (stderr, code) =
            ns.ip_rs_exec_cmd_expect_failure_with_code(&["l2tp"]);
        pretty_assertions::assert_eq!(expected_stderr, stderr);
        assert_eq!(expected_code, code);
    });
}

#[test]
fn test_l2tp_unknown_subcommand() {
    with_netns(|ns| {
        let (expected_stderr, expected_code) =
            ns.exec_cmd_expect_failure(&["ip", "l2tp", "bogus"]);
        let (stderr, code) =
            ns.ip_rs_exec_cmd_expect_failure_with_code(&["l2tp", "bogus"]);
        pretty_assertions::assert_eq!(expected_stderr, stderr);
        assert_eq!(expected_code, code);
    });
}

#[test]
fn test_l2tp_missing_options() {
    with_netns(|ns| {
        let ip_args = [
            "ip",
            "l2tp",
            "add",
            "tunnel",
            "tunnel_id",
            "1",
            "peer_tunnel_id",
            "2",
            "encap",
            "udp",
            "local",
            "127.0.0.1",
            "remote",
            "127.0.0.2",
        ];
        let (expected_stderr, expected_code) =
            ns.exec_cmd_expect_failure(&ip_args);
        let (stderr, code) =
            ns.ip_rs_exec_cmd_expect_failure_with_code(&ip_args[1..]);
        pretty_assertions::assert_eq!(expected_stderr, stderr);
        assert_eq!(expected_code, code);
    });
}

#[test]
fn test_l2tp_invalid_id() {
    with_netns(|ns| {
        let ip_args = ["ip", "l2tp", "add", "tunnel", "tunnel_id", "abc"];
        let (expected_stderr, expected_code) =
            ns.exec_cmd_expect_failure(&ip_args);
        let (stderr, code) =
            ns.ip_rs_exec_cmd_expect_failure_with_code(&ip_args[1..]);
        pretty_assertions::assert_eq!(expected_stderr, stderr);
        assert_eq!(expected_code, code);
    });
}

#[test]
fn test_l2tp_invalid_address() {
    with_netns(|ns| {
        let ip_args = [
            "ip",
            "l2tp",
            "add",
            "tunnel",
            "tunnel_id",
            "1",
            "peer_tunnel_id",
            "2",
            "encap",
            "udp",
            "local",
            "bogus",
            "remote",
            "127.0.0.2",
            "udp_sport",
            "1",
            "udp_dport",
            "2",
        ];
        let (expected_stderr, expected_code) =
            ns.exec_cmd_expect_failure(&ip_args);
        let (stderr, code) =
            ns.ip_rs_exec_cmd_expect_failure_with_code(&ip_args[1..]);
        pretty_assertions::assert_eq!(expected_stderr, stderr);
        assert_eq!(expected_code, code);
    });
}

#[test]
fn test_l2tp_unknown_encap() {
    with_netns(|ns| {
        let ip_args = [
            "ip",
            "l2tp",
            "add",
            "tunnel",
            "tunnel_id",
            "1",
            "peer_tunnel_id",
            "2",
            "encap",
            "bogus",
            "local",
            "127.0.0.1",
            "remote",
            "127.0.0.2",
        ];
        let (expected_stderr, expected_code) =
            ns.exec_cmd_expect_failure(&ip_args);
        let (stderr, code) =
            ns.ip_rs_exec_cmd_expect_failure_with_code(&ip_args[1..]);
        pretty_assertions::assert_eq!(expected_stderr, stderr);
        assert_eq!(expected_code, code);
    });
}

#[test]
fn test_l2tp_kernel_error_exit_code() {
    // iproute2 prints `RTNETLINK answers: No such device` while the crate
    // prints its own error, only the exit code has to match.
    with_netns(|ns| {
        let (_, expected_code) = ns.exec_cmd_expect_failure(&[
            "ip",
            "l2tp",
            "del",
            "tunnel",
            "tunnel_id",
            "99999",
        ]);
        let (stderr, code) = ns.ip_rs_exec_cmd_expect_failure_with_code(&[
            "l2tp",
            "del",
            "tunnel",
            "tunnel_id",
            "99999",
        ]);
        assert!(!stderr.trim().is_empty());
        assert_eq!(expected_code, code);
    });
}
