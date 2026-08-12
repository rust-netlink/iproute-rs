// SPDX-License-Identifier: MIT

use std::process::Command;

mod common;
use self::common::{NetnsGuard, with_netns};

const BAREUDP_NAME: &str = "bareudp0";

fn run_ip_cmd_in_ns(
    ns: &NetnsGuard,
    args: &[&str],
) -> (String, String, Option<i32>) {
    let mut full_args = vec!["netns", "exec", &ns.name, "ip"];
    full_args.extend_from_slice(args);
    let output = Command::new("ip")
        .args(&full_args)
        .output()
        .expect("failed to run ip command");
    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
        output.status.code(),
    )
}

fn run_ip_rs_cmd_in_ns(
    ns: &NetnsGuard,
    args: &[&str],
) -> (String, String, Option<i32>) {
    let ip_rs = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("ip-rs");
    let mut full_args = vec!["netns", "exec", &ns.name];
    full_args.push(ip_rs.to_str().unwrap());
    full_args.extend_from_slice(args);
    let output = Command::new("ip")
        .args(&full_args)
        .output()
        .expect("failed to run ip-rs command");
    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
        output.status.code(),
    )
}

#[test]
fn test_link_add_bareudp_mpls_uc() {
    with_bareudp_iface(&["dstport", "6635", "ethertype", "mpls_uc"], |ns| {
        ns.assert_eq_output(&["link", "show", BAREUDP_NAME]);
    });
}

#[test]
fn test_link_detailed_show_bareudp_mpls_uc() {
    with_bareudp_iface(&["dstport", "6635", "ethertype", "mpls_uc"], |ns| {
        ns.assert_eq_output(&["-d", "link", "show", BAREUDP_NAME]);
    });
}

#[test]
fn test_link_show_bareudp_mpls_uc_json() {
    with_bareudp_iface(&["dstport", "6635", "ethertype", "mpls_uc"], |ns| {
        ns.assert_eq_output(&["-j", "link", "show", BAREUDP_NAME]);
    });
}

#[test]
fn test_link_detailed_show_bareudp_mpls_uc_json() {
    with_bareudp_iface(&["dstport", "6635", "ethertype", "mpls_uc"], |ns| {
        ns.assert_eq_output(&["-d", "-j", "link", "show", BAREUDP_NAME]);
    });
}

#[test]
fn test_link_add_bareudp_ipv4() {
    with_bareudp_iface(&["dstport", "6635", "ethertype", "ipv4"], |ns| {
        ns.assert_eq_output(&["link", "show", BAREUDP_NAME]);
    });
}

#[test]
fn test_link_detailed_show_bareudp_ipv4() {
    with_bareudp_iface(&["dstport", "6635", "ethertype", "ipv4"], |ns| {
        ns.assert_eq_output(&["-d", "link", "show", BAREUDP_NAME]);
    });
}

#[test]
fn test_link_add_bareudp_ipv6() {
    with_bareudp_iface(&["dstport", "6635", "ethertype", "ipv6"], |ns| {
        ns.assert_eq_output(&["link", "show", BAREUDP_NAME]);
    });
}

#[test]
fn test_link_detailed_show_bareudp_ipv6() {
    with_bareudp_iface(&["dstport", "6635", "ethertype", "ipv6"], |ns| {
        ns.assert_eq_output(&["-d", "link", "show", BAREUDP_NAME]);
    });
}

#[test]
fn test_link_detailed_show_bareudp_ipv6_json() {
    with_bareudp_iface(&["dstport", "6635", "ethertype", "ipv6"], |ns| {
        ns.assert_eq_output(&["-d", "-j", "link", "show", BAREUDP_NAME]);
    });
}

#[test]
fn test_link_add_bareudp_mpls_mc() {
    with_bareudp_iface(&["dstport", "6635", "ethertype", "mpls_mc"], |ns| {
        ns.assert_eq_output(&["link", "show", BAREUDP_NAME]);
    });
}

#[test]
fn test_link_detailed_show_bareudp_mpls_mc() {
    with_bareudp_iface(&["dstport", "6635", "ethertype", "mpls_mc"], |ns| {
        ns.assert_eq_output(&["-d", "link", "show", BAREUDP_NAME]);
    });
}

#[test]
fn test_link_add_bareudp_multiproto() {
    with_bareudp_iface(
        &["dstport", "6635", "ethertype", "mpls_uc", "multiproto"],
        |ns| {
            ns.assert_eq_output(&["link", "show", BAREUDP_NAME]);
        },
    );
}

#[test]
fn test_link_detailed_show_bareudp_multiproto() {
    with_bareudp_iface(
        &["dstport", "6635", "ethertype", "mpls_uc", "multiproto"],
        |ns| {
            ns.assert_eq_output(&["-d", "link", "show", BAREUDP_NAME]);
        },
    );
}

#[test]
fn test_link_add_bareudp_srcportmin() {
    with_bareudp_iface(
        &["dstport", "6635", "ethertype", "ipv4", "srcportmin", "1024"],
        |ns| {
            ns.assert_eq_output(&["link", "show", BAREUDP_NAME]);
        },
    );
}

#[test]
fn test_link_detailed_show_bareudp_srcportmin() {
    with_bareudp_iface(
        &["dstport", "6635", "ethertype", "ipv4", "srcportmin", "1024"],
        |ns| {
            ns.assert_eq_output(&["-d", "link", "show", BAREUDP_NAME]);
        },
    );
}

#[test]
fn test_link_detailed_show_bareudp_srcportmin_json() {
    with_bareudp_iface(
        &["dstport", "6635", "ethertype", "ipv4", "srcportmin", "1024"],
        |ns| {
            ns.assert_eq_output(&["-d", "-j", "link", "show", BAREUDP_NAME]);
        },
    );
}

#[test]
fn test_set_bareudp_up() {
    with_bareudp_iface(&["dstport", "6635", "ethertype", "mpls_uc"], |ns| {
        ns.assert_eq_output(&["link", "show", BAREUDP_NAME]);
    });
}

#[test]
fn test_set_bareudp_down() {
    with_bareudp_iface(&["dstport", "6635", "ethertype", "mpls_uc"], |ns| {
        ns.ip_rs_exec_cmd(&["link", "set", BAREUDP_NAME, "down"]);
        ns.assert_eq_output(&["link", "show", BAREUDP_NAME]);
    });
}

#[test]
fn test_set_bareudp_mtu() {
    with_bareudp_iface(&["dstport", "6635", "ethertype", "ipv4"], |ns| {
        ns.ip_rs_exec_cmd(&["link", "set", BAREUDP_NAME, "up"]);
        ns.ip_rs_exec_cmd(&["link", "set", BAREUDP_NAME, "mtu", "1400"]);
        ns.assert_eq_output(&["link", "show", BAREUDP_NAME]);
    });
}

#[test]
fn test_set_bareudp_txqueuelen() {
    with_bareudp_iface(&["dstport", "6635", "ethertype", "ipv6"], |ns| {
        ns.ip_rs_exec_cmd(&["link", "set", BAREUDP_NAME, "txqueuelen", "500"]);
        ns.assert_eq_output(&["link", "show", BAREUDP_NAME]);
    });
}

#[test]
fn test_set_bareudp_type_eopnotsupp() {
    let bareudp_set_name = "bdeopnotsupp";
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link",
            "add",
            bareudp_set_name,
            "type",
            "bareudp",
            "dstport",
            "6635",
            "ethertype",
            "mpls_uc",
        ]);

        let (_ip_stdout, ip_stderr, ip_code) = run_ip_cmd_in_ns(
            ns,
            &[
                "link",
                "set",
                bareudp_set_name,
                "type",
                "bareudp",
                "dstport",
                "7000",
                "ethertype",
                "ipv4",
            ],
        );
        let (_rs_stdout, rs_stderr, rs_code) = run_ip_rs_cmd_in_ns(
            ns,
            &[
                "link",
                "set",
                bareudp_set_name,
                "type",
                "bareudp",
                "dstport",
                "7000",
                "ethertype",
                "ipv4",
            ],
        );

        assert_eq!(ip_code, Some(2), "ip should exit 2: {ip_stderr}");
        assert_eq!(rs_code, Some(2), "ip-rs should exit 2: {rs_stderr}");
        assert!(
            ip_stderr.contains("Operation not supported"),
            "ip stderr: {ip_stderr}"
        );
        assert!(
            rs_stderr.contains("Operation not supported"),
            "ip-rs stderr: {rs_stderr}"
        );
    });
}

fn with_bareudp_iface<T>(opts: &[&str], test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        let mut args = vec!["link", "add", BAREUDP_NAME, "type", "bareudp"];
        args.extend_from_slice(opts);
        ns.ip_rs_exec_cmd(&args);
        ns.ip_rs_exec_cmd(&["link", "set", BAREUDP_NAME, "up"]);

        test(ns);
    });
}
