// SPDX-License-Identifier: MIT

use std::process::Command;

use crate::tests::{NetnsGuard, with_netns};

const AMT_NAME: &str = "amt0";
const UNDERLAY: &str = "veth_amt";
const UNDERLAY_PEER: &str = "veth_amt_peer";

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
fn test_link_add_amt_gateway_basic() {
    with_amt_iface(
        &[
            "mode",
            "gateway",
            "local",
            "10.0.0.1",
            "discovery",
            "10.0.0.2",
        ],
        |ns| {
            ns.assert_eq_output(&["link", "show", AMT_NAME]);
        },
    );
}

#[test]
fn test_link_detailed_show_amt_gateway() {
    with_amt_iface(
        &[
            "mode",
            "gateway",
            "local",
            "10.0.0.1",
            "discovery",
            "10.0.0.2",
        ],
        |ns| {
            ns.assert_eq_output(&["-d", "link", "show", AMT_NAME]);
        },
    );
}

#[test]
fn test_link_show_amt_gateway_json() {
    with_amt_iface(
        &[
            "mode",
            "gateway",
            "local",
            "10.0.0.1",
            "discovery",
            "10.0.0.2",
        ],
        |ns| {
            ns.assert_eq_output(&["-j", "link", "show", AMT_NAME]);
        },
    );
}

#[test]
fn test_link_detailed_show_amt_gateway_json() {
    with_amt_iface(
        &[
            "mode",
            "gateway",
            "local",
            "10.0.0.1",
            "discovery",
            "10.0.0.2",
        ],
        |ns| {
            ns.assert_eq_output(&["-d", "-j", "link", "show", AMT_NAME]);
        },
    );
}

#[test]
fn test_link_add_amt_relay() {
    with_amt_iface(
        &[
            "mode",
            "relay",
            "local",
            "10.0.0.1",
            "discovery",
            "10.0.0.2",
            "relay_port",
            "1234",
        ],
        |ns| {
            ns.assert_eq_output(&["link", "show", AMT_NAME]);
        },
    );
}

#[test]
fn test_link_detailed_show_amt_relay() {
    with_amt_iface(
        &[
            "mode",
            "relay",
            "local",
            "10.0.0.1",
            "discovery",
            "10.0.0.2",
            "relay_port",
            "1234",
        ],
        |ns| {
            ns.assert_eq_output(&["-d", "link", "show", AMT_NAME]);
        },
    );
}

#[test]
fn test_link_add_amt_gateway_full() {
    with_amt_iface(
        &[
            "mode",
            "gateway",
            "local",
            "10.0.0.1",
            "discovery",
            "10.0.0.2",
            "gateway_port",
            "2268",
            "max_tunnels",
            "16",
        ],
        |ns| {
            ns.assert_eq_output(&["link", "show", AMT_NAME]);
        },
    );
}

#[test]
fn test_link_detailed_show_amt_gateway_full() {
    with_amt_iface(
        &[
            "mode",
            "gateway",
            "local",
            "10.0.0.1",
            "discovery",
            "10.0.0.2",
            "gateway_port",
            "2268",
            "max_tunnels",
            "16",
        ],
        |ns| {
            ns.assert_eq_output(&["-d", "link", "show", AMT_NAME]);
        },
    );
}

#[test]
fn test_link_set_amt_eopnotsupp() {
    let amt_set_name = "amt-eopnotsupp";
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link",
            "add",
            UNDERLAY,
            "type",
            "veth",
            "peer",
            "name",
            UNDERLAY_PEER,
        ]);
        ns.ip_rs_exec_cmd(&["link", "set", UNDERLAY, "up"]);

        ns.ip_rs_exec_cmd(&[
            "link",
            "add",
            amt_set_name,
            "type",
            "amt",
            "dev",
            UNDERLAY,
            "mode",
            "gateway",
            "local",
            "10.0.0.1",
            "discovery",
            "10.0.0.2",
        ]);

        let (_ip_stdout, ip_stderr, ip_code) = run_ip_cmd_in_ns(
            ns,
            &[
                "link",
                "set",
                amt_set_name,
                "type",
                "amt",
                "dev",
                UNDERLAY,
                "mode",
                "relay",
                "local",
                "10.0.0.2",
            ],
        );
        let (_rs_stdout, rs_stderr, rs_code) = run_ip_rs_cmd_in_ns(
            ns,
            &[
                "link",
                "set",
                amt_set_name,
                "type",
                "amt",
                "dev",
                UNDERLAY,
                "mode",
                "relay",
                "local",
                "10.0.0.2",
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

fn with_amt_iface<T>(opts: &[&str], test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link",
            "add",
            UNDERLAY,
            "type",
            "veth",
            "peer",
            "name",
            UNDERLAY_PEER,
        ]);
        ns.ip_rs_exec_cmd(&["link", "set", UNDERLAY, "up"]);

        let mut args =
            vec!["link", "add", AMT_NAME, "type", "amt", "dev", UNDERLAY];
        args.extend_from_slice(opts);
        ns.ip_rs_exec_cmd(&args);
        ns.ip_rs_exec_cmd(&["link", "set", AMT_NAME, "up"]);

        test(ns);
    });
}
