// SPDX-License-Identifier: MIT

mod common;
use self::common::{NetnsGuard, with_netns};

const DEV: &str = "test-add-opts";

fn with_add_dummy<T>(test: T, args: &[&str])
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        let mut cmd = vec!["link", "add"];
        cmd.extend_from_slice(args);
        ns.ip_rs_exec_cmd(&cmd);
        test(ns);
    });
}

#[test]
fn test_add_dummy_mtu() {
    with_add_dummy(
        |ns| {
            ns.assert_eq_output(&["link", "show", DEV]);
        },
        &[DEV, "mtu", "2000", "type", "dummy"],
    );
}

#[test]
fn test_add_dummy_txqueuelen() {
    with_add_dummy(
        |ns| {
            ns.assert_eq_output(&["link", "show", DEV]);
        },
        &[DEV, "txqueuelen", "500", "type", "dummy"],
    );
}

#[test]
fn test_add_dummy_txqueuelen_qlen() {
    with_add_dummy(
        |ns| {
            ns.assert_eq_output(&["link", "show", DEV]);
        },
        &[DEV, "qlen", "600", "type", "dummy"],
    );
}

#[test]
fn test_add_dummy_txqueuelen_txqlen() {
    with_add_dummy(
        |ns| {
            ns.assert_eq_output(&["link", "show", DEV]);
        },
        &[DEV, "txqlen", "700", "type", "dummy"],
    );
}

#[test]
fn test_add_dummy_broadcast() {
    with_add_dummy(
        |ns| {
            ns.assert_eq_output(&["link", "show", DEV]);
        },
        &[DEV, "broadcast", "ff:ff:ff:ff:ff:ff", "type", "dummy"],
    );
}

#[test]
fn test_add_dummy_broadcast_brd() {
    with_add_dummy(
        |ns| {
            ns.assert_eq_output(&["link", "show", DEV]);
        },
        &[DEV, "brd", "00:00:00:00:00:00", "type", "dummy"],
    );
}

#[test]
fn test_add_dummy_numtxqueues_numrxqueues() {
    with_add_dummy(
        |ns| {
            ns.assert_eq_output(&["link", "show", DEV]);
        },
        &[DEV, "numtxqueues", "8", "numrxqueues", "4", "type", "dummy"],
    );
}

#[test]
fn test_add_dummy_all_opts() {
    with_add_dummy(
        |ns| {
            ns.assert_eq_output(&["-d", "link", "show", DEV]);
        },
        &[
            DEV,
            "mtu",
            "2000",
            "txqueuelen",
            "500",
            "address",
            "00:11:22:33:44:55",
            "broadcast",
            "ff:ff:ff:ff:ff:ff",
            "numtxqueues",
            "8",
            "numrxqueues",
            "4",
            "type",
            "dummy",
        ],
    );
}
