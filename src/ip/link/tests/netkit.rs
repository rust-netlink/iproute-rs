// SPDX-License-Identifier: MIT

use crate::tests::{NetnsGuard, with_netns};

const NETKIT_NAME: &str = "tnk";

#[test]
fn test_link_show_netkit() {
    with_netkit_default(|ns| {
        ns.assert_eq_output(&["link", "show", NETKIT_NAME]);
    });
}

#[test]
fn test_link_detailed_show_netkit() {
    with_netkit_default(|ns| {
        ns.assert_eq_output(&["-d", "link", "show", NETKIT_NAME]);
    });
}

#[test]
fn test_link_show_netkit_json() {
    with_netkit_default(|ns| {
        ns.assert_eq_output(&["-j", "link", "show", NETKIT_NAME]);
    });
}

#[test]
fn test_link_detailed_show_netkit_json() {
    with_netkit_default(|ns| {
        ns.assert_eq_output(&["-d", "-j", "link", "show", NETKIT_NAME]);
    });
}

#[test]
fn test_netkit_create_mode_l2() {
    with_netns(|ns| {
        let name = "tnk-l2";
        ns.ip_rs_exec_cmd(&[
            "link", "add", name, "type", "netkit", "mode", "l2",
        ]);
        netkit_bring_up_all(ns, name);

        let outputs = ns.assert_eq_output(&["-d", "link", "show", name]);
        assert!(outputs.expected.contains("mode l2"));
    });
}

#[test]
fn test_netkit_create_forward_policy() {
    with_netns(|ns| {
        let name = "tnk-fwd";
        ns.ip_rs_exec_cmd(&["link", "add", name, "type", "netkit", "forward"]);
        netkit_bring_up_all(ns, name);

        let outputs = ns.assert_eq_output(&["-d", "link", "show", name]);
        assert!(outputs.expected.contains("policy forward"));
    });
}

#[test]
fn test_netkit_create_blackhole_policy() {
    with_netns(|ns| {
        let name = "tnk-bh";
        ns.ip_rs_exec_cmd(&[
            "link",
            "add",
            name,
            "type",
            "netkit",
            "blackhole",
        ]);
        netkit_bring_up_all(ns, name);

        let outputs = ns.assert_eq_output(&["-d", "link", "show", name]);
        assert!(outputs.expected.contains("policy blackhole"));
    });
}

#[test]
fn test_netkit_create_with_peer_name() {
    with_netns(|ns| {
        let name = "tnk-pn";
        let peer = "tnk-pn-p";
        ns.ip_rs_exec_cmd(&[
            "link", "add", name, "type", "netkit", "peer", peer,
        ]);
        netkit_bring_up_all(ns, name);

        ns.assert_eq_output(&["-d", "link", "show", name]);
    });
}

#[test]
fn test_netkit_create_peer_with_scrub_policy_name() {
    with_netns(|ns| {
        let name = "tnk-spn";
        let peer = "tnk-spn-p";
        ns.ip_rs_exec_cmd(&[
            "link", "add", name, "type", "netkit", "peer", "scrub", "none",
            "forward", peer,
        ]);
        netkit_bring_up_all(ns, name);

        let outputs = ns.assert_eq_output(&["-d", "link", "show", name]);
        assert!(outputs.expected.contains("peer policy forward"));
        assert!(outputs.expected.contains("peer scrub none"));
    });
}

#[test]
fn test_netkit_create_peer_with_policy_name() {
    with_netns(|ns| {
        let name = "tnk-pn2";
        let peer = "tnk-pn2-p";
        ns.ip_rs_exec_cmd(&[
            "link", "add", name, "type", "netkit", "peer", "forward", peer,
        ]);
        netkit_bring_up_all(ns, name);

        let outputs = ns.assert_eq_output(&["-d", "link", "show", name]);
        assert!(outputs.expected.contains("peer policy forward"));
    });
}

fn netkit_bring_up_all(ns: &NetnsGuard, primary: &str) {
    let output = ns.exec_cmd(&["ip", "link", "show", primary]);
    let peer = output
        .split_once('@')
        .and_then(|(_, rest)| rest.split_once(':').map(|(p, _)| p.trim()));
    if let Some(peer) = peer {
        ns.exec_cmd(&["ip", "link", "set", peer, "up"]);
    }
    ns.exec_cmd(&["ip", "link", "set", primary, "up"]);
}

fn with_netkit_default<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&["link", "add", NETKIT_NAME, "type", "netkit"]);
        netkit_bring_up_all(ns, NETKIT_NAME);

        test(ns);
    });
}
