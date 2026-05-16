// SPDX-License-Identifier: MIT

use crate::tests::{NetnsGuard, with_netns};

#[test]
fn test_link_show_veth() {
    with_netns(|ns| {
        let ifname = "tveth0";
        let peer = "tveth0_peer";

        with_veth_iface(ns, ifname, peer, || {
            let expected_output = ns.exec_cmd(&["ip", "link", "show", ifname]);

            let our_output = ns.ip_rs_exec_cmd(&["link", "show", ifname]);

            pretty_assertions::assert_eq!(expected_output, our_output);
        });
    });
}

#[test]
fn test_link_detailed_show_veth() {
    with_netns(|ns| {
        let ifname = "tveth1";
        let peer = "tveth1_peer";

        with_veth_iface(ns, ifname, peer, || {
            let expected_output =
                ns.exec_cmd(&["ip", "-d", "link", "show", ifname]);

            let our_output = ns.ip_rs_exec_cmd(&["-d", "link", "show", ifname]);

            pretty_assertions::assert_eq!(expected_output, our_output);
        });
    });
}

#[test]
fn test_link_show_veth_json() {
    with_netns(|ns| {
        let ifname = "tveth2";
        let peer = "tveth2_peer";

        with_veth_iface(ns, ifname, peer, || {
            let expected_output =
                ns.exec_cmd(&["ip", "-j", "link", "show", ifname]);

            let our_output = ns.ip_rs_exec_cmd(&["-j", "link", "show", ifname]);

            pretty_assertions::assert_eq!(expected_output, our_output);
        });
    });
}

#[test]
fn test_link_detailed_show_veth_json() {
    with_netns(|ns| {
        let ifname = "tveth3";
        let peer = "tveth3_peer";

        with_veth_iface(ns, ifname, peer, || {
            let expected_output =
                ns.exec_cmd(&["ip", "-d", "-j", "link", "show", ifname]);

            let our_output =
                ns.ip_rs_exec_cmd(&["-d", "-j", "link", "show", ifname]);

            pretty_assertions::assert_eq!(expected_output, our_output);
        });
    });
}

fn with_veth_iface<T>(ns: &NetnsGuard, name: &str, peer: &str, test: T)
where
    T: FnOnce(),
{
    ns.ip_rs_exec_cmd(&["link", "add", name, "type", "veth", "peer", peer]);
    ns.exec_cmd(&["ip", "link", "set", name, "up"]);
    ns.exec_cmd(&["ip", "link", "set", peer, "up"]);

    test();
}
