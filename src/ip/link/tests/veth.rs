// SPDX-License-Identifier: MIT

use crate::tests::{exec_cmd, ip_rs_exec_cmd};

#[test]
fn test_link_show_veth() {
    let ifname = "tveth0";
    let peer = "tveth0_peer";

    with_veth_iface(ifname, peer, || {
        let expected_output = exec_cmd(&["ip", "link", "show", ifname]);

        let our_output = ip_rs_exec_cmd(&["link", "show", ifname]);

        pretty_assertions::assert_eq!(expected_output, our_output);
    })
}

#[test]
fn test_link_detailed_show_veth() {
    let ifname = "tveth1";
    let peer = "tveth1_peer";

    with_veth_iface(ifname, peer, || {
        let expected_output = exec_cmd(&["ip", "-d", "link", "show", ifname]);

        let our_output = ip_rs_exec_cmd(&["-d", "link", "show", ifname]);

        pretty_assertions::assert_eq!(expected_output, our_output);
    })
}

#[test]
fn test_link_show_veth_json() {
    let ifname = "tveth2";
    let peer = "tveth2_peer";

    with_veth_iface(ifname, peer, || {
        let expected_output = exec_cmd(&["ip", "-j", "link", "show", ifname]);

        let our_output = ip_rs_exec_cmd(&["-j", "link", "show", ifname]);

        pretty_assertions::assert_eq!(expected_output, our_output);
    })
}

#[test]
fn test_link_detailed_show_veth_json() {
    let ifname = "tveth3";
    let peer = "tveth3_peer";

    with_veth_iface(ifname, peer, || {
        let expected_output =
            exec_cmd(&["ip", "-d", "-j", "link", "show", ifname]);

        let our_output = ip_rs_exec_cmd(&["-d", "-j", "link", "show", ifname]);

        pretty_assertions::assert_eq!(expected_output, our_output);
    })
}

fn with_veth_iface<T>(name: &str, peer: &str, test: T)
where
    T: FnOnce() + std::panic::UnwindSafe,
{
    ip_rs_exec_cmd(&["link", "add", name, "type", "veth", "peer", peer]);
    exec_cmd(&["ip", "link", "set", name, "up"]);
    exec_cmd(&["ip", "link", "set", peer, "up"]);

    let result = std::panic::catch_unwind(|| {
        test();
    });

    // clean up (deleting veth removes both ends)
    let _ = exec_cmd(&["ip", "link", "del", name]);

    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}
