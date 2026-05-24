// SPDX-License-Identifier: MIT

use crate::tests::{exec_cmd, ip_rs_exec_cmd};

#[test]
fn test_link_show_vlan() {
    let vlan_name = "tvlan20";

    with_vlan_iface(vlan_name, &[], || {
        let expected_output = exec_cmd(&["ip", "link", "show", vlan_name]);

        let our_output = ip_rs_exec_cmd(&["link", "show", vlan_name]);

        pretty_assertions::assert_eq!(&expected_output, &our_output);
    })
}

#[test]
fn test_link_detailed_show_vlan() {
    let vlan_name = "tvlan10";

    with_vlan_iface(vlan_name, &[], || {
        let expected_output =
            exec_cmd(&["ip", "-d", "link", "show", vlan_name]);

        let our_output = ip_rs_exec_cmd(&["-d", "link", "show", vlan_name]);

        pretty_assertions::assert_eq!(&expected_output, &our_output);
    })
}

#[test]
fn test_vlan_protocol() {
    let vlan_name = "tvlan_proto";

    with_vlan_iface(vlan_name, &["protocol", "802.1ad"], || {
        let expected_output =
            exec_cmd(&["ip", "-d", "link", "show", vlan_name]);

        let our_output = ip_rs_exec_cmd(&["-d", "link", "show", vlan_name]);

        assert!(expected_output.contains("protocol 802.1ad"));

        pretty_assertions::assert_eq!(&expected_output, &our_output);
    })
}

#[test]
fn test_vlan_reorder_hdr_on() {
    let vlan_name = "tvlan_rh_on";

    with_vlan_iface(vlan_name, &["reorder_hdr", "on"], || {
        let expected_output =
            exec_cmd(&["ip", "-d", "link", "show", vlan_name]);

        let our_output = ip_rs_exec_cmd(&["-d", "link", "show", vlan_name]);

        assert!(expected_output.contains("REORDER_HDR"));

        pretty_assertions::assert_eq!(&expected_output, &our_output);
    })
}

#[test]
fn test_vlan_reorder_hdr_off() {
    let vlan_name = "tvlan_rh_off";

    with_vlan_iface(vlan_name, &["reorder_hdr", "off"], || {
        let expected_output =
            exec_cmd(&["ip", "-d", "link", "show", vlan_name]);

        let our_output = ip_rs_exec_cmd(&["-d", "link", "show", vlan_name]);

        assert!(!expected_output.contains("REORDER_HDR"));

        pretty_assertions::assert_eq!(&expected_output, &our_output);
    })
}

#[test]
fn test_vlan_gvrp_on() {
    let vlan_name = "tvlan_gvrp_on";

    with_vlan_iface(vlan_name, &["gvrp", "on"], || {
        let expected_output =
            exec_cmd(&["ip", "-d", "link", "show", vlan_name]);

        let our_output = ip_rs_exec_cmd(&["-d", "link", "show", vlan_name]);

        assert!(expected_output.contains("GVRP"));

        pretty_assertions::assert_eq!(&expected_output, &our_output);
    })
}

#[test]
fn test_vlan_gvrp_off() {
    let vlan_name = "tvlan_gvrp_off";

    with_vlan_iface(vlan_name, &["gvrp", "off"], || {
        let expected_output =
            exec_cmd(&["ip", "-d", "link", "show", vlan_name]);

        let our_output = ip_rs_exec_cmd(&["-d", "link", "show", vlan_name]);

        assert!(!expected_output.contains("GVRP"));

        pretty_assertions::assert_eq!(&expected_output, &our_output);
    })
}

#[test]
fn test_vlan_mvrp_on() {
    let vlan_name = "tvlan_mvrp_on";

    with_vlan_iface(vlan_name, &["mvrp", "on"], || {
        let expected_output =
            exec_cmd(&["ip", "-d", "link", "show", vlan_name]);

        let our_output = ip_rs_exec_cmd(&["-d", "link", "show", vlan_name]);

        assert!(expected_output.contains("MVRP"));

        pretty_assertions::assert_eq!(&expected_output, &our_output);
    })
}

#[test]
fn test_vlan_mvrp_off() {
    let vlan_name = "tvlan_mvrp_off";

    with_vlan_iface(vlan_name, &["mvrp", "off"], || {
        let expected_output =
            exec_cmd(&["ip", "-d", "link", "show", vlan_name]);

        let our_output = ip_rs_exec_cmd(&["-d", "link", "show", vlan_name]);

        assert!(!expected_output.contains("MVRP"));

        pretty_assertions::assert_eq!(&expected_output, &our_output);
    })
}

#[test]
fn test_vlan_loose_binding_on() {
    let vlan_name = "tvlan_lb_on";

    with_vlan_iface(vlan_name, &["loose_binding", "on"], || {
        let expected_output =
            exec_cmd(&["ip", "-d", "link", "show", vlan_name]);

        let our_output = ip_rs_exec_cmd(&["-d", "link", "show", vlan_name]);

        assert!(expected_output.contains("LOOSE_BINDING"));

        pretty_assertions::assert_eq!(&expected_output, &our_output);
    })
}

#[test]
fn test_vlan_loose_binding_off() {
    let vlan_name = "tvlan_lb_off";

    with_vlan_iface(vlan_name, &["loose_binding", "off"], || {
        let expected_output =
            exec_cmd(&["ip", "-d", "link", "show", vlan_name]);

        let our_output = ip_rs_exec_cmd(&["-d", "link", "show", vlan_name]);

        assert!(!expected_output.contains("LOOSE_BINDING"));

        pretty_assertions::assert_eq!(&expected_output, &our_output);
    })
}

#[test]
fn test_vlan_bridge_binding_on() {
    let vlan_name = "tvlan_bb_on";

    with_vlan_iface(vlan_name, &["bridge_binding", "on"], || {
        let expected_output =
            exec_cmd(&["ip", "-d", "link", "show", vlan_name]);

        let our_output = ip_rs_exec_cmd(&["-d", "link", "show", vlan_name]);

        assert!(expected_output.contains("BRIDGE_BINDING"));

        pretty_assertions::assert_eq!(&expected_output, &our_output);
    })
}

#[test]
fn test_vlan_bridge_binding_off() {
    let vlan_name = "tvlan_bb_off";

    with_vlan_iface(vlan_name, &["bridge_binding", "off"], || {
        let expected_output =
            exec_cmd(&["ip", "-d", "link", "show", vlan_name]);

        let our_output = ip_rs_exec_cmd(&["-d", "link", "show", vlan_name]);

        assert!(!expected_output.contains("BRIDGE_BINDING"));

        pretty_assertions::assert_eq!(&expected_output, &our_output);
    })
}

#[test]
fn test_vlan_all_flags_on() {
    let vlan_name = "tvn_all_flg";

    with_vlan_iface(
        vlan_name,
        &[
            "protocol",
            "802.1ad",
            "reorder_hdr",
            "on",
            "gvrp",
            "on",
            "loose_binding",
            "on",
            "bridge_binding",
            "on",
        ],
        || {
            let expected_output =
                exec_cmd(&["ip", "-d", "link", "show", vlan_name]);

            let our_output = ip_rs_exec_cmd(&["-d", "link", "show", vlan_name]);

            assert!(expected_output.contains("protocol 802.1ad"));
            assert!(expected_output.contains("REORDER_HDR"));
            assert!(expected_output.contains("GVRP"));
            assert!(expected_output.contains("LOOSE_BINDING"));
            assert!(expected_output.contains("BRIDGE_BINDING"));

            pretty_assertions::assert_eq!(&expected_output, &our_output);
        },
    )
}

fn with_vlan_iface<T>(vlan_name: &str, opts: &[&str], test: T)
where
    T: FnOnce() + std::panic::UnwindSafe,
{
    let parent_name = format!("p{vlan_name}");

    // create parent dummy interface using ip-rs
    ip_rs_exec_cmd(&[
        "link",
        "add",
        &parent_name,
        "address",
        "0e:d1:49:08:27:84",
        "type",
        "dummy",
    ]);
    exec_cmd(&["ip", "link", "set", &parent_name, "up"]);

    let mut args = vec![
        "link",
        "add",
        "link",
        &parent_name,
        "name",
        vlan_name,
        "type",
        "vlan",
        "id",
        "100",
    ];

    args.extend_from_slice(opts);

    ip_rs_exec_cmd(&args);
    exec_cmd(&["ip", "link", "set", vlan_name, "up"]);

    let result = std::panic::catch_unwind(|| {
        test();
    });

    // clean up
    exec_cmd(&["ip", "link", "del", vlan_name]);
    exec_cmd(&["ip", "link", "del", &parent_name]);
    assert!(result.is_ok())
}
