// SPDX-License-Identifier: MIT

use rand::RngExt;

use crate::tests::{NetnsGuard, with_netns};

#[test]
fn test_link_show_vxlan() {
    with_netns(|ns| {
        let vxlan_name = "tvxln20";

        with_vxlan_iface(ns, vxlan_name, || {
            let expected_output =
                ns.exec_cmd(&["ip", "link", "show", vxlan_name]);

            let our_output = ns.ip_rs_exec_cmd(&["link", "show", vxlan_name]);

            pretty_assertions::assert_eq!(&expected_output, &our_output);
        });
    })
}

#[test]
fn test_link_detailed_show_vxlan() {
    with_netns(|ns| {
        let vxlan_name = "tvxln10";

        with_vxlan_iface(ns, vxlan_name, || {
            let expected_output =
                ns.exec_cmd(&["ip", "-d", "link", "show", vxlan_name]);

            let our_output =
                ns.ip_rs_exec_cmd(&["-d", "link", "show", vxlan_name]);

            pretty_assertions::assert_eq!(&expected_output, &our_output);
        });
    })
}

fn with_vxlan_iface<T>(ns: &NetnsGuard, vxlan_name: &str, test: T)
where
    T: FnOnce(),
{
    let mut rng = rand::rng();
    let vlan_id: u32 = rng.random_range(1000..10000);
    let dstport: u16 = rng.random_range(20000..60000);

    ns.exec_cmd(&[
        "ip",
        "link",
        "add",
        vxlan_name,
        "address",
        "16:00:14:8a:28:cb",
        "type",
        "vxlan",
        "id",
        &vlan_id.to_string(),
        "dstport",
        &dstport.to_string(),
        "mcroute",
        "df",
        "inherit",
        "ttl",
        "inherit",
    ]);

    ns.exec_cmd(&["ip", "link", "set", vxlan_name, "up"]);

    test();
}
