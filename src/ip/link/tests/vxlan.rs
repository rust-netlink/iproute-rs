// SPDX-License-Identifier: MIT

use rand::RngExt;

use crate::tests::{NetnsGuard, with_netns};

const VXLAN_NAME: &str = "tvxln";

#[test]
fn test_link_show_vxlan() {
    with_vxlan_iface(|ns| {
        ns.assert_eq_output(&["link", "show", VXLAN_NAME]);
    });
}

#[test]
fn test_link_detailed_show_vxlan() {
    with_vxlan_iface(|ns| {
        ns.assert_eq_output(&["-d", "link", "show", VXLAN_NAME]);
    });
}

fn with_vxlan_iface<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        let mut rng = rand::rng();
        let vlan_id: u32 = rng.random_range(1000..10000);
        let dstport: u16 = rng.random_range(20000..60000);

        ns.exec_cmd(&[
            "ip",
            "link",
            "add",
            VXLAN_NAME,
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

        ns.exec_cmd(&["ip", "link", "set", VXLAN_NAME, "up"]);

        test(ns);
    });
}
