// SPDX-License-Identifier: MIT

use rand::RngExt;

use crate::tests::{exec_cmd, ip_rs_exec_cmd};

#[test]
fn test_link_show_vxlan() {
    let vxlan_name = "tvxln20";

    with_vxlan_iface(vxlan_name, || {
        let expected_output = exec_cmd(&["ip", "link", "show", vxlan_name]);

        let our_output = ip_rs_exec_cmd(&["link", "show", vxlan_name]);

        pretty_assertions::assert_eq!(&expected_output, &our_output);
    })
}

#[test]
fn test_link_detailed_show_vxlan() {
    let vxlan_name = "tvxln10";

    with_vxlan_iface(vxlan_name, || {
        let expected_output =
            exec_cmd(&["ip", "-d", "link", "show", vxlan_name]);

        let our_output = ip_rs_exec_cmd(&["-d", "link", "show", vxlan_name]);

        pretty_assertions::assert_eq!(&expected_output, &our_output);
    })
}

fn with_vxlan_iface<T>(vxlan_name: &str, test: T)
where
    T: FnOnce() + std::panic::UnwindSafe,
{
    let mut rng = rand::rng();
    let vlan_id: u32 = rng.random_range(1000..10000);
    let dstport: u16 = rng.random_range(20000..60000);

    exec_cmd(&[
        "ip",
        "link",
        "add",
        vxlan_name,
        "type",
        "vxlan",
        "id",
        &vlan_id.to_string(),
        "dstport",
        &dstport.to_string(),
        "mcroute",
    ]);

    exec_cmd(&["ip", "link", "set", vxlan_name, "up"]);

    let result = std::panic::catch_unwind(|| {
        test();
    });

    // clean up
    exec_cmd(&["ip", "link", "del", vxlan_name]);
    assert!(result.is_ok())
}
