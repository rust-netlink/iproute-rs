// SPDX-License-Identifier: MIT

use crate::tests::with_netns;

fn normalize_tabs(s: String) -> String {
    s.replace('\t', "        ")
}

macro_rules! test_link_help {
    ($name:ident, $type:expr) => {
        #[test]
        fn $name() {
            with_netns(|ns| {
                ns.assert_eq_output_map(
                    &["link", "help", $type],
                    normalize_tabs,
                );
            });
        }
    };
}

test_link_help!(test_link_help_sit, "sit");
test_link_help!(test_link_help_bond, "bond");
test_link_help!(test_link_help_bridge, "bridge");
test_link_help!(test_link_help_dummy, "dummy");
test_link_help!(test_link_help_geneve, "geneve");
test_link_help!(test_link_help_gre, "gre");
test_link_help!(test_link_help_gretap, "gretap");
test_link_help!(test_link_help_gtp, "gtp");
test_link_help!(test_link_help_hsr, "hsr");
test_link_help!(test_link_help_ip6gre, "ip6gre");
test_link_help!(test_link_help_ip6gretap, "ip6gretap");
test_link_help!(test_link_help_ip6tnl, "ip6tnl");
test_link_help!(test_link_help_ipip, "ipip");
test_link_help!(test_link_help_ipvlan, "ipvlan");
test_link_help!(test_link_help_ipvtap, "ipvtap");
test_link_help!(test_link_help_macsec, "macsec");
test_link_help!(test_link_help_macvlan, "macvlan");
test_link_help!(test_link_help_macvtap, "macvtap");
test_link_help!(test_link_help_netkit, "netkit");
test_link_help!(test_link_help_team, "team");
test_link_help!(test_link_help_netdevsim, "netdevsim");
test_link_help!(test_link_help_nlmon, "nlmon");
test_link_help!(test_link_help_vcan, "vcan");
test_link_help!(test_link_help_veth, "veth");
test_link_help!(test_link_help_vlan, "vlan");
test_link_help!(test_link_help_vrf, "vrf");
test_link_help!(test_link_help_vxcan, "vxcan");
test_link_help!(test_link_help_vxlan, "vxlan");
test_link_help!(test_link_help_bareudp, "bareudp");
test_link_help!(test_link_help_batadv, "batadv");
test_link_help!(test_link_help_can, "can");
test_link_help!(test_link_help_bond_port, "bond_slave");
test_link_help!(test_link_help_bridge_port, "bridge_slave");
test_link_help!(test_link_help_virt_wifi, "virt_wifi");
test_link_help!(test_link_help_wwan, "wwan");
test_link_help!(test_link_help_xfrm, "xfrm");
