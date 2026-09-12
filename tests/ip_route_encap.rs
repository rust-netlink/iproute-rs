// SPDX-License-Identifier: MIT

mod common;
use self::common::{NetnsGuard, with_netns};

const DUMMY_NAME: &str = "test-dummy";

fn setup_interface(ns: &NetnsGuard) {
    ns.exec_cmd(&["ip", "link", "add", DUMMY_NAME, "type", "dummy"]);
    ns.exec_cmd(&["ip", "link", "set", DUMMY_NAME, "up"]);
    ns.exec_cmd(&["ip", "addr", "add", "10.0.0.1/24", "dev", DUMMY_NAME]);
    ns.exec_cmd(&["ip", "addr", "add", "2001:db8::1/64", "dev", DUMMY_NAME]);
}

fn assert_route_show_eq(ns: &NetnsGuard, args: &[&str]) {
    ns.assert_eq_output(args);
    let mut json_args = vec!["-j"];
    json_args.extend_from_slice(args);
    ns.assert_eq_output(&json_args);
}

// `ip-rs` must accept the same `encap` arguments as `iproute2` and push the
// same encapsulation to the kernel.
fn assert_ip_rs_add_show_eq(
    ns: &NetnsGuard,
    add_args: &[&str],
    show_args: &[&str],
) {
    ns.ip_rs_exec_cmd(add_args);
    assert_route_show_eq(ns, show_args);
}

// MPLS encapsulation pushes a label stack.
#[test]
fn test_route_show_encap_mpls() {
    with_netns(|ns| {
        setup_interface(ns);
        ns.exec_cmd(&[
            "ip",
            "route",
            "add",
            "10.106.0.0/16",
            "encap",
            "mpls",
            "100/200",
            "dev",
            DUMMY_NAME,
        ]);

        assert_route_show_eq(ns, &["route", "show", "10.106.0.0/16"]);
    });
}

// IPv6 encapsulation of an IPv6 route.
#[test]
fn test_route_show_encap_ip6() {
    with_netns(|ns| {
        setup_interface(ns);
        ns.exec_cmd(&[
            "ip",
            "-6",
            "route",
            "add",
            "2001:db8:5::/64",
            "encap",
            "ip6",
            "id",
            "101",
            "dst",
            "2001:db8::2",
            "dev",
            DUMMY_NAME,
        ]);

        assert_route_show_eq(ns, &["-6", "route", "show", "2001:db8:5::/64"]);
    });
}

// SRv6 encapsulation with a segment list.
#[test]
fn test_route_show_encap_seg6() {
    with_netns(|ns| {
        setup_interface(ns);
        ns.exec_cmd(&[
            "ip",
            "-6",
            "route",
            "add",
            "2001:db8:2::/64",
            "encap",
            "seg6",
            "mode",
            "encap",
            "segs",
            "2001:db8::2,2001:db8::3",
            "dev",
            DUMMY_NAME,
        ]);

        assert_route_show_eq(ns, &["-6", "route", "show", "2001:db8:2::/64"]);
    });
}

// IPv4 encapsulation of an IPv4 route with tunnel flags.
#[test]
fn test_route_show_encap_ip() {
    with_netns(|ns| {
        setup_interface(ns);
        ns.exec_cmd(&[
            "ip",
            "route",
            "add",
            "10.115.0.0/16",
            "encap",
            "ip",
            "id",
            "200",
            "src",
            "10.0.0.1",
            "dst",
            "10.0.0.3",
            "ttl",
            "64",
            "tos",
            "8",
            "key",
            "csum",
            "dev",
            DUMMY_NAME,
        ]);

        assert_route_show_eq(ns, &["route", "show", "10.115.0.0/16"]);
    });
}

// The kernel requires the output interface of an xfrm encapsulation to be an
// xfrm interface.
#[test]
fn test_route_show_encap_xfrm() {
    with_netns(|ns| {
        setup_interface(ns);
        ns.exec_cmd(&[
            "ip",
            "link",
            "add",
            "test-xfrm0",
            "type",
            "xfrm",
            "if_id",
            "1",
        ]);
        ns.exec_cmd(&["ip", "link", "set", "test-xfrm0", "up"]);
        assert_ip_rs_add_show_eq(
            ns,
            &[
                "route",
                "add",
                "10.116.0.0/16",
                "dev",
                "test-xfrm0",
                "encap",
                "xfrm",
                "if_id",
                "1",
                "link_dev",
                "test-xfrm0",
            ],
            &["route", "show", "10.116.0.0/16"],
        );
    });
}

#[test]
fn test_route_add_encap_mpls() {
    with_netns(|ns| {
        setup_interface(ns);
        assert_ip_rs_add_show_eq(
            ns,
            &[
                "route",
                "add",
                "10.120.0.0/16",
                "encap",
                "mpls",
                "100/200",
                "ttl",
                "64",
                "dev",
                DUMMY_NAME,
            ],
            &["route", "show", "10.120.0.0/16"],
        );
    });
}

#[test]
fn test_route_add_encap_ip() {
    with_netns(|ns| {
        setup_interface(ns);
        assert_ip_rs_add_show_eq(
            ns,
            &[
                "route",
                "add",
                "10.121.0.0/16",
                "encap",
                "ip",
                "id",
                "200",
                "dst",
                "10.0.0.3",
                "src",
                "10.0.0.1",
                "ttl",
                "64",
                "tos",
                "8",
                "key",
                "csum",
                "seq",
                "dev",
                DUMMY_NAME,
            ],
            &["route", "show", "10.121.0.0/16"],
        );
    });
}

#[test]
fn test_route_add_encap_ip6() {
    with_netns(|ns| {
        setup_interface(ns);
        assert_ip_rs_add_show_eq(
            ns,
            &[
                "-6",
                "route",
                "add",
                "2001:db8:20::/64",
                "encap",
                "ip6",
                "id",
                "100",
                "dst",
                "2001:db8::2",
                "src",
                "2001:db8::3",
                "tc",
                "7",
                "hoplimit",
                "253",
                "csum",
                "dev",
                DUMMY_NAME,
            ],
            &["-6", "route", "show", "2001:db8:20::/64"],
        );
    });
}

#[test]
fn test_route_add_encap_seg6() {
    with_netns(|ns| {
        setup_interface(ns);
        assert_ip_rs_add_show_eq(
            ns,
            &[
                "-6",
                "route",
                "add",
                "2001:db8:21::/64",
                "encap",
                "seg6",
                "mode",
                "encap",
                "segs",
                "2001:db8::2,2001:db8::3",
                "dev",
                DUMMY_NAME,
            ],
            &["-6", "route", "show", "2001:db8:21::/64"],
        );
    });
}

// Inline mode has a trailing zeroed segment which `iproute2` prints.
#[test]
fn test_route_add_encap_seg6_inline() {
    with_netns(|ns| {
        setup_interface(ns);
        assert_ip_rs_add_show_eq(
            ns,
            &[
                "-6",
                "route",
                "add",
                "2001:db8:22::/64",
                "encap",
                "seg6",
                "mode",
                "inline",
                "segs",
                "2001:db8::4",
                "dev",
                DUMMY_NAME,
            ],
            &["-6", "route", "show", "2001:db8:22::/64"],
        );
    });
}

#[test]
fn test_route_replace_and_delete_encap() {
    with_netns(|ns| {
        setup_interface(ns);
        assert_ip_rs_add_show_eq(
            ns,
            &[
                "route",
                "add",
                "10.122.0.0/16",
                "encap",
                "ip",
                "id",
                "1",
                "dst",
                "10.0.0.2",
                "dev",
                DUMMY_NAME,
            ],
            &["route", "show", "10.122.0.0/16"],
        );
        assert_ip_rs_add_show_eq(
            ns,
            &[
                "route",
                "replace",
                "10.122.0.0/16",
                "encap",
                "ip",
                "id",
                "2",
                "dst",
                "10.0.0.3",
                "dev",
                DUMMY_NAME,
            ],
            &["route", "show", "10.122.0.0/16"],
        );
        ns.ip_rs_exec_cmd(&[
            "route",
            "del",
            "10.122.0.0/16",
            "encap",
            "ip",
            "id",
            "2",
            "dst",
            "10.0.0.3",
            "dev",
            DUMMY_NAME,
        ]);
        assert_eq!(ns.ip_rs_exec_cmd(&["route", "show", "10.122.0.0/16"]), "");
    });
}

// SRv6 local encapsulation with an `End` action.
#[test]
fn test_route_show_encap_seg6local_end() {
    with_netns(|ns| {
        setup_interface(ns);
        ns.exec_cmd(&[
            "ip",
            "-6",
            "route",
            "add",
            "2001:db8:7::/64",
            "encap",
            "seg6local",
            "action",
            "End",
            "dev",
            DUMMY_NAME,
        ]);

        assert_route_show_eq(ns, &["-6", "route", "show", "2001:db8:7::/64"]);
    });
}

// SRv6 local encapsulation with `nh4`, `nh6` and `table` options.
#[test]
fn test_route_show_encap_seg6local_options() {
    with_netns(|ns| {
        setup_interface(ns);
        for (prefix, action, extra) in [
            ("2001:db8:8::/64", "End.DX4", vec!["nh4", "10.0.0.2"]),
            ("2001:db8:9::/64", "End.DX6", vec!["nh6", "2001:db8::2"]),
            ("2001:db8:a::/64", "End.DT6", vec!["table", "100"]),
            // `vrftable` is not tested here: the kernel rejects it without
            // the VRF strict mode and a VRF device of that table.
        ] {
            let mut add_args = vec![
                "ip",
                "-6",
                "route",
                "add",
                prefix,
                "encap",
                "seg6local",
                "action",
                action,
            ];
            add_args.extend_from_slice(&extra);
            add_args.push("dev");
            add_args.push(DUMMY_NAME);
            ns.exec_cmd(&add_args);

            assert_route_show_eq(ns, &["-6", "route", "show", prefix]);
        }
    });
}

// SRv6 local encapsulation with a segment routing header, `ip-rs` must
// build the same SRH as iproute2.
#[test]
fn test_route_show_encap_seg6local_srh() {
    with_netns(|ns| {
        setup_interface(ns);
        ns.ip_rs_exec_cmd(&[
            "-6",
            "route",
            "add",
            "2001:db8:c::/64",
            "encap",
            "seg6local",
            "action",
            "End.B6.Encaps",
            "srh",
            "segs",
            "2001:db8::2,2001:db8::3",
            "dev",
            DUMMY_NAME,
        ]);

        assert_route_show_eq(ns, &["-6", "route", "show", "2001:db8:c::/64"]);
    });
}

// RPL encapsulation with a segment list.
//
// Ignored because RPL LWT is optional in the kernel: without
// CONFIG_IPV6_RPL_LWTUNNEL, adding the route fails with EOPNOTSUPP.
#[test]
#[ignore = "requires a kernel built with CONFIG_IPV6_RPL_LWTUNNEL"]
fn test_route_show_encap_rpl() {
    with_netns(|ns| {
        setup_interface(ns);
        ns.exec_cmd(&[
            "ip",
            "-6",
            "route",
            "add",
            "2001:db8:60::/64",
            "encap",
            "rpl",
            "segs",
            "2001:db8::2,2001:db8::3",
            "dev",
            DUMMY_NAME,
        ]);

        assert_route_show_eq(ns, &["-6", "route", "show", "2001:db8:60::/64"]);
    });
}

#[test]
#[ignore = "requires a kernel built with CONFIG_IPV6_RPL_LWTUNNEL"]
fn test_route_add_encap_rpl() {
    with_netns(|ns| {
        setup_interface(ns);
        assert_ip_rs_add_show_eq(
            ns,
            &[
                "-6",
                "route",
                "add",
                "2001:db8:61::/64",
                "encap",
                "rpl",
                "segs",
                "2001:db8::2,2001:db8::3",
                "dev",
                DUMMY_NAME,
            ],
            &["-6", "route", "show", "2001:db8:61::/64"],
        );
    });
}

// IOAM6 encapsulation in encapsulating mode with a source and a trace.
#[test]
fn test_route_show_encap_ioam6() {
    with_netns(|ns| {
        setup_interface(ns);
        ns.exec_cmd(&[
            "ip",
            "-6",
            "route",
            "add",
            "2001:db8:62::/64",
            "encap",
            "ioam6",
            "freq",
            "2/3",
            "mode",
            "encap",
            "tunsrc",
            "2001:db8::8",
            "tundst",
            "2001:db8::9",
            "trace",
            "prealloc",
            "type",
            "0x800000",
            "ns",
            "7",
            "size",
            "8",
            "dev",
            DUMMY_NAME,
        ]);

        assert_route_show_eq(ns, &["-6", "route", "show", "2001:db8:62::/64"]);
    });
}

#[test]
fn test_route_add_encap_ioam6() {
    with_netns(|ns| {
        setup_interface(ns);
        assert_ip_rs_add_show_eq(
            ns,
            &[
                "-6",
                "route",
                "add",
                "2001:db8:63::/64",
                "encap",
                "ioam6",
                "mode",
                "encap",
                "tundst",
                "2001:db8::9",
                "trace",
                "prealloc",
                "type",
                "0x800000",
                "ns",
                "1",
                "size",
                "4",
                "dev",
                DUMMY_NAME,
            ],
            &["-6", "route", "show", "2001:db8:63::/64"],
        );
    });
}

// IOAM6 encapsulation in inline mode does not need a tunnel destination.
#[test]
fn test_route_add_encap_ioam6_inline() {
    with_netns(|ns| {
        setup_interface(ns);
        assert_ip_rs_add_show_eq(
            ns,
            &[
                "-6",
                "route",
                "add",
                "2001:db8:64::/64",
                "encap",
                "ioam6",
                "mode",
                "inline",
                "trace",
                "prealloc",
                "type",
                "0x800000",
                "ns",
                "1",
                "size",
                "4",
                "dev",
                DUMMY_NAME,
            ],
            &["-6", "route", "show", "2001:db8:64::/64"],
        );
    });
}

// `tunsrc` sets the source address of the SRv6 encapsulation.
#[test]
fn test_route_add_encap_seg6_tunsrc() {
    with_netns(|ns| {
        setup_interface(ns);
        assert_ip_rs_add_show_eq(
            ns,
            &[
                "-6",
                "route",
                "add",
                "2001:db8:65::/64",
                "encap",
                "seg6",
                "mode",
                "encap",
                "segs",
                "2001:db8::2,2001:db8::3",
                "tunsrc",
                "2001:db8::9",
                "dev",
                DUMMY_NAME,
            ],
            &["-6", "route", "show", "2001:db8:65::/64"],
        );
    });
}

// `hmac` appends the SRv6 HMAC TLV to the segment routing header.
#[test]
fn test_route_add_encap_seg6_hmac() {
    with_netns(|ns| {
        setup_interface(ns);
        assert_ip_rs_add_show_eq(
            ns,
            &[
                "-6",
                "route",
                "add",
                "2001:db8:66::/64",
                "encap",
                "seg6",
                "mode",
                "encap",
                "segs",
                "2001:db8::2",
                "hmac",
                "1234",
                "tunsrc",
                "2001:db8::9",
                "dev",
                DUMMY_NAME,
            ],
            &["-6", "route", "show", "2001:db8:66::/64"],
        );
    });
}

// `vxlan_opts` of `encap ip` sets the VXLAN GBP.
#[test]
fn test_route_add_encap_ip_vxlan_opts() {
    with_netns(|ns| {
        setup_interface(ns);
        assert_ip_rs_add_show_eq(
            ns,
            &[
                "route",
                "add",
                "10.41.0.0/16",
                "encap",
                "ip",
                "id",
                "300",
                "vxlan_opts",
                "100",
                "dev",
                DUMMY_NAME,
            ],
            &["route", "show", "10.41.0.0/16"],
        );
    });
}

// `erspan_opts` of `encap ip` sets the ERSPAN metadata.
#[test]
fn test_route_add_encap_ip_erspan_opts() {
    with_netns(|ns| {
        setup_interface(ns);
        assert_ip_rs_add_show_eq(
            ns,
            &[
                "route",
                "add",
                "10.42.0.0/16",
                "encap",
                "ip",
                "id",
                "300",
                "erspan_opts",
                "1:2:3:4",
                "dev",
                DUMMY_NAME,
            ],
            &["route", "show", "10.42.0.0/16"],
        );
    });
}

// `geneve_opts` of `encap ip` sets the Geneve option list.
//
// Ignored until the kernel is fixed:
// https://lore.kernel.org/netdev/20260912055304.1415016-1-cnfourt@gmail.com/
#[test]
#[ignore = "kernel panic bug in `ip_tun_parse_opts_geneve()`"]
fn test_route_add_encap_ip_geneve_opts() {
    with_netns(|ns| {
        setup_interface(ns);
        assert_ip_rs_add_show_eq(
            ns,
            &[
                "route",
                "add",
                "10.40.0.0/16",
                "encap",
                "ip",
                "id",
                "300",
                "geneve_opts",
                "0x1234:0x42:11223344,0x2020:0x1:deadbeef",
                "dev",
                DUMMY_NAME,
            ],
            &["route", "show", "10.40.0.0/16"],
        );
    });
}

// `geneve_opts` of `encap ip6` sets the Geneve option list.
// Ignored until the kernel is fixed:
// https://lore.kernel.org/netdev/20260912055304.1415016-1-cnfourt@gmail.com/
#[test]
#[ignore = "kernel panic bug in `ip_tun_parse_opts_geneve()`"]
fn test_route_add_encap_ip6_geneve_opts() {
    with_netns(|ns| {
        setup_interface(ns);
        assert_ip_rs_add_show_eq(
            ns,
            &[
                "-6",
                "route",
                "add",
                "2001:db8:71::/64",
                "encap",
                "ip6",
                "id",
                "300",
                "geneve_opts",
                "0x1234:0x42:11223344",
                "dev",
                DUMMY_NAME,
            ],
            &["-6", "route", "show", "2001:db8:71::/64"],
        );
    });
}
