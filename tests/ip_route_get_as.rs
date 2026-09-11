// SPDX-License-Identifier: MIT

mod common;
use self::common::with_dummy_iface_static_ip;

// `as ADDRESS` is only valid for MPLS route lookups: the kernel rejects
// `RTA_NEWDST` of an IPv4 and IPv6 lookup when strict checking is enabled,
// matching iproute2.
#[test]
fn test_route_get_as_address_rejected() {
    with_dummy_iface_static_ip(|ns| {
        let cases: [&[&str]; 3] = [
            &["route", "get", "192.168.1.2", "as", "192.168.1.1"],
            &[
                "-6",
                "route",
                "get",
                "2001:db8:beef::1",
                "as",
                "2001:db8:beef::2",
            ],
            &["route", "get", "192.168.1.2", "as", "to", "192.168.1.1"],
        ];
        for args in cases {
            let stderr = ns.ip_rs_exec_cmd_expect_failure(args);
            assert!(!stderr.trim().is_empty(), "no error message for {args:?}");
        }
    });
}
