// SPDX-License-Identifier: MIT

use super::netns::{NetnsGuard, with_netns};

pub(crate) const DUMMY_NAME: &str = "test-dummy";

pub(crate) fn with_dummy_iface_empty<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        ns.exec_cmd(&["ip", "link", "add", DUMMY_NAME, "type", "dummy"]);
        ns.exec_cmd(&["ip", "link", "set", DUMMY_NAME, "up"]);

        test(ns);
    });
}

pub(crate) fn with_dummy_iface_static_ip<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        ns.exec_cmd(&["ip", "link", "add", DUMMY_NAME, "type", "dummy"]);
        ns.exec_cmd(&["ip", "link", "set", DUMMY_NAME, "up"]);

        ns.exec_cmd(&[
            "ip",
            "addr",
            "add",
            "192.168.1.1/24",
            "dev",
            DUMMY_NAME,
        ]);
        ns.exec_cmd(&[
            "ip",
            "addr",
            "add",
            "192.168.1.2/24",
            "dev",
            DUMMY_NAME,
        ]);
        ns.exec_cmd(&["ip", "addr", "add", "ff::ab:cd/64", "dev", DUMMY_NAME]);
        ns.exec_cmd(&[
            "ip",
            "addr",
            "add",
            "2001:db8:beef::1/64",
            "dev",
            DUMMY_NAME,
            "valid_lft",
            "21384",
            "preferred_lft",
            "21384",
            "scope",
            "global",
            "mngtmpaddr",
            "proto",
            "kernel_ra",
        ]);
        ns.exec_cmd(&[
            "ip",
            "addr",
            "add",
            "2001:db8:beef::2/64",
            "dev",
            DUMMY_NAME,
            "valid_lft",
            "21381",
            "preferred_lft",
            "21381",
            "scope",
            "global",
            "home",
            "proto",
            "kernel_ra",
        ]);

        test(ns);
    });
}
