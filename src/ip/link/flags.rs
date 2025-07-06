// SPDX-License-Identifier: MIT

use rtnetlink::packet_route::link::LinkFlags;

// Defined in iproute2 `print_link_flags()` function.
const IPROUTE2_FLAGS_ORDER: [LinkFlags; 18] = [
    LinkFlags::Loopback,
    LinkFlags::Broadcast,
    LinkFlags::Pointopoint,
    LinkFlags::Multicast,
    LinkFlags::Noarp,
    LinkFlags::Allmulti,
    LinkFlags::Promisc,
    LinkFlags::Controller,
    LinkFlags::Port,
    LinkFlags::Debug,
    LinkFlags::Dynamic,
    LinkFlags::Automedia,
    LinkFlags::Portsel,
    LinkFlags::Notrailers,
    LinkFlags::Up,
    LinkFlags::LowerUp,
    LinkFlags::Dormant,
    LinkFlags::Echo,
];

/// Convert [LinkFlags] to Vec<String> using iproute2 order
pub fn link_flags_to_string(mut flags: LinkFlags) -> Vec<String> {
    let mut ret: Vec<String> = Vec::new();

    if flags.contains(LinkFlags::Up) && !flags.contains(LinkFlags::Running) {
        ret.push("NO-CARRIER".into())
    }

    flags.remove(LinkFlags::Running);

    for flag in IPROUTE2_FLAGS_ORDER {
        if flags.contains(flag) {
            if flag == LinkFlags::Port {
                // Compatible with iproute2, but we still append `PORT` after
                // iproute2 flags.
                ret.push("SLAVE".into());
            } else if flag == LinkFlags::Controller {
                // Compatible with iproute2, but we still append `CONTROLLER`
                // after iproute2 flags.
                ret.push("MASTER".into());
            } else if flag == LinkFlags::LowerUp {
                ret.push("LOWER_UP".into());
                flags.remove(flag)
            } else {
                ret.push(flag.to_string().to_uppercase());
                flags.remove(flag)
            }
        }
    }

    for remain_flag in flags.iter() {
        ret.push(remain_flag.to_string().to_uppercase());
    }

    ret
}
