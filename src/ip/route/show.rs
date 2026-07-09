// SPDX-License-Identifier: MIT

use std::{collections::HashMap, net::IpAddr};

use futures_util::TryStreamExt;
use iproute_rs::{CanDisplay, CanOutput, CliColor, write_with_color};
use rtnetlink::packet_route::{
    AddressFamily,
    route::{
        RouteAttribute, RouteCacheInfo, RouteFlags, RouteHeader, RouteMessage,
        RouteNextHopFlags, RoutePreference, RouteProtocol, RouteScope,
        RouteType,
    },
};
use serde::Serialize;

use crate::CliError;

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Serialize, Default)]
pub(crate) struct CliRouteInfo {
    #[serde(skip)]
    family: AddressFamily,
    #[serde(skip)]
    cloned: bool,
    #[serde(skip_serializing_if = "Option::is_none", rename = "type")]
    kind: Option<String>,
    dst: String,
    #[serde(skip)]
    dst_len: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    src: Option<String>,
    #[serde(skip)]
    src_len: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    gateway: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "dev")]
    oif: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    table: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    prefsrc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metric: Option<u32>,
    flags: Vec<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mark: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    uid: Option<u32>,
    #[serde(skip)]
    cache_info: Option<RouteCacheInfo>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "pref")]
    preference: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tos: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iif: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl_propagate: Option<bool>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    nexthops: Vec<CliRouteNextHop>,
}

#[derive(Serialize, Default)]
struct CliRouteNextHop {
    #[serde(skip_serializing_if = "Option::is_none")]
    gateway: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "dev")]
    oif: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    weight: Option<u32>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    flags: String,
}

const ROUTE_FLAG_DATA: &[(&str, RouteFlags)] = &[
    ("dead", RouteFlags::Dead),
    ("onlink", RouteFlags::Onlink),
    ("pervasive", RouteFlags::Pervasive),
    ("offload", RouteFlags::Offload),
    ("trap", RouteFlags::Trap),
    ("notify", RouteFlags::Notify),
    ("linkdown", RouteFlags::Linkdown),
    ("unresolved", RouteFlags::Unresolved),
    ("rt_offload", RouteFlags::RtOffload),
    ("rt_trap", RouteFlags::RtTrap),
    ("offload_failed", RouteFlags::OffloadFailed),
];

fn route_flags_to_strings(flags: RouteFlags) -> Vec<&'static str> {
    let mut result = Vec::new();
    for (name, mask) in ROUTE_FLAG_DATA {
        if flags.contains(*mask) {
            result.push(*name);
        }
    }
    result
}

fn route_type_to_string(t: RouteType) -> String {
    match t {
        RouteType::Unspec => "unspec".into(),
        RouteType::Unicast => "unicast".into(),
        RouteType::Local => "local".into(),
        RouteType::Broadcast => "broadcast".into(),
        RouteType::Anycast => "anycast".into(),
        RouteType::Multicast => "multicast".into(),
        RouteType::BlackHole => "blackhole".into(),
        RouteType::Unreachable => "unreachable".into(),
        RouteType::Prohibit => "prohibit".into(),
        RouteType::Throw => "throw".into(),
        RouteType::Nat => "nat".into(),
        RouteType::ExternalResolve => "xresolve".into(),
        RouteType::Other(v) => v.to_string(),
        _ => "unknown".into(),
    }
}

fn route_protocol_to_string(p: RouteProtocol) -> String {
    match p {
        RouteProtocol::Unspec => "unspec".into(),
        RouteProtocol::IcmpRedirect => "redirect".into(),
        RouteProtocol::Kernel => "kernel".into(),
        RouteProtocol::Boot => "boot".into(),
        RouteProtocol::Static => "static".into(),
        RouteProtocol::Gated => "gated".into(),
        RouteProtocol::Ra => "ra".into(),
        RouteProtocol::Mrt => "mrt".into(),
        RouteProtocol::Zebra => "zebra".into(),
        RouteProtocol::Bird => "bird".into(),
        RouteProtocol::DnRouted => "dnrouted".into(),
        RouteProtocol::Xorp => "xorp".into(),
        RouteProtocol::Ntk => "ntk".into(),
        RouteProtocol::Dhcp => "dhcp".into(),
        RouteProtocol::Mrouted => "mrouted".into(),
        RouteProtocol::KeepAlived => "keepalived".into(),
        RouteProtocol::Babel => "babel".into(),
        RouteProtocol::Bgp => "bgp".into(),
        RouteProtocol::Isis => "isis".into(),
        RouteProtocol::Ospf => "ospf".into(),
        RouteProtocol::Rip => "rip".into(),
        RouteProtocol::Eigrp => "eigrp".into(),
        RouteProtocol::Other(v) => v.to_string(),
        _ => "unknown".into(),
    }
}

fn route_scope_to_string(s: RouteScope) -> String {
    match s {
        RouteScope::Universe => "global".into(),
        RouteScope::Site => "site".into(),
        RouteScope::Link => "link".into(),
        RouteScope::Host => "host".into(),
        RouteScope::NoWhere => "nowhere".into(),
        RouteScope::Other(v) => v.to_string(),
        _ => "unknown".into(),
    }
}

fn route_preference_to_string(p: RoutePreference) -> String {
    match p {
        RoutePreference::Low => "low".into(),
        RoutePreference::Medium => "medium".into(),
        RoutePreference::High => "high".into(),
        RoutePreference::Invalid => "invalid".into(),
        RoutePreference::Other(v) => v.to_string(),
        _ => "invalid".into(),
    }
}

fn host_len(family: AddressFamily) -> u8 {
    match family {
        AddressFamily::Inet => 32,
        AddressFamily::Inet6 => 128,
        _ => 32,
    }
}

fn route_table_u32_to_string(table: u32) -> String {
    match table {
        0 => "unspec".into(),
        252 => "compat".into(),
        253 => "default".into(),
        254 => "main".into(),
        255 => "local".into(),
        v => v.to_string(),
    }
}

fn route_table_to_string(table: u8) -> String {
    match table {
        0 => "unspec".into(),
        252 => "compat".into(),
        253 => "default".into(),
        254 => "main".into(),
        255 => "local".into(),
        v => v.to_string(),
    }
}

fn route_next_hop_flags_to_strings(flags: RouteNextHopFlags) -> String {
    flags.to_string()
}

pub(crate) fn parse_nl_msg_to_route(
    nl_msg: RouteMessage,
    show_details: bool,
    link_map: &HashMap<u32, String>,
) -> CliRouteInfo {
    let family = nl_msg.header.address_family;
    let hlen = host_len(family);
    let mut info = CliRouteInfo {
        family,
        dst: String::new(),
        dst_len: nl_msg.header.destination_prefix_length,
        src_len: nl_msg.header.source_prefix_length,
        ..Default::default()
    };

    let mut oif_index: Option<u32> = None;
    let mut iif_index: Option<u32> = None;

    for nla in nl_msg.attributes.clone() {
        match nla {
            RouteAttribute::Destination(addr) => {
                let addr_str = match addr {
                    rtnetlink::packet_route::route::RouteAddress::Inet(a) => {
                        IpAddr::V4(a).to_string()
                    }
                    rtnetlink::packet_route::route::RouteAddress::Inet6(a) => {
                        IpAddr::V6(a).to_string()
                    }
                    rtnetlink::packet_route::route::RouteAddress::Mpls(m) => {
                        m.label.to_string()
                    }
                    rtnetlink::packet_route::route::RouteAddress::Other(v) => {
                        hex_encode(&v)
                    }
                    _ => String::new(),
                };
                info.dst = addr_str;
            }
            RouteAttribute::Source(addr) => {
                let addr_str = match addr {
                    rtnetlink::packet_route::route::RouteAddress::Inet(a) => {
                        if info.src_len > 0 && info.src_len != hlen {
                            format!("{}/{}", a, info.src_len)
                        } else {
                            a.to_string()
                        }
                    }
                    rtnetlink::packet_route::route::RouteAddress::Inet6(a) => {
                        if info.src_len > 0 && info.src_len != hlen {
                            format!("{}/{}", a, info.src_len)
                        } else {
                            a.to_string()
                        }
                    }
                    _ => String::new(),
                };
                if !addr_str.is_empty() {
                    info.src = Some(addr_str);
                }
            }
            RouteAttribute::Gateway(addr) => {
                info.gateway = match addr {
                    rtnetlink::packet_route::route::RouteAddress::Inet(a) => {
                        Some(a.to_string())
                    }
                    rtnetlink::packet_route::route::RouteAddress::Inet6(a) => {
                        Some(a.to_string())
                    }
                    _ => None,
                };
            }
            RouteAttribute::Via(via) => {
                info.gateway = Some(match via {
                    rtnetlink::packet_route::route::RouteVia::Inet(a) => {
                        a.to_string()
                    }
                    rtnetlink::packet_route::route::RouteVia::Inet6(a) => {
                        a.to_string()
                    }
                    rtnetlink::packet_route::route::RouteVia::Other((_, v)) => {
                        hex_encode(&v)
                    }
                    #[cfg(any(target_os = "linux", target_os = "fuchsia"))]
                    rtnetlink::packet_route::route::RouteVia::Packet(v) => {
                        hex_encode(&v)
                    }
                    _ => String::new(),
                });
            }
            RouteAttribute::PrefSource(addr) => {
                info.prefsrc = match addr {
                    rtnetlink::packet_route::route::RouteAddress::Inet(a) => {
                        Some(a.to_string())
                    }
                    rtnetlink::packet_route::route::RouteAddress::Inet6(a) => {
                        Some(a.to_string())
                    }
                    _ => None,
                };
            }
            RouteAttribute::Priority(p) => info.metric = Some(p),
            RouteAttribute::Oif(idx) => oif_index = Some(idx),
            RouteAttribute::Iif(idx) => iif_index = Some(idx),
            RouteAttribute::Table(t) => {
                // Use named table if known, otherwise numeric
                if t == 254 || t == 0 {
                    // Skip main/unspec - will be handled by header below
                } else {
                    info.table = Some(route_table_u32_to_string(t));
                }
            }
            RouteAttribute::Mark(m) => info.mark = Some(m),
            RouteAttribute::Uid(u) => info.uid = Some(u),
            RouteAttribute::Preference(p) => {
                info.preference = Some(route_preference_to_string(p))
            }
            RouteAttribute::CacheInfo(c) => info.cache_info = Some(c),
            RouteAttribute::MultiPath(nhs) => {
                for nh in nhs {
                    let mut cli_nh = CliRouteNextHop {
                        flags: route_next_hop_flags_to_strings(nh.flags),
                        weight: if nh.hops > 0 {
                            Some((nh.hops + 1) as u32)
                        } else {
                            None
                        },
                        ..Default::default()
                    };
                    for attr in nh.attributes {
                        match attr {
                            RouteAttribute::Gateway(addr) => {
                                cli_nh.gateway = match addr {
                                    rtnetlink::packet_route::route::RouteAddress::Inet(a) => Some(a.to_string()),
                                    rtnetlink::packet_route::route::RouteAddress::Inet6(a) => Some(a.to_string()),
                                    _ => None,
                                };
                            }
                            RouteAttribute::Via(via) => {
                                cli_nh.gateway = Some(match via {
                                    rtnetlink::packet_route::route::RouteVia::Inet(a) => a.to_string(),
                                    rtnetlink::packet_route::route::RouteVia::Inet6(a) => a.to_string(),
                                    _ => String::new(),
                                });
                            }
                            _ => {}
                        }
                    }
                    info.nexthops.push(cli_nh);
                }
            }
            _ => {}
        }
    }

    // Resolve OIF/IIF index to name
    if let Some(idx) = oif_index {
        info.oif = Some(
            link_map
                .get(&idx)
                .cloned()
                .unwrap_or_else(|| format!("if{idx}")),
        );
    }
    if let Some(idx) = iif_index {
        info.iif = Some(
            link_map
                .get(&idx)
                .cloned()
                .unwrap_or_else(|| format!("if{idx}")),
        );
    }

    // If no destination, it's "default"
    if info.dst.is_empty() {
        info.dst = "default".to_string();
    }

    // If there's a destination length, but no dest attribute, format as 0/len
    if info.dst == "default"
        && nl_msg.header.destination_prefix_length > 0
        && !has_dest_attr_before(&nl_msg)
    {
        info.dst = format!("0/{}", nl_msg.header.destination_prefix_length);
    } else if info.dst != "default"
        && nl_msg.header.destination_prefix_length != hlen
    {
        info.dst = format!("{}/{}", info.dst, info.dst_len);
    }

    let kind = nl_msg.header.kind;
    let show_type = kind != RouteType::Unicast || show_details;
    if show_type {
        info.kind = Some(route_type_to_string(kind));
    }

    // Default filter: only show main table unless table filter is set
    let table_val = if info.table.is_some() {
        0
    } else {
        nl_msg.header.table
    };
    let is_main = table_val == 0 || table_val == RouteHeader::RT_TABLE_MAIN;
    if info.table.is_none() && !is_main {
        info.table = Some(route_table_to_string(table_val));
    }

    let proto = nl_msg.header.protocol;
    let show_proto = proto != RouteProtocol::Boot || show_details;
    if show_proto {
        info.protocol = Some(route_protocol_to_string(proto));
    }

    let scope = nl_msg.header.scope;
    let show_scope = scope != RouteScope::Universe || show_details;
    if show_scope {
        info.scope = Some(route_scope_to_string(scope));
    }

    info.flags = route_flags_to_strings(nl_msg.header.flags);

    let is_cloned = nl_msg.header.flags.contains(RouteFlags::Cloned);
    info.cloned = is_cloned;

    // Only show cache info for cloned routes or with -d
    if !is_cloned && !show_details {
        info.cache_info = None;
    }

    info
}

fn has_dest_attr_before(msg: &RouteMessage) -> bool {
    msg.attributes
        .iter()
        .any(|a| matches!(a, RouteAttribute::Destination(_)))
}

impl std::fmt::Display for CliRouteInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use std::fmt::Write;

        let mut buf = String::new();

        // Type
        if let Some(ref kind) = self.kind {
            write!(buf, "{kind} ")?;
        }

        // Destination
        let color = match self.family {
            AddressFamily::Inet => CliColor::Ipv4Addr,
            AddressFamily::Inet6 => CliColor::Ipv6Addr,
            _ => CliColor::Ipv4Addr,
        };
        write_with_color!(buf, color, "{}", self.dst)?;
        buf.push(' ');

        // Source
        if let Some(ref src) = self.src {
            write!(buf, "from {src} ")?;
        }

        // Gateway (via)
        if let Some(ref gw) = self.gateway {
            write!(buf, "via ")?;
            write_with_color!(buf, color, "{gw}")?;
            buf.push(' ');
        }

        // Device
        if let Some(ref dev) = self.oif {
            write!(buf, "dev {dev} ")?;
        }

        // Skip table/protocol/scope for cloned routes (matching iproute2)
        if !self.cloned {
            if let Some(ref table) = self.table {
                write!(buf, "table {table} ")?;
            }

            if let Some(ref proto) = self.protocol {
                write!(buf, "proto {proto} ")?;
            }

            if let Some(ref scope) = self.scope {
                write!(buf, "scope {scope} ")?;
            }
        }

        // Preferred source
        if let Some(ref psrc) = self.prefsrc {
            write!(buf, "src ")?;
            write_with_color!(buf, color, "{psrc}")?;
            buf.push(' ');
        }

        // Metric
        if let Some(metric) = self.metric {
            write!(buf, "metric {metric} ")?;
        }

        // Flags
        for flag in &self.flags {
            write!(buf, "{flag} ")?;
        }

        // TOS
        if let Some(tos) = self.tos {
            write!(buf, "tos {tos} ")?;
        }

        // Mark
        if let Some(mark) = self.mark {
            if mark >= 16 {
                write!(buf, "mark 0x{mark:x} ")?;
            } else {
                write!(buf, "mark {mark} ")?;
            }
        }

        // UID
        if let Some(uid) = self.uid {
            write!(buf, "uid {uid} ")?;
        }

        // TTL propagate
        if let Some(ttl) = self.ttl_propagate {
            if ttl {
                write!(buf, "ttl-propagate enabled ")?;
            } else {
                write!(buf, "ttl-propagate disabled ")?;
            }
        }

        // Cache info
        if let Some(ref ci) = self.cache_info {
            let expires_str = if (ci.expires as i32) >= 0 {
                format!("{}", ci.expires)
            } else {
                format!("-{}", ci.expires.wrapping_neg())
            };
            write!(
                buf,
                " cache <clntref {}, last-use {}, expires {}, error {}, used \
                 {}, id {}, ts {}, ts_age {}>",
                ci.clntref,
                ci.last_use,
                expires_str,
                ci.error,
                ci.used,
                ci.id,
                ci.ts,
                ci.ts_age,
            )?;
        }

        // IIF
        if let Some(ref iif_dev) = self.iif {
            write!(buf, "iif {iif_dev} ")?;
        }

        // Preference (no trailing space - matches iproute2 behavior)
        if let Some(ref pref) = self.preference {
            write!(buf, "pref {pref}")?;
        }

        // Nexthops (multipath)
        for nh in &self.nexthops {
            buf.push_str("\n\tnexthop");
            if let Some(ref gw) = nh.gateway {
                write!(buf, " via {gw}")?;
            }
            if let Some(ref dev) = nh.oif {
                write!(buf, " dev {dev}")?;
            }
            if let Some(w) = nh.weight {
                write!(buf, " weight {w}")?;
            }
            if !nh.flags.is_empty() {
                write!(buf, " {}", nh.flags)?;
            }
        }

        f.write_str(&buf)
    }
}

impl CanDisplay for CliRouteInfo {
    fn gen_string(&self) -> String {
        self.to_string()
    }
}

impl CanOutput for CliRouteInfo {}

#[allow(dead_code)]
pub(crate) struct RouteShowFilter {
    pub(crate) tb: Option<u32>,
    pub(crate) cloned: bool,
    pub(crate) protocol: Option<u8>,
    pub(crate) protocol_mask: u8,
    pub(crate) scope: Option<u8>,
    pub(crate) scope_mask: u8,
    pub(crate) typemask: Option<u64>,
    pub(crate) tos: Option<u8>,
    pub(crate) oif: Option<String>,
    pub(crate) iif: Option<String>,
    pub(crate) mark: Option<u32>,
    pub(crate) metric: Option<u32>,
    pub(crate) rvia: Option<IpAddr>,
    pub(crate) rprefsrc: Option<IpAddr>,
    pub(crate) rdst: Option<(IpAddr, u8)>,
    pub(crate) rsrc: Option<(IpAddr, u8)>,
    pub(crate) dev_name: Option<String>,
}

impl RouteShowFilter {
    pub(crate) fn parse(
        opts: &[&str],
    ) -> Result<(Self, Vec<String>), CliError> {
        let mut tb: Option<u32> = None;
        let mut cloned = false;
        let mut protocol: Option<u8> = None;
        let mut protocol_mask: u8 = 0xff;
        let mut scope: Option<u8> = None;
        let mut scope_mask: u8 = 0xff;
        let mut typemask: Option<u64> = None;
        let mut tos: Option<u8> = None;
        let mut oif: Option<String> = None;
        let mut iif: Option<String> = None;
        let mut mark: Option<u32> = None;
        let mut metric: Option<u32> = None;
        let mut rvia: Option<IpAddr> = None;
        let mut rprefsrc: Option<IpAddr> = None;
        let mut rdst: Option<(IpAddr, u8)> = None;
        let mut rsrc: Option<(IpAddr, u8)> = None;
        let mut dev_name: Option<String> = None;
        let mut link_opts: Vec<String> = Vec::new();

        let mut iter = opts.iter().peekable();
        while let Some(arg) = iter.next() {
            match *arg {
                "table" => {
                    let val = iter.next().ok_or_else(|| {
                        CliError::from("\"table\" requires a value")
                    })?;
                    match *val {
                        "all" => tb = Some(0),
                        "cache" => cloned = true,
                        v => tb = Some(parse_table_id(v)?),
                    }
                }
                "cached" | "cloned" => cloned = true,
                "protocol" | "proto" => {
                    let val = iter.next().ok_or_else(|| {
                        CliError::from("\"protocol\" requires a value")
                    })?;
                    if *val == "all" {
                        protocol_mask = 0;
                    } else {
                        protocol = Some(parse_protocol_value(val)?);
                    }
                }
                "scope" => {
                    let val = iter.next().ok_or_else(|| {
                        CliError::from("\"scope\" requires a value")
                    })?;
                    if *val == "all" {
                        scope_mask = 0;
                    } else {
                        scope = Some(parse_scope_val(val)?);
                    }
                }
                "type" => {
                    let val = iter.next().ok_or_else(|| {
                        CliError::from("\"type\" requires a value")
                    })?;
                    typemask = Some(parse_type_mask(val)?);
                }
                "tos" => {
                    let val = iter.next().ok_or_else(|| {
                        CliError::from("\"tos\" requires a value")
                    })?;
                    tos = Some(val.parse::<u8>().map_err(|_| {
                        CliError::from(format!("invalid tos value: {val}"))
                    })?);
                }
                "dev" | "oif" => {
                    let val = iter.next().ok_or_else(|| {
                        CliError::from("\"dev\" requires a value")
                    })?;
                    oif = Some(val.to_string());
                }
                "iif" => {
                    let val = iter.next().ok_or_else(|| {
                        CliError::from("\"iif\" requires a value")
                    })?;
                    iif = Some(val.to_string());
                }
                "mark" => {
                    let val = iter.next().ok_or_else(|| {
                        CliError::from("\"mark\" requires a value")
                    })?;
                    mark = Some(parse_mark_value(val)?);
                }
                "metric" | "priority" | "preference" => {
                    let val = iter.next().ok_or_else(|| {
                        CliError::from("\"metric\" requires a value")
                    })?;
                    metric = Some(val.parse::<u32>().map_err(|_| {
                        CliError::from(format!("invalid metric: {val}"))
                    })?);
                }
                "via" => {
                    let val = iter.next().ok_or_else(|| {
                        CliError::from("\"via\" requires a value")
                    })?;
                    rvia = Some(val.parse::<IpAddr>().map_err(|_| {
                        CliError::from(format!("invalid address: {val}"))
                    })?);
                }
                "src" => {
                    let val = iter.next().ok_or_else(|| {
                        CliError::from("\"src\" requires a value")
                    })?;
                    rprefsrc = Some(val.parse::<IpAddr>().map_err(|_| {
                        CliError::from(format!("invalid address: {val}"))
                    })?);
                }
                "from" => {
                    let val = iter.next().ok_or_else(|| {
                        CliError::from("\"from\" requires a value")
                    })?;
                    rsrc = Some(parse_prefix_val(val)?);
                }
                "to" => {
                    let val = iter.next().ok_or_else(|| {
                        CliError::from("\"to\" requires a value")
                    })?;
                    rdst = Some(parse_prefix_val(val)?);
                }
                _ => {
                    if rdst.is_none() && !arg.starts_with('-') {
                        // Try parsing as destination prefix first
                        if let Ok(prefix) = parse_prefix_val(arg) {
                            rdst = Some(prefix);
                        } else if dev_name.is_none() {
                            dev_name = Some(arg.to_string());
                        }
                    } else {
                        link_opts.push(arg.to_string());
                        if let Some(val) = iter.peek()
                            && !val.starts_with('-')
                        {
                            link_opts.push(iter.next().unwrap().to_string());
                        }
                    }
                }
            }
        }

        Ok((
            RouteShowFilter {
                tb,
                cloned,
                protocol,
                protocol_mask,
                scope,
                scope_mask,
                typemask,
                tos,
                oif,
                iif,
                mark,
                metric,
                rvia,
                rprefsrc,
                rdst,
                rsrc,
                dev_name,
            },
            link_opts,
        ))
    }

    fn parse_dst(s: &str) -> Option<(IpAddr, u8)> {
        if s == "default" {
            return Some((IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), 0));
        }
        let (addr_str, plen_str) = s.split_once('/').unwrap_or((s, "32"));
        let addr = addr_str.parse::<IpAddr>().ok()?;
        let plen = if s.contains('/') {
            plen_str.parse::<u8>().ok()?
        } else if addr.is_ipv4() {
            32
        } else {
            128
        };
        Some((addr, plen))
    }

    pub(crate) fn matches(&self, route: &CliRouteInfo) -> bool {
        if let Some(tb) = self.tb {
            let table_val = route
                .table
                .as_deref()
                .and_then(|t| t.parse::<u32>().ok())
                .unwrap_or(0);
            if tb != 0 && table_val != tb {
                return false;
            }
        }

        if let Some(p) = self.protocol {
            if self.protocol_mask == 0 {
                // protocol all: skip filtering
            } else {
                let route_proto = route.protocol.as_deref().unwrap_or("boot");
                let filter_proto = match p {
                    0 => "unspec",
                    1 => "redirect",
                    2 => "kernel",
                    3 => "boot",
                    4 => "static",
                    8 => "gated",
                    9 => "ra",
                    10 => "mrt",
                    11 => "zebra",
                    12 => "bird",
                    13 => "dnrouted",
                    14 => "xorp",
                    15 => "ntk",
                    16 => "dhcp",
                    17 => "mrouted",
                    18 => "keepalived",
                    42 => "babel",
                    186 => "bgp",
                    187 => "isis",
                    188 => "ospf",
                    189 => "rip",
                    192 => "eigrp",
                    v => {
                        let fallback = v.to_string();
                        return route_proto == fallback;
                    }
                };
                if route_proto != filter_proto {
                    return false;
                }
            }
        }

        if let Some(s) = self.scope {
            let scope_val = route
                .scope
                .as_deref()
                .and_then(|s| {
                    Some(match s {
                        "global" => 0u8,
                        "site" => 200,
                        "link" => 253,
                        "host" => 254,
                        "nowhere" => 255,
                        v => v.parse().ok()?,
                    })
                })
                .unwrap_or(0);
            if (scope_val ^ s) & self.scope_mask != 0 {
                return false;
            }
        }

        if let Some(tm) = self.typemask {
            let kind = route.kind.as_deref().unwrap_or("unicast");
            let type_val: u8 = match kind {
                "unspec" => 0,
                "unicast" => 1,
                "local" => 2,
                "broadcast" => 3,
                "anycast" => 4,
                "multicast" => 5,
                "blackhole" => 6,
                "unreachable" => 7,
                "prohibit" => 8,
                "throw" => 9,
                "nat" => 10,
                "xresolve" => 11,
                _ => return false,
            };
            if (tm & (1u64 << type_val)) == 0 {
                return false;
            }
        }

        if let Some(tos) = self.tos
            && route.tos != Some(tos)
        {
            return false;
        }

        if let Some(ref dev) = self.oif
            && route.oif.as_deref() != Some(dev.as_str())
        {
            return false;
        }

        if let Some(ref iif_dev) = self.iif
            && route.iif.as_deref() != Some(iif_dev.as_str())
        {
            return false;
        }

        if let Some(m) = self.metric
            && route.metric != Some(m)
        {
            return false;
        }

        if let Some(ref via_addr) = self.rvia {
            let gw = route
                .gateway
                .as_deref()
                .and_then(|s| s.parse::<IpAddr>().ok());
            if gw.as_ref() != Some(via_addr) {
                return false;
            }
        }

        if let Some(ref psrc) = self.rprefsrc {
            let paddr = route
                .prefsrc
                .as_deref()
                .and_then(|s| s.parse::<IpAddr>().ok());
            if paddr.as_ref() != Some(psrc) {
                return false;
            }
        }

        if let Some((ref dst_addr, _dst_plen)) = self.rdst {
            if let Some((route_addr, _)) = Self::parse_dst(&route.dst) {
                if route_addr != *dst_addr {
                    return false;
                }
            } else {
                return false;
            }
        }

        if let Some((ref src_addr, _src_plen)) = self.rsrc {
            if let Some(ref src) = route.src {
                if let Ok(addr) = src.parse::<IpAddr>() {
                    if addr != *src_addr {
                        return false;
                    }
                } else {
                    return false;
                }
            } else {
                return false;
            }
        }

        if let Some(ref dev_name) = self.dev_name
            && route.oif.as_deref() != Some(dev_name.as_str())
        {
            return false;
        }

        true
    }

    pub(crate) fn strip_matches(&self, route: &mut CliRouteInfo) {
        if self.oif.is_some() {
            route.oif = None;
        }
        if self.rvia.is_some() {
            route.gateway = None;
        }
        if self.protocol.is_some() {
            route.protocol = None;
        }
        if self.scope.is_some() {
            route.scope = None;
        }
        if self.tos.is_some() {
            route.tos = None;
        }
        if self.metric.is_some() {
            route.metric = None;
        }
        if self.iif.is_some() {
            route.iif = None;
        }
        if self.rdst.is_some() {
            // Don't strip 'dst' - it's always shown
        }
    }
}

fn parse_table_id(s: &str) -> Result<u32, CliError> {
    match s {
        "local" => Ok(255),
        "main" => Ok(254),
        "default" => Ok(253),
        v => v
            .parse::<u32>()
            .map_err(|_| CliError::from(format!("invalid table ID: {v}"))),
    }
}

fn parse_protocol_value(s: &str) -> Result<u8, CliError> {
    match s {
        "unspec" => Ok(0),
        "redirect" => Ok(1),
        "kernel" => Ok(2),
        "boot" => Ok(3),
        "static" => Ok(4),
        "gated" => Ok(8),
        "ra" => Ok(9),
        "mrt" => Ok(10),
        "zebra" => Ok(11),
        "bird" => Ok(12),
        "dnrouted" => Ok(13),
        "xorp" => Ok(14),
        "ntk" => Ok(15),
        "dhcp" => Ok(16),
        "mrouted" => Ok(17),
        "keepalived" => Ok(18),
        "babel" => Ok(42),
        "bgp" => Ok(186),
        "isis" => Ok(187),
        "ospf" => Ok(188),
        "rip" => Ok(189),
        "eigrp" => Ok(192),
        v => v
            .parse::<u8>()
            .map_err(|_| CliError::from(format!("invalid protocol: {v}"))),
    }
}

fn parse_scope_val(s: &str) -> Result<u8, CliError> {
    match s {
        "global" | "universe" => Ok(0),
        "site" => Ok(200),
        "link" => Ok(253),
        "host" => Ok(254),
        "nowhere" => Ok(255),
        v => v
            .parse::<u8>()
            .map_err(|_| CliError::from(format!("invalid scope: {v}"))),
    }
}

fn parse_type_mask(s: &str) -> Result<u64, CliError> {
    let v: u8 = match s {
        "unspec" => 0,
        "unicast" => 1,
        "local" => 2,
        "broadcast" => 3,
        "anycast" => 4,
        "multicast" => 5,
        "blackhole" => 6,
        "unreachable" => 7,
        "prohibit" => 8,
        "throw" => 9,
        "nat" => 10,
        "xresolve" => 11,
        v => v
            .parse::<u8>()
            .map_err(|_| CliError::from(format!("invalid route type: {v}")))?,
    };
    Ok(1u64 << v)
}

fn parse_mark_value(s: &str) -> Result<u32, CliError> {
    if let Some(hex_str) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))
    {
        u32::from_str_radix(hex_str, 16)
            .map_err(|_| CliError::from(format!("invalid mark value: {s}")))
    } else {
        s.parse::<u32>()
            .map_err(|_| CliError::from(format!("invalid mark value: {s}")))
    }
}

fn parse_prefix_val(s: &str) -> Result<(IpAddr, u8), CliError> {
    if let Some((addr_str, plen_str)) = s.split_once('/') {
        let addr: IpAddr = addr_str.parse().map_err(|_| {
            CliError::from(format!("invalid address: {addr_str}"))
        })?;
        let plen = plen_str.parse::<u8>().map_err(|_| {
            CliError::from(format!("invalid prefix length: {plen_str}"))
        })?;
        Ok((addr, plen))
    } else {
        let addr: IpAddr = s
            .parse()
            .map_err(|_| CliError::from(format!("invalid address: {s}")))?;
        let default_plen = if addr.is_ipv4() { 32 } else { 128 };
        Ok((addr, default_plen))
    }
}

pub(crate) async fn handle_show(
    opts: &[&str],
    preferred_family: Option<AddressFamily>,
    show_details: bool,
) -> Result<Vec<CliRouteInfo>, CliError> {
    let (filter, _link_opts) = RouteShowFilter::parse(opts)?;

    let show_all_tables = filter.tb == Some(0);

    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    // Build link index -> name map
    let mut link_map: HashMap<u32, String> = HashMap::new();
    let mut links = handle.link().get().execute();
    while let Ok(Some(link)) = links.try_next().await {
        let ifname = link
            .attributes
            .iter()
            .find_map(|attr| {
                if let rtnetlink::packet_route::link::LinkAttribute::IfName(
                    name,
                ) = attr
                {
                    Some(name.clone())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| format!("if{}", link.header.index));
        link_map.insert(link.header.index, ifname);
    }

    let msg = RouteMessage::default();
    let mut routes = handle.route().get(msg).execute();

    let mut result: Vec<CliRouteInfo> = Vec::new();

    // Default to IPv4 only (like iproute2), but show all families for table all
    let filter_family = if show_all_tables && preferred_family.is_none() {
        None
    } else {
        Some(preferred_family.unwrap_or(AddressFamily::Inet))
    };

    while let Ok(Some(nl_msg)) = routes.try_next().await {
        if let Some(fam) = filter_family
            && nl_msg.header.address_family != fam
        {
            continue;
        }

        let route = parse_nl_msg_to_route(nl_msg, show_details, &link_map);

        // Default filter: only show main table routes
        let is_main_table = matches!(
            route.table.as_deref(),
            None | Some("main") | Some("254") | Some("unspec") | Some("0")
        );
        if !show_all_tables && !is_main_table {
            continue;
        }

        if filter.matches(&route) {
            let mut route = route;
            filter.strip_matches(&mut route);
            result.push(route);
        }
    }

    Ok(result)
}
