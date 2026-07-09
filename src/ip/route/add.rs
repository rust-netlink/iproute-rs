// SPDX-License-Identifier: MIT

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use futures_util::TryStreamExt;
use rtnetlink::packet_route::{
    AddressFamily,
    route::{RouteProtocol, RouteScope, RouteType},
};

use crate::CliError;

pub(crate) struct RouteAddConfig {
    pub(crate) dst: Option<IpAddr>,
    pub(crate) dst_len: u8,
    pub(crate) src: Option<IpAddr>,
    pub(crate) src_len: u8,
    pub(crate) via: Option<IpAddr>,
    pub(crate) dev: Option<String>,
    pub(crate) table: Option<u32>,
    pub(crate) protocol: Option<RouteProtocol>,
    pub(crate) scope: Option<RouteScope>,
    pub(crate) kind: Option<RouteType>,
    pub(crate) metric: Option<u32>,
    pub(crate) prefsrc: Option<IpAddr>,
    pub(crate) onlink: bool,
    pub(crate) expires: Option<u32>,
    pub(crate) mark: Option<u32>,
    pub(crate) uid: Option<u32>,
    pub(crate) preference: Option<u8>,
    pub(crate) family: Option<AddressFamily>,
}

pub(crate) fn parse_route_config(
    opts: &[String],
    preferred_family: Option<AddressFamily>,
) -> Result<RouteAddConfig, CliError> {
    let mut dst: Option<IpAddr> = None;
    let mut dst_len: u8 = 0;
    let mut src: Option<IpAddr> = None;
    let mut src_len: u8 = 0;
    let mut via: Option<IpAddr> = None;
    let mut dev: Option<String> = None;
    let mut table: Option<u32> = None;
    let mut protocol: Option<RouteProtocol> = None;
    let mut scope: Option<RouteScope> = None;
    let mut kind: Option<RouteType> = None;
    let mut metric: Option<u32> = None;
    let mut prefsrc: Option<IpAddr> = None;
    let mut onlink = false;
    let mut expires: Option<u32> = None;
    let mut mark: Option<u32> = None;
    let mut uid: Option<u32> = None;
    let mut preference: Option<u8> = None;
    let mut family: Option<AddressFamily> = preferred_family;
    let mut positional_prefix_seen = false;

    let mut iter = opts.iter().peekable();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "via" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"via\" requires a value")
                })?;
                let (addr, fam) = parse_via_address(val, family, &mut iter)?;
                via = Some(addr);
                family = fam.or(family).or(addr_to_family(&addr));
            }
            "dev" => {
                dev = Some(
                    iter.next()
                        .ok_or_else(|| {
                            CliError::from("\"dev\" requires a value")
                        })?
                        .clone(),
                );
            }
            "src" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"src\" requires a value")
                })?;
                let addr: IpAddr = val.parse().map_err(|_| {
                    CliError::from(format!("invalid source address: {val}"))
                })?;
                prefsrc = Some(addr);
            }
            "from" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"from\" requires a value")
                })?;
                let (addr, plen) = parse_prefix(val)?;
                src = Some(addr);
                src_len = plen;
                if family.is_none() {
                    family = addr_to_family(&addr);
                }
            }
            "to" => {
                let val = iter
                    .next()
                    .ok_or_else(|| CliError::from("\"to\" requires a value"))?;
                let (addr, plen) = parse_prefix(val)?;
                dst = Some(addr);
                dst_len = plen;
                positional_prefix_seen = true;
                if family.is_none() {
                    family = addr_to_family(&addr);
                }
            }
            "table" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"table\" requires a value")
                })?;
                table = Some(parse_table_id(val)?);
            }
            "proto" | "protocol" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"proto\" requires a value")
                })?;
                protocol = Some(parse_route_protocol(val)?);
            }
            "scope" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"scope\" requires a value")
                })?;
                scope = Some(parse_route_scope(val)?);
            }
            "type" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"type\" requires a value")
                })?;
                kind = Some(parse_route_type(val)?);
            }
            "metric" | "priority" | "preference" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"metric\" requires a value")
                })?;
                metric = Some(val.parse::<u32>().map_err(|_| {
                    CliError::from(format!("invalid metric value: {val}"))
                })?);
            }
            "onlink" => onlink = true,
            "expires" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"expires\" requires a value")
                })?;
                expires = Some(val.parse::<u32>().map_err(|_| {
                    CliError::from(format!("invalid expires value: {val}"))
                })?);
            }
            "mark" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"mark\" requires a value")
                })?;
                mark = Some(parse_mark_value(val)?);
            }
            "uid" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"uid\" requires a value")
                })?;
                uid = Some(val.parse::<u32>().map_err(|_| {
                    CliError::from(format!("invalid uid value: {val}"))
                })?);
            }
            "pref" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"pref\" requires a value")
                })?;
                preference = Some(match val.as_str() {
                    "low" => 0x3,
                    "medium" => 0x0,
                    "high" => 0x1,
                    _ => {
                        return Err(CliError::from(format!(
                            "invalid preference: {val}"
                        )));
                    }
                });
            }
            _ => {
                if !positional_prefix_seen {
                    if let Ok(rt) = parse_route_type(arg) {
                        kind = Some(rt);
                    } else {
                        let (addr, plen) = parse_prefix(arg)?;
                        dst = Some(addr);
                        dst_len = plen;
                        positional_prefix_seen = true;
                        if family.is_none() {
                            family = addr_to_family(&addr);
                        }
                    }
                } else {
                    return Err(CliError::from(format!(
                        "unexpected argument: {arg}"
                    )));
                }
            }
        }
    }

    if family.is_none() {
        family = Some(AddressFamily::Inet);
    }

    Ok(RouteAddConfig {
        dst,
        dst_len,
        src,
        src_len,
        via,
        dev,
        table,
        protocol,
        scope,
        kind,
        metric,
        prefsrc,
        onlink,
        expires,
        mark,
        uid,
        preference,
        family,
    })
}

fn addr_to_family(addr: &IpAddr) -> Option<AddressFamily> {
    match addr {
        IpAddr::V4(_) => Some(AddressFamily::Inet),
        IpAddr::V6(_) => Some(AddressFamily::Inet6),
    }
}

fn parse_via_address<'a>(
    s: &str,
    current_family: Option<AddressFamily>,
    iter: &mut std::iter::Peekable<impl Iterator<Item = &'a String>>,
) -> Result<(IpAddr, Option<AddressFamily>), CliError> {
    let result = match s {
        "inet" => {
            let addr = iter.next().ok_or_else(|| {
                CliError::from("\"via inet\" requires an address")
            })?;
            let v4: Ipv4Addr = addr.parse().map_err(|_| {
                CliError::from(format!("invalid IPv4 via address: {addr}"))
            })?;
            (IpAddr::V4(v4), Some(AddressFamily::Inet))
        }
        "inet6" => {
            let addr = iter.next().ok_or_else(|| {
                CliError::from("\"via inet6\" requires an address")
            })?;
            let v6: Ipv6Addr = addr.parse().map_err(|_| {
                CliError::from(format!("invalid IPv6 via address: {addr}"))
            })?;
            (IpAddr::V6(v6), Some(AddressFamily::Inet6))
        }
        _ => {
            let addr: IpAddr = s.parse().map_err(|_| {
                CliError::from(format!("invalid via address: {s}"))
            })?;
            let fam = addr_to_family(&addr);
            if let Some(cf) = current_family
                && fam != Some(cf)
            {
                // Address family differs from route family -
                // will use RTA_VIA instead of RTA_GATEWAY
            }
            (addr, fam)
        }
    };
    Ok(result)
}

fn parse_prefix(s: &str) -> Result<(IpAddr, u8), CliError> {
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
        let plen = if addr.is_ipv4() { 32 } else { 128 };
        Ok((addr, plen))
    }
}

fn parse_table_id(s: &str) -> Result<u32, CliError> {
    match s {
        "local" => Ok(255),
        "main" => Ok(254),
        "default" => Ok(253),
        "all" => Ok(0),
        v => v
            .parse::<u32>()
            .map_err(|_| CliError::from(format!("invalid table ID: {v}"))),
    }
}

fn parse_route_protocol(s: &str) -> Result<RouteProtocol, CliError> {
    match s {
        "unspec" => Ok(RouteProtocol::Unspec),
        "redirect" => Ok(RouteProtocol::IcmpRedirect),
        "kernel" => Ok(RouteProtocol::Kernel),
        "boot" => Ok(RouteProtocol::Boot),
        "static" => Ok(RouteProtocol::Static),
        "gated" => Ok(RouteProtocol::Gated),
        "ra" => Ok(RouteProtocol::Ra),
        "mrt" => Ok(RouteProtocol::Mrt),
        "zebra" => Ok(RouteProtocol::Zebra),
        "bird" => Ok(RouteProtocol::Bird),
        "dnrouted" => Ok(RouteProtocol::DnRouted),
        "xorp" => Ok(RouteProtocol::Xorp),
        "ntk" => Ok(RouteProtocol::Ntk),
        "dhcp" => Ok(RouteProtocol::Dhcp),
        "mrouted" => Ok(RouteProtocol::Mrouted),
        "keepalived" => Ok(RouteProtocol::KeepAlived),
        "babel" => Ok(RouteProtocol::Babel),
        "bgp" => Ok(RouteProtocol::Bgp),
        "isis" => Ok(RouteProtocol::Isis),
        "ospf" => Ok(RouteProtocol::Ospf),
        "rip" => Ok(RouteProtocol::Rip),
        "eigrp" => Ok(RouteProtocol::Eigrp),
        v => {
            let num = v.parse::<u8>().map_err(|_| {
                CliError::from(format!("invalid protocol: {v}"))
            })?;
            Ok(RouteProtocol::from(num))
        }
    }
}

fn parse_route_scope(s: &str) -> Result<RouteScope, CliError> {
    match s {
        "global" | "universe" => Ok(RouteScope::Universe),
        "site" => Ok(RouteScope::Site),
        "link" => Ok(RouteScope::Link),
        "host" => Ok(RouteScope::Host),
        "nowhere" => Ok(RouteScope::NoWhere),
        v => {
            let num = v
                .parse::<u8>()
                .map_err(|_| CliError::from(format!("invalid scope: {v}")))?;
            Ok(RouteScope::from(num))
        }
    }
}

fn parse_route_type(s: &str) -> Result<RouteType, CliError> {
    match s {
        "unspec" => Ok(RouteType::Unspec),
        "unicast" => Ok(RouteType::Unicast),
        "local" => Ok(RouteType::Local),
        "broadcast" => Ok(RouteType::Broadcast),
        "anycast" => Ok(RouteType::Anycast),
        "multicast" => Ok(RouteType::Multicast),
        "blackhole" => Ok(RouteType::BlackHole),
        "unreachable" => Ok(RouteType::Unreachable),
        "prohibit" => Ok(RouteType::Prohibit),
        "throw" => Ok(RouteType::Throw),
        "nat" => Ok(RouteType::Nat),
        "xresolve" => Ok(RouteType::ExternalResolve),
        v => {
            let num = v.parse::<u8>().map_err(|_| {
                CliError::from(format!("invalid route type: {v}"))
            })?;
            Ok(RouteType::from(num))
        }
    }
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

pub(crate) async fn resolve_ifindex(
    handle: &rtnetlink::Handle,
    name: &str,
) -> Result<u32, CliError> {
    let mut links = handle.link().get().match_name(name.to_string()).execute();
    let link = links.try_next().await?.ok_or_else(|| {
        CliError::from(format!("Device \"{name}\" does not exist"))
    })?;
    Ok(link.header.index)
}
