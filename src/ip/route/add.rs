// SPDX-License-Identifier: MIT

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use futures_util::TryStreamExt;
use rtnetlink::{
    packet_core::DefaultNla,
    packet_route::{
        AddressFamily,
        route::{
            RouteMetric, RouteProtocol, RouteRealm, RouteScope, RouteType,
        },
    },
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
    pub(crate) metrics: Vec<RouteMetric>,
    pub(crate) realm: Option<RouteRealm>,
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
    let mut metrics: Vec<RouteMetric> = Vec::new();
    let mut realm: Option<RouteRealm> = None;
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
            "mtu" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"mtu\" requires a value")
                })?;
                metrics.push(RouteMetric::Mtu(parse_u32_any_base(val)?));
            }
            "advmss" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"advmss\" requires a value")
                })?;
                metrics.push(RouteMetric::Advmss(parse_u32_any_base(val)?));
            }
            "rtt" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"rtt\" requires a value")
                })?;
                let (value, raw) = parse_time_rtt(val)?;
                let value = if raw {
                    value
                } else {
                    value.checked_mul(8).ok_or_else(|| {
                        CliError::from(format!("invalid rtt value: {val}"))
                    })?
                };
                metrics.push(RouteMetric::Rtt(value));
            }
            "rttvar" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"rttvar\" requires a value")
                })?;
                let (value, raw) = parse_time_rtt(val)?;
                let value = if raw {
                    value
                } else {
                    value.checked_mul(4).ok_or_else(|| {
                        CliError::from(format!("invalid rttvar value: {val}"))
                    })?
                };
                metrics.push(RouteMetric::RttVar(value));
            }
            "reordering" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"reordering\" requires a value")
                })?;
                metrics.push(RouteMetric::Reordering(parse_u32_any_base(val)?));
            }
            "window" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"window\" requires a value")
                })?;
                metrics.push(RouteMetric::Window(parse_u32_any_base(val)?));
            }
            "cwnd" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"cwnd\" requires a value")
                })?;
                metrics.push(RouteMetric::Cwnd(parse_u32_any_base(val)?));
            }
            "initcwnd" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"initcwnd\" requires a value")
                })?;
                metrics.push(RouteMetric::InitCwnd(parse_u32_any_base(val)?));
            }
            "initrwnd" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"initrwnd\" requires a value")
                })?;
                metrics.push(RouteMetric::InitRwnd(parse_u32_any_base(val)?));
            }
            "ssthresh" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"ssthresh\" requires a value")
                })?;
                metrics.push(RouteMetric::SsThresh(parse_u32_any_base(val)?));
            }
            "hoplimit" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"hoplimit\" requires a value")
                })?;
                let value = parse_u32_any_base(val)?;
                if value > 255 {
                    return Err(CliError::from(format!(
                        "invalid hoplimit value: {val}"
                    )));
                }
                metrics.push(RouteMetric::Hoplimit(value));
            }
            "rto_min" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"rto_min\" requires a value")
                })?;
                let (value, _) = parse_time_rtt(val)?;
                metrics.push(RouteMetric::RtoMin(value));
            }
            "features" => {
                let mut features = 0u32;
                let mut count = 0u32;
                while let Some(feature) = iter.peek() {
                    let bit = match feature.as_str() {
                        "ecn" => 1,
                        "tcp_usec_ts" => 16,
                        _ => break,
                    };
                    features |= bit;
                    count += 1;
                    iter.next();
                }
                if count == 0 {
                    return Err(CliError::from(
                        "\"features\" requires at least one feature",
                    ));
                }
                metrics.push(RouteMetric::Features(features));
            }
            "quickack" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"quickack\" requires a value")
                })?;
                let value = parse_u32_any_base(val)?;
                if value > 1 {
                    return Err(CliError::from(
                        "\"quickack\" value should be 0 or 1",
                    ));
                }
                metrics.push(RouteMetric::QuickAck(value));
            }
            "congctl" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"congctl\" requires a value")
                })?;
                // netlink-packet-route's `CcAlgo` variant currently models
                // RTAX_CC_ALGO as u32; emit the string payload via `Other`
                // until that crate is fixed.
                metrics.push(RouteMetric::Other(DefaultNla::new(
                    16,
                    val.as_bytes().to_vec(),
                )));
            }
            "fastopen_no_cookie" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"fastopen_no_cookie\" requires a value")
                })?;
                let value = parse_u32_any_base(val)?;
                if value > 1 {
                    return Err(CliError::from(
                        "\"fastopen_no_cookie\" value should be 0 or 1",
                    ));
                }
                metrics.push(RouteMetric::FastopenNoCookie(value));
            }
            "realms" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"realms\" requires a value")
                })?;
                realm = Some(parse_realm(val)?);
            }
            "as" => {
                return Err(CliError::from(format!("invalid argument: {arg}")));
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
        metrics,
        realm,
    })
}

fn parse_u32_any_base(s: &str) -> Result<u32, CliError> {
    let (radix, digits) = if let Some(hex) =
        s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))
    {
        (16, hex)
    } else if s.len() > 1 && s.starts_with('0') {
        (8, &s[1..])
    } else {
        (10, s)
    };
    u32::from_str_radix(digits, radix)
        .map_err(|_| CliError::from(format!("invalid number: {s}")))
}

fn parse_time_rtt(s: &str) -> Result<(u32, bool), CliError> {
    let lower = s.to_ascii_lowercase();
    let (num, multiplier, has_suffix) =
        if let Some(num) = lower.strip_suffix("msecs") {
            (num, 1.0, true)
        } else if let Some(num) = lower.strip_suffix("msec") {
            (num, 1.0, true)
        } else if let Some(num) = lower.strip_suffix("ms") {
            (num, 1.0, true)
        } else if let Some(num) = lower.strip_suffix("secs") {
            (num, 1000.0, true)
        } else if let Some(num) = lower.strip_suffix("sec") {
            (num, 1000.0, true)
        } else if let Some(num) = lower.strip_suffix("s") {
            (num, 1000.0, true)
        } else {
            (lower.as_str(), 1.0, false)
        };

    if num.is_empty() {
        return Err(CliError::from(format!("invalid time value: {s}")));
    }

    let value = if num.contains('.') {
        let t: f64 = num
            .parse()
            .map_err(|_| CliError::from(format!("invalid time value: {s}")))?;
        if t < 0.0 || !t.is_finite() {
            return Err(CliError::from(format!("invalid time value: {s}")));
        }
        t * multiplier
    } else {
        parse_u32_any_base(num)? as f64 * multiplier
    };

    if value > u32::MAX as f64 {
        return Err(CliError::from(format!("invalid time value: {s}")));
    }
    Ok((value.ceil() as u32, !has_suffix))
}

fn parse_realm(s: &str) -> Result<RouteRealm, CliError> {
    if let Some((from, to)) = s.split_once('/') {
        Ok(RouteRealm {
            source: parse_realm_component(from)?,
            destination: parse_realm_component(to)?,
        })
    } else {
        let value = parse_u32_any_base(s)?;
        Ok(RouteRealm {
            source: (value >> 16) as u16,
            destination: value as u16,
        })
    }
}

fn parse_realm_component(s: &str) -> Result<u16, CliError> {
    let value = parse_u32_any_base(s)?;
    if value > u16::MAX as u32 {
        return Err(CliError::from(format!("invalid realm value: {s}")));
    }
    Ok(value as u16)
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

#[cfg(test)]
mod tests {
    use rtnetlink::packet_route::route::RouteAttribute;

    use super::*;

    fn opts(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn test_parse_route_metric_options() {
        let config = parse_route_config(
            &opts(&[
                "10.0.0.0/8",
                "via",
                "192.0.2.1",
                "mtu",
                "1500",
                "advmss",
                "1400",
                "rtt",
                "100ms",
                "rttvar",
                "100ms",
                "reordering",
                "10",
                "window",
                "100",
                "cwnd",
                "10",
                "initcwnd",
                "10",
                "initrwnd",
                "10",
                "ssthresh",
                "100",
                "hoplimit",
                "64",
                "rto_min",
                "200ms",
                "features",
                "ecn",
                "tcp_usec_ts",
                "quickack",
                "1",
                "congctl",
                "cubic",
                "fastopen_no_cookie",
                "1",
                "realms",
                "10/20",
            ]),
            None,
        )
        .unwrap();

        assert_eq!(
            config.metrics,
            vec![
                RouteMetric::Mtu(1500),
                RouteMetric::Advmss(1400),
                RouteMetric::Rtt(800),
                RouteMetric::RttVar(400),
                RouteMetric::Reordering(10),
                RouteMetric::Window(100),
                RouteMetric::Cwnd(10),
                RouteMetric::InitCwnd(10),
                RouteMetric::InitRwnd(10),
                RouteMetric::SsThresh(100),
                RouteMetric::Hoplimit(64),
                RouteMetric::RtoMin(200),
                RouteMetric::Features(17),
                RouteMetric::QuickAck(1),
                RouteMetric::Other(DefaultNla::new(16, b"cubic".to_vec(),)),
                RouteMetric::FastopenNoCookie(1),
            ]
        );
        assert_eq!(
            config.realm,
            Some(RouteRealm {
                source: 10,
                destination: 20,
            })
        );
    }

    #[test]
    fn test_parse_route_time_metrics_raw() {
        let config = parse_route_config(
            &opts(&[
                "10.0.0.0/8",
                "rtt",
                "100",
                "rttvar",
                "50",
                "rto_min",
                "200",
            ]),
            None,
        )
        .unwrap();

        assert_eq!(
            config.metrics,
            vec![
                RouteMetric::Rtt(100),
                RouteMetric::RttVar(50),
                RouteMetric::RtoMin(200),
            ]
        );
    }

    #[test]
    fn test_parse_route_as_rejected() {
        let result = parse_route_config(
            &opts(&["10.0.0.0/8", "as", "to", "192.0.2.1"]),
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_build_route_metric_message() {
        let config = parse_route_config(
            &opts(&["10.0.0.0/8", "mtu", "1500", "realms", "1/2"]),
            None,
        )
        .unwrap();
        let msg = super::super::modify::build_route_message(&config).unwrap();

        assert!(
            msg.attributes.contains(&RouteAttribute::Metrics(vec![
                RouteMetric::Mtu(1500)
            ]))
        );
        assert!(msg.attributes.contains(&RouteAttribute::Realm(RouteRealm {
            source: 1,
            destination: 2,
        })));
    }
}
