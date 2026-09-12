// SPDX-License-Identifier: MIT

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use futures_util::TryStreamExt;
use rtnetlink::{
    packet_core::DefaultNla,
    packet_route::{
        AddressFamily,
        route::{
            Ioam6Mode, MplsLabel, RouteIp6TunnelFlags, RouteIpTunnelFlags,
            RouteMetric, RouteProtocol, RouteRealm, RouteScope, RouteType,
            Seg6LocalAction, Seg6LocalSrh, Seg6Mode,
        },
    },
};

use crate::CliError;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RouteNextHopConfig {
    pub(crate) via: Option<IpAddr>,
    pub(crate) dev: Option<String>,
    /// Weight as given on the command line (`1..=256`).
    pub(crate) weight: Option<u16>,
    pub(crate) onlink: bool,
    pub(crate) pervasive: bool,
}

/// `encap TYPE ...` of the `ip route` commands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RouteEncapOpt {
    Geneve {
        class: u16,
        typ: u8,
        data: Vec<u8>,
    },
    Vxlan {
        gbp: u32,
    },
    Erspan {
        ver: u8,
        index: Option<u32>,
        dir: Option<u8>,
        hwid: Option<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RouteEncapConfig {
    Mpls {
        dst: Vec<MplsLabel>,
        ttl: Option<u8>,
    },
    Ip {
        id: Option<u64>,
        dst: Option<Ipv4Addr>,
        src: Option<Ipv4Addr>,
        ttl: Option<u8>,
        tos: Option<u8>,
        flags: RouteIpTunnelFlags,
        opts: Vec<RouteEncapOpt>,
    },
    Ip6 {
        id: Option<u64>,
        dst: Option<Ipv6Addr>,
        src: Option<Ipv6Addr>,
        hoplimit: Option<u8>,
        tc: Option<u8>,
        flags: RouteIp6TunnelFlags,
        opts: Vec<RouteEncapOpt>,
    },
    Seg6 {
        mode: Seg6Mode,
        segs: Vec<Ipv6Addr>,
        tunsrc: Option<Ipv6Addr>,
        lookup: Option<u32>,
        hmac: Option<u32>,
    },
    Rpl {
        segs: Vec<Ipv6Addr>,
    },
    Ioam6 {
        freq_k: u32,
        freq_n: u32,
        mode: Ioam6Mode,
        tunsrc: Option<Ipv6Addr>,
        tundst: Option<Ipv6Addr>,
        trace_type: u32,
        ns: u16,
        size: u16,
    },
    Xfrm {
        if_id: u32,
        link_dev: Option<String>,
    },
    Seg6Local {
        action: Seg6LocalAction,
        table: Option<u32>,
        vrftable: Option<u32>,
        nh4: Option<Ipv4Addr>,
        nh6: Option<Ipv6Addr>,
        iif: Option<String>,
        oif: Option<String>,
        srh: Option<Seg6LocalSrh>,
    },
}

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
    pub(crate) nexthops: Vec<RouteNextHopConfig>,
    pub(crate) nhid: Option<u32>,
    pub(crate) tos: Option<u8>,
    pub(crate) ttl_propagate: Option<bool>,
    pub(crate) encap: Option<RouteEncapConfig>,
    /// `RTA_DST` of a `-f mpls` route.
    pub(crate) mpls_dst: Option<MplsLabel>,
    /// `as to LABEL` of a `-f mpls` route, the `RTA_NEWDST` label stack.
    pub(crate) mpls_newdst: Option<Vec<MplsLabel>>,
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
    let mut nexthops: Vec<RouteNextHopConfig> = Vec::new();
    let mut nhid: Option<u32> = None;
    let mut tos: Option<u8> = None;
    let mut ttl_propagate: Option<bool> = None;
    let mut encap: Option<RouteEncapConfig> = None;
    let mut mpls_dst: Option<MplsLabel> = None;
    let mut mpls_newdst: Option<Vec<MplsLabel>> = None;
    let mut positional_prefix_seen = false;

    let mut iter = opts.iter().peekable();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "via" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"via\" requires a value")
                })?;
                let (addr, fam) = parse_via_address(val, &mut iter)?;
                via = Some(addr);
                family = family.or(fam).or(addr_to_family(&addr));
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
            "tos" | "dsfield" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"tos\" requires a value")
                })?;
                tos = Some(parse_dsfield(val)?);
            }
            "ttl-propagate" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"ttl-propagate\" requires a value")
                })?;
                ttl_propagate = Some(match val.as_str() {
                    "enabled" => true,
                    "disabled" => false,
                    _ => {
                        return Err(CliError::from(format!(
                            "invalid ttl-propagate value: {val}"
                        )));
                    }
                });
            }
            "encap" => {
                encap = Some(parse_encap(&mut iter)?);
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
            "nhid" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"nhid\" requires a value")
                })?;
                nhid = Some(parse_u32_any_base(val)?);
            }
            "nexthop" => {
                nexthops.push(parse_one_nexthop(&mut iter, &mut family)?);
                while let Some(arg) = iter.peek() {
                    if arg.as_str() != "nexthop" {
                        return Err(CliError::from(format!(
                            "unexpected argument: {arg}"
                        )));
                    }
                    iter.next();
                    nexthops.push(parse_one_nexthop(&mut iter, &mut family)?);
                }
                break;
            }
            "as" => {
                // Only MPLS routes accept `as [to] LABEL`.
                if family != Some(AddressFamily::Mpls) {
                    return Err(CliError::from(format!(
                        "invalid argument: {arg}"
                    )));
                }
                let mut val = iter
                    .next()
                    .ok_or_else(|| CliError::from("\"as\" requires a value"))?;
                if val == "to" {
                    val = iter.next().ok_or_else(|| {
                        CliError::from("\"as to\" requires a value")
                    })?;
                }
                mpls_newdst = Some(parse_mpls_label_stack(val)?);
            }
            _ => {
                if !positional_prefix_seen {
                    // `iproute2` only parses a route type when the argument
                    // does not start with a digit, a MPLS label prefix or an
                    // inet prefix is a number as well.
                    let numeric =
                        arg.as_bytes().first().is_some_and(u8::is_ascii_digit);
                    if !numeric && let Ok(rt) = parse_route_type(arg) {
                        kind = Some(rt);
                        continue;
                    }
                    if family == Some(AddressFamily::Mpls) {
                        mpls_dst = Some(parse_mpls_dst_label(arg)?);
                        dst_len = 20;
                        positional_prefix_seen = true;
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
        nexthops,
        nhid,
        tos,
        ttl_propagate,
        encap,
        mpls_dst,
        mpls_newdst,
    })
}

fn encap_arg<'a>(
    iter: &mut std::iter::Peekable<impl Iterator<Item = &'a String>>,
    keyword: &str,
) -> Result<String, CliError> {
    iter.next().map(|val| val.to_string()).ok_or_else(|| {
        CliError::from(format!("\"{keyword}\" requires a value"))
    })
}

fn parse_encap<'a>(
    iter: &mut std::iter::Peekable<impl Iterator<Item = &'a String>>,
) -> Result<RouteEncapConfig, CliError> {
    let kind = iter.next().ok_or_else(|| {
        CliError::from("\"encap\" requires an encapsulation type")
    })?;

    match kind.as_str() {
        "mpls" => parse_encap_mpls(iter),
        "ip" => parse_encap_ip(iter),
        "ip6" => parse_encap_ip6(iter),
        "seg6" => parse_encap_seg6(iter),
        "seg6local" => parse_encap_seg6local(iter),
        "rpl" => parse_encap_rpl(iter),
        "ioam6" => parse_encap_ioam6(iter),
        "xfrm" => parse_encap_xfrm(iter),
        other => {
            Err(CliError::from(format!("unsupported encap type: {other}")))
        }
    }
}

// `iproute2` parses MPLS addresses as a `/` separated label stack, only the
// last label has the bottom of stack bit set.
fn parse_mpls_label_stack(stack: &str) -> Result<Vec<MplsLabel>, CliError> {
    let labels: Vec<&str> = stack.split('/').collect();
    let mut ret = Vec::with_capacity(labels.len());

    for (index, label) in labels.iter().enumerate() {
        let value = label.parse::<u32>().map_err(|_| {
            CliError::from(format!("invalid MPLS label: {label}"))
        })?;
        if value >= 1 << 20 {
            return Err(CliError::from(format!(
                "MPLS label out of range: {label}"
            )));
        }
        ret.push(MplsLabel {
            label: value,
            traffic_class: 0,
            bottom_of_stack: index == labels.len() - 1,
            ttl: 0,
        });
    }

    Ok(ret)
}

// `iproute2` parses the prefix of a `-f mpls` route as a single label, the
// `/` separator is only used for the prefix length of inet routes.
fn parse_mpls_dst_label(value: &str) -> Result<MplsLabel, CliError> {
    let label = value
        .parse::<u32>()
        .map_err(|_| CliError::from(format!("invalid MPLS label: {value}")))?;
    if label >= 1 << 20 {
        return Err(CliError::from(format!(
            "MPLS label out of range: {value}"
        )));
    }
    Ok(MplsLabel {
        label,
        traffic_class: 0,
        bottom_of_stack: true,
        ttl: 0,
    })
}

fn parse_encap_u64(value: &str) -> Result<u64, CliError> {
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).map_err(|_| {
            CliError::from(format!("invalid encapsulation id: {value}"))
        })
    } else {
        value.parse::<u64>().map_err(|_| {
            CliError::from(format!("invalid encapsulation id: {value}"))
        })
    }
}

fn parse_encap_ipv4(value: &str) -> Result<Ipv4Addr, CliError> {
    value
        .parse::<Ipv4Addr>()
        .map_err(|_| CliError::from(format!("invalid IPv4 address: {value}")))
}

fn parse_encap_ipv6(value: &str) -> Result<Ipv6Addr, CliError> {
    value
        .parse::<Ipv6Addr>()
        .map_err(|_| CliError::from(format!("invalid IPv6 address: {value}")))
}

fn parse_encap_u8(value: &str, keyword: &str) -> Result<u8, CliError> {
    let parsed = parse_u32_any_base(value).map_err(|_| {
        CliError::from(format!("invalid \"{keyword}\" value: {value}"))
    })?;
    if parsed > u32::from(u8::MAX) {
        return Err(CliError::from(format!(
            "invalid \"{keyword}\" value: {value}"
        )));
    }
    Ok(parsed as u8)
}

fn parse_encap_mpls<'a>(
    iter: &mut std::iter::Peekable<impl Iterator<Item = &'a String>>,
) -> Result<RouteEncapConfig, CliError> {
    let stack = iter
        .next()
        .ok_or_else(|| CliError::from("encap mpls requires a label stack"))?;
    let dst = parse_mpls_label_stack(stack)?;
    let mut ttl: Option<u8> = None;

    while let Some(raw_arg) = iter.peek() {
        let arg = raw_arg.to_string();
        match arg.as_str() {
            "ttl" => {
                iter.next();
                let val = encap_arg(iter, "ttl")?;
                ttl = Some(parse_encap_u8(&val, "ttl")?);
            }
            _ => break,
        }
    }

    Ok(RouteEncapConfig::Mpls { dst, ttl })
}

fn parse_encap_ip<'a>(
    iter: &mut std::iter::Peekable<impl Iterator<Item = &'a String>>,
) -> Result<RouteEncapConfig, CliError> {
    let mut id: Option<u64> = None;
    let mut dst: Option<Ipv4Addr> = None;
    let mut src: Option<Ipv4Addr> = None;
    let mut ttl: Option<u8> = None;
    let mut tos: Option<u8> = None;
    let mut flags = RouteIpTunnelFlags::empty();
    let mut opts: Vec<RouteEncapOpt> = Vec::new();

    while let Some(raw_arg) = iter.peek() {
        let arg = raw_arg.to_string();
        match arg.as_str() {
            "id" => {
                iter.next();
                let val = encap_arg(iter, "id")?;
                id = Some(parse_encap_u64(&val)?);
            }
            "dst" => {
                iter.next();
                let val = encap_arg(iter, "dst")?;
                dst = Some(parse_encap_ipv4(&val)?);
            }
            "src" => {
                iter.next();
                let val = encap_arg(iter, "src")?;
                src = Some(parse_encap_ipv4(&val)?);
            }
            "ttl" => {
                iter.next();
                let val = encap_arg(iter, "ttl")?;
                ttl = Some(parse_encap_u8(&val, "ttl")?);
            }
            "tos" => {
                iter.next();
                let val = encap_arg(iter, "tos")?;
                tos = Some(parse_dsfield(&val)?);
            }
            "key" => {
                iter.next();
                flags |= RouteIpTunnelFlags::Key;
            }
            "csum" => {
                iter.next();
                flags |= RouteIpTunnelFlags::Checksum;
            }
            "seq" => {
                iter.next();
                flags |= RouteIpTunnelFlags::Sequence;
            }
            "geneve_opts" | "vxlan_opts" | "erspan_opts" => {
                iter.next();
                let val = encap_arg(iter, &arg)?;
                opts.extend(parse_encap_opts(&arg, &val)?);
            }
            _ => break,
        }
    }

    Ok(RouteEncapConfig::Ip {
        id,
        dst,
        src,
        ttl,
        tos,
        flags,
        opts,
    })
}

fn parse_encap_ip6<'a>(
    iter: &mut std::iter::Peekable<impl Iterator<Item = &'a String>>,
) -> Result<RouteEncapConfig, CliError> {
    let mut id: Option<u64> = None;
    let mut dst: Option<Ipv6Addr> = None;
    let mut src: Option<Ipv6Addr> = None;
    let mut hoplimit: Option<u8> = None;
    let mut tc: Option<u8> = None;
    let mut flags = RouteIp6TunnelFlags::empty();
    let mut opts: Vec<RouteEncapOpt> = Vec::new();

    while let Some(raw_arg) = iter.peek() {
        let arg = raw_arg.to_string();
        match arg.as_str() {
            "id" => {
                iter.next();
                let val = encap_arg(iter, "id")?;
                id = Some(parse_encap_u64(&val)?);
            }
            "dst" => {
                iter.next();
                let val = encap_arg(iter, "dst")?;
                dst = Some(parse_encap_ipv6(&val)?);
            }
            "src" => {
                iter.next();
                let val = encap_arg(iter, "src")?;
                src = Some(parse_encap_ipv6(&val)?);
            }
            "hoplimit" => {
                iter.next();
                let val = encap_arg(iter, "hoplimit")?;
                hoplimit = Some(parse_encap_u8(&val, "hoplimit")?);
            }
            "tc" => {
                iter.next();
                let val = encap_arg(iter, "tc")?;
                tc = Some(parse_dsfield(&val)?);
            }
            "key" => {
                iter.next();
                flags |= RouteIp6TunnelFlags::Key;
            }
            "csum" => {
                iter.next();
                flags |= RouteIp6TunnelFlags::Checksum;
            }
            "seq" => {
                iter.next();
                flags |= RouteIp6TunnelFlags::Sequence;
            }
            "geneve_opts" | "vxlan_opts" | "erspan_opts" => {
                iter.next();
                let val = encap_arg(iter, &arg)?;
                opts.extend(parse_encap_opts(&arg, &val)?);
            }
            _ => break,
        }
    }

    Ok(RouteEncapConfig::Ip6 {
        id,
        dst,
        src,
        hoplimit,
        tc,
        flags,
        opts,
    })
}

fn parse_encap_seg6<'a>(
    iter: &mut std::iter::Peekable<impl Iterator<Item = &'a String>>,
) -> Result<RouteEncapConfig, CliError> {
    let mut mode: Option<Seg6Mode> = None;
    let mut segs: Option<Vec<Ipv6Addr>> = None;
    let mut tunsrc: Option<Ipv6Addr> = None;
    let mut lookup: Option<u32> = None;
    let mut hmac: Option<u32> = None;

    while let Some(raw_arg) = iter.peek() {
        let arg = raw_arg.to_string();
        match arg.as_str() {
            "mode" => {
                iter.next();
                let val = encap_arg(iter, "mode")?;
                mode = Some(match val.as_str() {
                    "inline" => Seg6Mode::Inline,
                    "encap" => Seg6Mode::Encap,
                    _ => {
                        return Err(CliError::from(format!(
                            "invalid seg6 mode: {val}"
                        )));
                    }
                });
            }
            "segs" => {
                iter.next();
                let val = encap_arg(iter, "segs")?;
                let mut list = Vec::new();
                for segment in val.split(',') {
                    list.push(parse_encap_ipv6(segment)?);
                }
                segs = Some(list);
            }
            "tunsrc" => {
                iter.next();
                let val = encap_arg(iter, "tunsrc")?;
                tunsrc = Some(parse_encap_ipv6(&val)?);
            }
            "lookup" => {
                iter.next();
                let val = encap_arg(iter, "lookup")?;
                lookup = Some(parse_table_id(&val)?);
            }
            "hmac" => {
                iter.next();
                let val = encap_arg(iter, "hmac")?;
                hmac = Some(parse_u32_any_base(&val)?);
            }
            _ => break,
        }
    }

    let mode = mode.ok_or_else(|| {
        CliError::from("encap seg6 requires a \"mode\" value")
    })?;

    Ok(RouteEncapConfig::Seg6 {
        mode,
        segs: segs.unwrap_or_default(),
        tunsrc,
        lookup,
        hmac,
    })
}

fn parse_seg6local_action(action: &str) -> Result<Seg6LocalAction, CliError> {
    Ok(match action {
        "End" => Seg6LocalAction::End,
        "End.X" => Seg6LocalAction::EndX,
        "End.T" => Seg6LocalAction::EndT,
        "End.DX2" => Seg6LocalAction::EndDx2,
        "End.DX6" => Seg6LocalAction::EndDx6,
        "End.DX4" => Seg6LocalAction::EndDx4,
        "End.DT6" => Seg6LocalAction::EndDt6,
        "End.DT4" => Seg6LocalAction::EndDt4,
        "End.B6" => Seg6LocalAction::EndB6,
        "End.B6.Encaps" => Seg6LocalAction::EndB6Encap,
        "End.BM" => Seg6LocalAction::EndBm,
        "End.S" => Seg6LocalAction::EndS,
        "End.AS" => Seg6LocalAction::EndAs,
        "End.AM" => Seg6LocalAction::EndAm,
        "End.BPF" => Seg6LocalAction::EndBpf,
        "End.DT46" => Seg6LocalAction::EndDt46,
        _ => {
            return Err(CliError::from(format!(
                "invalid seg6local action: {action}"
            )));
        }
    })
}

/// Builds the SRH of `encap seg6local srh segs ...` like iproute2 does:
/// the segments are stored in the reversed order and every action but
/// `End.B6.Encaps` gets an extra zeroed segment.
fn build_seg6local_srh(
    action: Seg6LocalAction,
    mut segments: Vec<Ipv6Addr>,
) -> Seg6LocalSrh {
    if action != Seg6LocalAction::EndB6Encap {
        segments.push(Ipv6Addr::UNSPECIFIED);
    }
    let segment_count = segments.len() as u8;
    let mut srh = Seg6LocalSrh::default();
    srh.routing_type = 4;
    srh.segments_left = segment_count - 1;
    srh.first_segment = segment_count - 1;
    srh.segments = segments.into_iter().rev().collect();
    srh
}

fn parse_encap_seg6local<'a>(
    iter: &mut std::iter::Peekable<impl Iterator<Item = &'a String>>,
) -> Result<RouteEncapConfig, CliError> {
    let mut action: Option<Seg6LocalAction> = None;
    let mut table: Option<u32> = None;
    let mut vrftable: Option<u32> = None;
    let mut nh4: Option<Ipv4Addr> = None;
    let mut nh6: Option<Ipv6Addr> = None;
    let mut iif: Option<String> = None;
    let mut oif: Option<String> = None;
    let mut srh: Option<Seg6LocalSrh> = None;

    while let Some(raw_arg) = iter.peek() {
        let arg = raw_arg.to_string();
        match arg.as_str() {
            "action" => {
                iter.next();
                let val = encap_arg(iter, "action")?;
                action = Some(parse_seg6local_action(&val)?);
            }
            "table" => {
                iter.next();
                let val = encap_arg(iter, "table")?;
                table = Some(parse_table_id(&val)?);
            }
            "vrftable" => {
                iter.next();
                let val = encap_arg(iter, "vrftable")?;
                vrftable = Some(parse_table_id(&val)?);
            }
            "nh4" => {
                iter.next();
                let val = encap_arg(iter, "nh4")?;
                nh4 = Some(parse_encap_ipv4(&val)?);
            }
            "nh6" => {
                iter.next();
                let val = encap_arg(iter, "nh6")?;
                nh6 = Some(parse_encap_ipv6(&val)?);
            }
            "iif" => {
                iter.next();
                iif = Some(encap_arg(iter, "iif")?);
            }
            "oif" => {
                iter.next();
                oif = Some(encap_arg(iter, "oif")?);
            }
            "srh" => {
                iter.next();
                let val = encap_arg(iter, "srh")?;
                if val != "segs" {
                    return Err(CliError::from(
                        "encap seg6local srh requires \"segs\"",
                    ));
                }
                let val = encap_arg(iter, "segs")?;
                let mut segments = Vec::new();
                for segment in val.split(',') {
                    segments.push(parse_encap_ipv6(segment)?);
                }
                let selected = action.ok_or_else(|| {
                    CliError::from(
                        "encap seg6local requires an \"action\" before \"srh\"",
                    )
                })?;
                srh = Some(build_seg6local_srh(selected, segments));
            }
            // `count`, `flavors` and `endpoint` are not supported yet.
            "count" | "flavors" | "endpoint" => {
                return Err(CliError::from(format!(
                    "encap seg6local {arg} is not supported"
                )));
            }
            _ => break,
        }
    }

    Ok(RouteEncapConfig::Seg6Local {
        action: action.ok_or_else(|| {
            CliError::from("encap seg6local requires an \"action\" value")
        })?,
        table,
        vrftable,
        nh4,
        nh6,
        iif,
        oif,
        srh,
    })
}

fn parse_hex_bytes(value: &str) -> Result<Vec<u8>, CliError> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    if !value.len().is_multiple_of(2)
        || !value.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(CliError::from(format!(
            "invalid hexadecimal value: {value}"
        )));
    }
    let mut ret = Vec::new();
    for start in (0..value.len()).step_by(2) {
        ret.push(u8::from_str_radix(&value[start..start + 2], 16).map_err(
            |_| CliError::from(format!("invalid hexadecimal value: {value}")),
        )?);
    }
    Ok(ret)
}

fn parse_encap_u16(value: &str, keyword: &str) -> Result<u16, CliError> {
    let parsed = parse_u32_any_base(value)?;
    if parsed > u32::from(u16::MAX) {
        return Err(CliError::from(format!(
            "invalid {keyword} value: {value}"
        )));
    }
    Ok(parsed as u16)
}

// `geneve_opts CLASS:TYPE:DATA[,CLASS:TYPE:DATA...]`, `vxlan_opts GBP` and
// `erspan_opts VER:INDEX:DIR:HWID` of `encap ip` and `encap ip6`.
fn parse_encap_opts(
    keyword: &str,
    value: &str,
) -> Result<Vec<RouteEncapOpt>, CliError> {
    match keyword {
        "geneve_opts" => {
            let mut ret = Vec::new();
            for opt in value.split(',') {
                let (class, rest) = opt.split_once(':').ok_or_else(|| {
                    CliError::from(format!("invalid geneve_opts value: {opt}"))
                })?;
                let (typ, data) = rest.split_once(':').ok_or_else(|| {
                    CliError::from(format!("invalid geneve_opts value: {opt}"))
                })?;
                ret.push(RouteEncapOpt::Geneve {
                    class: parse_encap_u16(class, "geneve_opts class")?,
                    typ: parse_encap_u8(typ, "geneve_opts type")?,
                    data: parse_hex_bytes(data)?,
                });
            }
            Ok(ret)
        }
        "vxlan_opts" => Ok(vec![RouteEncapOpt::Vxlan {
            gbp: parse_u32_any_base(value)?,
        }]),
        "erspan_opts" => {
            let mut tokens = value.split(':');
            let ver = tokens
                .next()
                .ok_or_else(|| {
                    CliError::from(format!(
                        "invalid erspan_opts value: {value}"
                    ))
                })
                .and_then(|ver| parse_encap_u8(ver, "erspan_opts ver"))?;
            let index = match tokens.next() {
                Some("") | None => None,
                Some(index) => Some(parse_u32_any_base(index)?),
            };
            let dir = match tokens.next() {
                Some("") | None => None,
                Some(dir) => Some(parse_encap_u8(dir, "erspan_opts dir")?),
            };
            let hwid = match tokens.next() {
                Some("") | None => None,
                Some(hwid) => Some(parse_encap_u8(hwid, "erspan_opts hwid")?),
            };
            if tokens.next().is_some() {
                return Err(CliError::from(format!(
                    "invalid erspan_opts value: {value}"
                )));
            }
            Ok(vec![RouteEncapOpt::Erspan {
                ver,
                index,
                dir,
                hwid,
            }])
        }
        _ => Err(CliError::from(format!(
            "unsupported encapsulation option: {keyword}"
        ))),
    }
}

// `encap rpl segs ADDR[,ADDR...]` of `iproute2`.
fn parse_encap_rpl<'a>(
    iter: &mut std::iter::Peekable<impl Iterator<Item = &'a String>>,
) -> Result<RouteEncapConfig, CliError> {
    let mut segs: Option<Vec<Ipv6Addr>> = None;

    while let Some(raw_arg) = iter.peek() {
        let arg = raw_arg.to_string();
        match arg.as_str() {
            "segs" => {
                iter.next();
                let val = encap_arg(iter, "segs")?;
                let mut list = Vec::new();
                for segment in val.split(',') {
                    list.push(parse_encap_ipv6(segment)?);
                }
                segs = Some(list);
            }
            _ => break,
        }
    }

    let segs = segs
        .ok_or_else(|| CliError::from("encap rpl requires a \"segs\" value"))?;

    Ok(RouteEncapConfig::Rpl { segs })
}

// `encap ioam6 ...` of `iproute2`:
//   [ freq K/N ] [ mode MODE ] [ tunsrc ADDR ] tundst ADDR trace prealloc
//   [ type TYPE ] [ ns NS ] [ size SIZE ]
fn parse_encap_ioam6<'a>(
    iter: &mut std::iter::Peekable<impl Iterator<Item = &'a String>>,
) -> Result<RouteEncapConfig, CliError> {
    let mut freq_k: u32 = 1;
    let mut freq_n: u32 = 1;
    let mut mode = Ioam6Mode::Inline;
    let mut tunsrc: Option<Ipv6Addr> = None;
    let mut tundst: Option<Ipv6Addr> = None;
    let mut trace_type: Option<u32> = None;
    let mut ns: Option<u16> = None;
    let mut size: Option<u16> = None;
    let mut trace = false;
    let mut prealloc = false;

    while let Some(raw_arg) = iter.peek() {
        let arg = raw_arg.to_string();
        match arg.as_str() {
            "freq" => {
                iter.next();
                let val = encap_arg(iter, "freq")?;
                let (k, n) = val.split_once('/').ok_or_else(|| {
                    CliError::from(format!("invalid ioam6 frequency: {val}"))
                })?;
                freq_k = k.parse::<u32>().map_err(|_| {
                    CliError::from(format!("invalid ioam6 frequency: {val}"))
                })?;
                freq_n = n.parse::<u32>().map_err(|_| {
                    CliError::from(format!("invalid ioam6 frequency: {val}"))
                })?;
            }
            "mode" => {
                iter.next();
                let val = encap_arg(iter, "mode")?;
                mode = match val.as_str() {
                    "inline" => Ioam6Mode::Inline,
                    "encap" => Ioam6Mode::Encap,
                    "auto" => Ioam6Mode::Auto,
                    _ => {
                        return Err(CliError::from(format!(
                            "invalid ioam6 mode: {val}"
                        )));
                    }
                };
            }
            "tunsrc" => {
                iter.next();
                let val = encap_arg(iter, "tunsrc")?;
                tunsrc = Some(parse_encap_ipv6(&val)?);
            }
            "tundst" => {
                iter.next();
                let val = encap_arg(iter, "tundst")?;
                tundst = Some(parse_encap_ipv6(&val)?);
            }
            "trace" => {
                iter.next();
                trace = true;
            }
            "prealloc" => {
                iter.next();
                prealloc = true;
            }
            "type" => {
                iter.next();
                let val = encap_arg(iter, "type")?;
                trace_type = Some(parse_u32_any_base(&val)?);
            }
            "ns" => {
                iter.next();
                let val = encap_arg(iter, "ns")?;
                ns = Some(val.parse::<u16>().map_err(|_| {
                    CliError::from(format!("invalid ioam6 namespace ID: {val}"))
                })?);
            }
            "size" => {
                iter.next();
                let val = encap_arg(iter, "size")?;
                size = Some(val.parse::<u16>().map_err(|_| {
                    CliError::from(format!("invalid ioam6 trace size: {val}"))
                })?);
            }
            _ => break,
        }
    }

    if mode != Ioam6Mode::Inline && tundst.is_none() {
        return Err(CliError::from(
            "encap ioam6 requires a \"tundst\" value unless the mode is inline",
        ));
    }
    if !trace || !prealloc {
        return Err(CliError::from(
            "encap ioam6 requires the \"trace prealloc\" options",
        ));
    }
    let trace_type = trace_type.ok_or_else(|| {
        CliError::from("encap ioam6 requires a \"type\" value")
    })?;
    let ns = ns
        .ok_or_else(|| CliError::from("encap ioam6 requires a \"ns\" value"))?;
    let size = size.ok_or_else(|| {
        CliError::from("encap ioam6 requires a \"size\" value")
    })?;

    Ok(RouteEncapConfig::Ioam6 {
        freq_k,
        freq_n,
        mode,
        tunsrc,
        tundst,
        trace_type,
        ns,
        size,
    })
}

fn parse_encap_xfrm<'a>(
    iter: &mut std::iter::Peekable<impl Iterator<Item = &'a String>>,
) -> Result<RouteEncapConfig, CliError> {
    let mut if_id: Option<u32> = None;
    let mut link_dev: Option<String> = None;

    while let Some(raw_arg) = iter.peek() {
        let arg = raw_arg.to_string();
        match arg.as_str() {
            "if_id" => {
                iter.next();
                let val = encap_arg(iter, "if_id")?;
                let id = parse_mark_value(&val)?;
                if id == 0 {
                    return Err(CliError::from("invalid \"if_id\" value: 0"));
                }
                if_id = Some(id);
            }
            "link_dev" => {
                iter.next();
                link_dev = Some(encap_arg(iter, "link_dev")?);
            }
            _ => break,
        }
    }

    Ok(RouteEncapConfig::Xfrm {
        if_id: if_id.ok_or_else(|| {
            CliError::from("encap xfrm requires an \"if_id\" value")
        })?,
        link_dev,
    })
}

fn parse_one_nexthop<'a>(
    iter: &mut std::iter::Peekable<impl Iterator<Item = &'a String>>,
    family: &mut Option<AddressFamily>,
) -> Result<RouteNextHopConfig, CliError> {
    let mut nexthop = RouteNextHopConfig::default();

    while let Some(raw_arg) = iter.peek() {
        let arg = raw_arg.to_string();
        match arg.as_str() {
            "via" => {
                iter.next();
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"via\" requires a value")
                })?;
                let (addr, _) = parse_via_address(val, iter)?;
                nexthop.via = Some(addr);
                // The route address family is only taken from the first
                // nexthop when it was not determined by the command line
                // family option or the destination prefix.
                if family.is_none() {
                    *family = addr_to_family(&addr);
                }
            }
            "dev" => {
                iter.next();
                nexthop.dev = Some(
                    iter.next()
                        .ok_or_else(|| {
                            CliError::from("\"dev\" requires a value")
                        })?
                        .clone(),
                );
            }
            "weight" => {
                iter.next();
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"weight\" requires a value")
                })?;
                let weight = parse_u32_any_base(val)?;
                if weight == 0 || weight > 256 {
                    return Err(CliError::from(format!(
                        "invalid weight value: {val}"
                    )));
                }
                nexthop.weight = Some(weight as u16);
            }
            "onlink" => {
                iter.next();
                nexthop.onlink = true;
            }
            "pervasive" => {
                iter.next();
                nexthop.pervasive = true;
            }
            _ => break,
        }
    }

    Ok(nexthop)
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
            (addr, addr_to_family(&addr))
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

fn parse_dsfield(s: &str) -> Result<u8, CliError> {
    let named = match s {
        "default" => Some(0x00),
        "CS1" => Some(0x20),
        "CS2" => Some(0x40),
        "CS3" => Some(0x60),
        "CS4" => Some(0x80),
        "CS5" => Some(0xa0),
        "CS6" => Some(0xc0),
        "CS7" => Some(0xe0),
        "AF11" => Some(0x28),
        "AF12" => Some(0x30),
        "AF13" => Some(0x38),
        "AF21" => Some(0x48),
        "AF22" => Some(0x50),
        "AF23" => Some(0x58),
        "AF31" => Some(0x68),
        "AF32" => Some(0x70),
        "AF33" => Some(0x78),
        "AF41" => Some(0x88),
        "AF42" => Some(0x90),
        "AF43" => Some(0x98),
        "EF" => Some(0xb8),
        _ => None,
    };
    if let Some(value) = named {
        return Ok(value);
    }

    // iproute2 parses the numeric value as hexadecimal.
    let digits = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    let value = u16::from_str_radix(digits, 16)
        .map_err(|_| CliError::from(format!("invalid tos value: {s}")))?;
    if value > u8::MAX as u16 {
        return Err(CliError::from(format!("invalid tos value: {s}")));
    }
    Ok(value as u8)
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

pub(crate) async fn resolve_route_ifindexes(
    handle: &rtnetlink::Handle,
    config: &RouteAddConfig,
) -> Result<std::collections::HashMap<String, u32>, CliError> {
    let mut indexes = std::collections::HashMap::new();

    let dev_names = config
        .dev
        .iter()
        .chain(config.nexthops.iter().filter_map(|nh| nh.dev.as_ref()))
        .chain(config.encap.iter().filter_map(|encap| match encap {
            RouteEncapConfig::Xfrm { link_dev, .. } => link_dev.as_ref(),
            _ => None,
        }))
        .chain(config.encap.iter().flat_map(|encap| match encap {
            RouteEncapConfig::Seg6Local { iif, oif, .. } => {
                [iif.as_ref(), oif.as_ref()].into_iter().flatten()
            }
            _ => [None, None].into_iter().flatten(),
        }));
    for name in dev_names {
        if indexes.contains_key(name) {
            continue;
        }
        let index = resolve_ifindex(handle, name).await?;
        indexes.insert(name.clone(), index);
    }

    Ok(indexes)
}

#[cfg(test)]
mod tests {
    use rtnetlink::packet_route::route::{
        RouteAttribute, RouteMplsTtlPropagation, RouteNextHopFlags, RouteVia,
    };

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
        let msg = super::super::modify::build_route_message(
            &config,
            &Default::default(),
            false,
        )
        .unwrap();

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

    #[test]
    fn test_parse_route_multipath() {
        let config = parse_route_config(
            &opts(&[
                "10.109.0.0/16",
                "nexthop",
                "via",
                "10.0.0.254",
                "dev",
                "test-dummy",
                "weight",
                "1",
                "nexthop",
                "via",
                "10.0.0.253",
                "dev",
                "test-dummy",
                "weight",
                "2",
                "onlink",
            ]),
            None,
        )
        .unwrap();

        assert_eq!(config.nexthops.len(), 2);
        assert_eq!(
            config.nexthops[0],
            RouteNextHopConfig {
                via: Some("10.0.0.254".parse().unwrap()),
                dev: Some("test-dummy".to_string()),
                weight: Some(1),
                onlink: false,
                pervasive: false,
            }
        );
        assert_eq!(
            config.nexthops[1],
            RouteNextHopConfig {
                via: Some("10.0.0.253".parse().unwrap()),
                dev: Some("test-dummy".to_string()),
                weight: Some(2),
                onlink: true,
                pervasive: false,
            }
        );
    }

    #[test]
    fn test_parse_route_nhid_and_pervasive() {
        let config = parse_route_config(
            &opts(&[
                "10.109.0.0/16",
                "nhid",
                "10",
                "nexthop",
                "via",
                "10.0.0.254",
                "dev",
                "test-dummy",
                "pervasive",
            ]),
            None,
        )
        .unwrap();

        assert_eq!(config.nhid, Some(10));
        assert_eq!(config.nexthops.len(), 1);
        assert!(config.nexthops[0].pervasive);
    }

    #[test]
    fn test_parse_route_nexthop_weight_bounds() {
        assert!(
            parse_route_config(
                &opts(&["10.0.0.0/8", "nexthop", "weight", "0"]),
                None,
            )
            .is_err()
        );
        assert!(
            parse_route_config(
                &opts(&["10.0.0.0/8", "nexthop", "weight", "257"]),
                None,
            )
            .is_err()
        );

        let config = parse_route_config(
            &opts(&["10.0.0.0/8", "nexthop", "weight", "256"]),
            None,
        )
        .unwrap();
        assert_eq!(config.nexthops[0].weight, Some(256));
    }

    #[test]
    fn test_build_route_multipath_message() {
        let config = parse_route_config(
            &opts(&[
                "10.109.0.0/16",
                "nexthop",
                "via",
                "10.0.0.254",
                "weight",
                "2",
                "pervasive",
                "nexthop",
                "via",
                "inet6",
                "2001:db8::1",
            ]),
            None,
        )
        .unwrap();
        let msg = super::super::modify::build_route_message(
            &config,
            &Default::default(),
            false,
        )
        .unwrap();

        let Some(RouteAttribute::MultiPath(nexthops)) = msg
            .attributes
            .iter()
            .find(|attr| matches!(attr, RouteAttribute::MultiPath(_)))
        else {
            panic!("multipath attribute not found");
        };

        assert_eq!(nexthops.len(), 2);
        assert_eq!(nexthops[0].hops, 1);
        assert!(nexthops[0].flags.contains(RouteNextHopFlags::Pervasive));
        assert_eq!(
            nexthops[0].attributes,
            vec![RouteAttribute::Gateway(
                "10.0.0.254".parse::<Ipv4Addr>().unwrap().into()
            )]
        );
        assert_eq!(
            nexthops[1].attributes,
            vec![RouteAttribute::Via(RouteVia::Inet6(
                "2001:db8::1".parse().unwrap()
            ))]
        );
    }

    #[test]
    fn test_build_route_nhid_message() {
        let config =
            parse_route_config(&opts(&["10.111.0.0/16", "nhid", "10"]), None)
                .unwrap();
        let msg = super::super::modify::build_route_message(
            &config,
            &Default::default(),
            false,
        )
        .unwrap();

        assert!(msg.attributes.contains(&RouteAttribute::NhId(10)));
        assert_eq!(msg.header.scope, RouteScope::Universe);
    }

    #[test]
    fn test_parse_route_nexthop_family() {
        // The destination prefix fixes the route family: a nexthop using
        // another family must not change it.
        let config = parse_route_config(
            &opts(&["10.112.0.0/16", "nexthop", "via", "inet6", "2001:db8::2"]),
            None,
        )
        .unwrap();
        assert_eq!(config.family, Some(AddressFamily::Inet));
        assert_eq!(
            config.nexthops[0].via,
            Some("2001:db8::2".parse().unwrap())
        );

        // Without a prefix the family is taken from the first nexthop.
        let config = parse_route_config(
            &opts(&["nexthop", "via", "inet6", "2001:db8::2"]),
            None,
        )
        .unwrap();
        assert_eq!(config.family, Some(AddressFamily::Inet6));
    }

    #[test]
    fn test_parse_route_dsfield() {
        let config =
            parse_route_config(&opts(&["10.0.0.0/8", "tos", "AF11"]), None)
                .unwrap();
        assert_eq!(config.tos, Some(0x28));

        // iproute2 parses numeric DS fields as hexadecimal.
        let config =
            parse_route_config(&opts(&["10.0.0.0/8", "dsfield", "28"]), None)
                .unwrap();
        assert_eq!(config.tos, Some(0x28));

        let config =
            parse_route_config(&opts(&["10.0.0.0/8", "tos", "0xB8"]), None)
                .unwrap();
        assert_eq!(config.tos, Some(0xb8));

        // iproute2 rejects lowercase names and values above 0xff.
        assert!(
            parse_route_config(&opts(&["10.0.0.0/8", "tos", "af11"]), None)
                .is_err()
        );
        assert!(
            parse_route_config(&opts(&["10.0.0.0/8", "tos", "0x100"]), None)
                .is_err()
        );
    }

    #[test]
    fn test_parse_route_ttl_propagate() {
        let config = parse_route_config(
            &opts(&["10.0.0.0/8", "ttl-propagate", "enabled"]),
            None,
        )
        .unwrap();
        assert_eq!(config.ttl_propagate, Some(true));

        let config = parse_route_config(
            &opts(&["10.0.0.0/8", "ttl-propagate", "disabled"]),
            None,
        )
        .unwrap();
        assert_eq!(config.ttl_propagate, Some(false));

        assert!(
            parse_route_config(
                &opts(&["10.0.0.0/8", "ttl-propagate", "foo"]),
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn test_build_route_tos_and_ttl_propagate_message() {
        let config = parse_route_config(
            &opts(&["10.0.0.0/8", "tos", "AF11", "ttl-propagate", "disabled"]),
            None,
        )
        .unwrap();
        let msg = super::super::modify::build_route_message(
            &config,
            &Default::default(),
            false,
        )
        .unwrap();

        assert_eq!(msg.header.tos, 0x28);
        assert!(msg.attributes.contains(&RouteAttribute::TtlPropagate(
            RouteMplsTtlPropagation::Disabled
        )));
    }

    #[test]
    fn test_build_route_scope() {
        let scope =
            |args: &[&str], family: Option<AddressFamily>, is_delete: bool| {
                let config = parse_route_config(&opts(args), family).unwrap();
                super::super::modify::build_route_message(
                    &config,
                    &Default::default(),
                    is_delete,
                )
                .unwrap()
                .header
                .scope
            };

        // IPv4 unicast without gateway uses link scope.
        assert_eq!(scope(&["10.0.0.0/8"], None, false), RouteScope::Link);
        assert_eq!(
            scope(&["10.0.0.0/8", "pref", "low"], None, false),
            RouteScope::Link
        );

        // A gateway or nexthop ID makes the route global.
        assert_eq!(
            scope(&["10.0.0.0/8", "via", "192.0.2.1"], None, false),
            RouteScope::Universe
        );
        assert_eq!(
            scope(&["10.0.0.0/8", "nexthop", "via", "192.0.2.1"], None, false),
            RouteScope::Universe
        );
        assert_eq!(
            scope(&["10.0.0.0/8", "nhid", "10"], None, false),
            RouteScope::Universe
        );

        // IPv6 and MPLS always default to universe.
        assert_eq!(
            scope(&["2001:db8::/64"], Some(AddressFamily::Inet6), false),
            RouteScope::Universe
        );
        assert_eq!(
            scope(&["2001:db8::/64"], Some(AddressFamily::Inet6), true),
            RouteScope::Universe
        );

        // Other IPv4 route types.
        assert_eq!(
            scope(&["local", "10.0.0.1/32"], None, false),
            RouteScope::Host
        );
        assert_eq!(
            scope(&["blackhole", "10.0.0.0/8"], None, false),
            RouteScope::Universe
        );

        // Deleting an IPv4 route uses `nowhere` as the scope wildcard.
        assert_eq!(scope(&["10.0.0.0/8"], None, true), RouteScope::NoWhere);

        // An explicit scope always wins.
        assert_eq!(
            scope(&["10.0.0.0/8", "scope", "host"], None, false),
            RouteScope::Host
        );
    }

    #[test]
    fn test_parse_route_encap_mpls() {
        let config = parse_route_config(
            &opts(&["10.0.0.0/8", "encap", "mpls", "100/200", "dev", "d0"]),
            None,
        )
        .unwrap();
        assert_eq!(
            config.encap,
            Some(RouteEncapConfig::Mpls {
                dst: vec![
                    MplsLabel {
                        label: 100,
                        traffic_class: 0,
                        bottom_of_stack: false,
                        ttl: 0,
                    },
                    MplsLabel {
                        label: 200,
                        traffic_class: 0,
                        bottom_of_stack: true,
                        ttl: 0,
                    },
                ],
                ttl: None,
            })
        );

        let config = parse_route_config(
            &opts(&[
                "10.0.0.0/8",
                "encap",
                "mpls",
                "100",
                "ttl",
                "64",
                "dev",
                "d0",
            ]),
            None,
        )
        .unwrap();
        assert_eq!(
            config.encap,
            Some(RouteEncapConfig::Mpls {
                dst: vec![MplsLabel {
                    label: 100,
                    traffic_class: 0,
                    bottom_of_stack: true,
                    ttl: 0,
                }],
                ttl: Some(64),
            })
        );
    }

    #[test]
    fn test_parse_route_encap_ip() {
        let config = parse_route_config(
            &opts(&[
                "10.0.0.0/8",
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
                "d0",
            ]),
            None,
        )
        .unwrap();
        assert_eq!(
            config.encap,
            Some(RouteEncapConfig::Ip {
                id: Some(200),
                dst: Some(Ipv4Addr::new(10, 0, 0, 3)),
                src: Some(Ipv4Addr::new(10, 0, 0, 1)),
                ttl: Some(64),
                tos: Some(8),
                flags: RouteIpTunnelFlags::Key
                    | RouteIpTunnelFlags::Checksum
                    | RouteIpTunnelFlags::Sequence,
                opts: Vec::new(),
            })
        );
    }

    #[test]
    fn test_parse_route_encap_ip6() {
        let config = parse_route_config(
            &opts(&[
                "2001:db8::/64",
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
                "d0",
            ]),
            Some(AddressFamily::Inet6),
        )
        .unwrap();
        assert_eq!(
            config.encap,
            Some(RouteEncapConfig::Ip6 {
                id: Some(100),
                dst: Some("2001:db8::2".parse().unwrap()),
                src: Some("2001:db8::3".parse().unwrap()),
                hoplimit: Some(253),
                tc: Some(7),
                flags: RouteIp6TunnelFlags::Checksum,
                opts: Vec::new(),
            })
        );
    }

    #[test]
    fn test_parse_route_encap_ip_opts() {
        let config = parse_route_config(
            &opts(&[
                "10.0.0.0/8",
                "encap",
                "ip",
                "id",
                "300",
                "geneve_opts",
                "0x1234:0x42:11223344,0x2020:0x1:deadbeef",
                "dev",
                "d0",
            ]),
            None,
        )
        .unwrap();
        assert_eq!(
            config.encap,
            Some(RouteEncapConfig::Ip {
                id: Some(300),
                dst: None,
                src: None,
                ttl: None,
                tos: None,
                flags: RouteIpTunnelFlags::empty(),
                opts: vec![
                    RouteEncapOpt::Geneve {
                        class: 0x1234,
                        typ: 0x42,
                        data: vec![0x11, 0x22, 0x33, 0x44],
                    },
                    RouteEncapOpt::Geneve {
                        class: 0x2020,
                        typ: 0x1,
                        data: vec![0xde, 0xad, 0xbe, 0xef],
                    },
                ],
            })
        );

        let config = parse_route_config(
            &opts(&[
                "10.0.0.0/8",
                "encap",
                "ip",
                "vxlan_opts",
                "100",
                "erspan_opts",
                "1:2:3:4",
                "dev",
                "d0",
            ]),
            None,
        )
        .unwrap();
        assert_eq!(
            config.encap,
            Some(RouteEncapConfig::Ip {
                id: None,
                dst: None,
                src: None,
                ttl: None,
                tos: None,
                flags: RouteIpTunnelFlags::empty(),
                opts: vec![
                    RouteEncapOpt::Vxlan { gbp: 100 },
                    RouteEncapOpt::Erspan {
                        ver: 1,
                        index: Some(2),
                        dir: Some(3),
                        hwid: Some(4),
                    },
                ],
            })
        );
    }

    #[test]
    fn test_parse_route_encap_seg6() {
        let config = parse_route_config(
            &opts(&[
                "2001:db8::/64",
                "encap",
                "seg6",
                "mode",
                "encap",
                "segs",
                "2001:db8::2,2001:db8::3",
                "dev",
                "d0",
            ]),
            Some(AddressFamily::Inet6),
        )
        .unwrap();
        assert_eq!(
            config.encap,
            Some(RouteEncapConfig::Seg6 {
                mode: Seg6Mode::Encap,
                segs: vec![
                    "2001:db8::2".parse().unwrap(),
                    "2001:db8::3".parse().unwrap(),
                ],
                tunsrc: None,
                lookup: None,
                hmac: None,
            })
        );

        // `mode` is required.
        assert!(
            parse_route_config(
                &opts(&[
                    "2001:db8::/64",
                    "encap",
                    "seg6",
                    "segs",
                    "2001:db8::2",
                    "dev",
                    "d0",
                ]),
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn test_parse_route_encap_xfrm() {
        let config = parse_route_config(
            &opts(&[
                "10.0.0.0/8",
                "encap",
                "xfrm",
                "if_id",
                "1",
                "link_dev",
                "d0",
                "dev",
                "d0",
            ]),
            None,
        )
        .unwrap();
        assert_eq!(
            config.encap,
            Some(RouteEncapConfig::Xfrm {
                if_id: 1,
                link_dev: Some("d0".to_string()),
            })
        );

        // `if_id` is required and must not be zero.
        assert!(
            parse_route_config(
                &opts(&["10.0.0.0/8", "encap", "xfrm", "dev", "d0"]),
                None,
            )
            .is_err()
        );
        assert!(
            parse_route_config(
                &opts(&["10.0.0.0/8", "encap", "xfrm", "if_id", "0"]),
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn test_parse_route_encap_unsupported() {
        assert!(
            parse_route_config(
                &opts(&["10.0.0.0/8", "encap", "bpf", "dev", "d0"]),
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn test_parse_route_mpls() {
        let config = parse_route_config(
            &opts(&["100", "dev", "d0", "ttl-propagate", "enabled"]),
            Some(AddressFamily::Mpls),
        )
        .unwrap();
        assert_eq!(
            config.mpls_dst,
            Some(MplsLabel {
                label: 100,
                traffic_class: 0,
                bottom_of_stack: true,
                ttl: 0,
            })
        );
        assert_eq!(config.dst_len, 20);
        assert_eq!(config.ttl_propagate, Some(true));

        // `as to LABEL` pushes a label stack, `via inet` keeps the MPLS
        // route family and moves the gateway to `RTA_VIA`.
        let config = parse_route_config(
            &opts(&[
                "300", "via", "inet", "10.0.0.2", "dev", "d0", "as", "to",
                "400/500",
            ]),
            Some(AddressFamily::Mpls),
        )
        .unwrap();
        assert_eq!(config.family, Some(AddressFamily::Mpls));
        assert_eq!(config.via, Some("10.0.0.2".parse().unwrap()));
        assert_eq!(
            config.mpls_newdst,
            Some(vec![
                MplsLabel {
                    label: 400,
                    traffic_class: 0,
                    bottom_of_stack: false,
                    ttl: 0,
                },
                MplsLabel {
                    label: 500,
                    traffic_class: 0,
                    bottom_of_stack: true,
                    ttl: 0,
                },
            ])
        );

        // A label stack is not a valid MPLS route prefix, `iproute2` treats
        // the part after `/` as prefix length and rejects it.
        assert!(
            parse_route_config(
                &opts(&["100/200", "dev", "d0"]),
                Some(AddressFamily::Mpls),
            )
            .is_err()
        );
    }
}
