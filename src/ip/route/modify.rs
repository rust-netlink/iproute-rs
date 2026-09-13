// SPDX-License-Identifier: MIT

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv6Addr},
};

use futures_util::stream::StreamExt;
use rtnetlink::{
    RouteNextHopBuilder,
    packet_core::{
        NLM_F_ACK, NLM_F_APPEND, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REPLACE,
        NLM_F_REQUEST, NetlinkMessage,
    },
    packet_route::{
        AddressFamily, RouteNetlinkMessage,
        route::{
            Ioam6TraceHdr, RouteAddress, RouteAttribute, RouteErspanOpt,
            RouteGeneveOpt, RouteIoam6Tunnel, RouteIp6Tunnel, RouteIpTunnel,
            RouteLwEnCapType, RouteLwTunnelEncap, RouteLwTunnelOpt,
            RouteMessage, RouteMplsIpTunnel, RouteMplsTtlPropagation,
            RoutePreference, RouteProtocol, RouteRplIpTunnel, RouteScope,
            RouteSeg6IpTunnel, RouteSeg6LocalTunnel, RouteType, RouteVia,
            RouteVxlanOpt, RouteXfrmTunnel, RplSrh, Seg6Header, Seg6Mode,
        },
    },
};

use super::add::{
    RouteAddConfig, RouteEncapConfig, RouteEncapOpt, parse_route_config,
    resolve_route_ifindexes,
};
use crate::CliError;

enum RouteModifyOp {
    Add,
    Append,
    Change,
    Prepend,
    Replace,
}

async fn send_route_request(
    mut handle: rtnetlink::Handle,
    msg: RouteMessage,
    op: RouteModifyOp,
) -> Result<(), CliError> {
    let mut nl_msg = NetlinkMessage::from(RouteNetlinkMessage::NewRoute(msg));
    nl_msg.header.flags = match op {
        RouteModifyOp::Add => {
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE
        }
        RouteModifyOp::Append => {
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_APPEND | NLM_F_CREATE
        }
        RouteModifyOp::Prepend => NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE,
        RouteModifyOp::Change => NLM_F_REQUEST | NLM_F_ACK | NLM_F_REPLACE,
        RouteModifyOp::Replace => {
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_REPLACE | NLM_F_CREATE
        }
    };

    let mut response = handle
        .request(nl_msg)
        .map_err(|e| CliError::from(format!("{e}")))?;
    while let Some(msg) = response.next().await {
        if let rtnetlink::packet_core::NetlinkPayload::Error(err) = msg.payload
        {
            return Err(CliError::from(format!(
                "Received a netlink error message {err}"
            )));
        }
    }
    Ok(())
}

async fn handle_modify(
    opts: &[String],
    preferred_family: Option<AddressFamily>,
    op: RouteModifyOp,
) -> Result<(), CliError> {
    let config = parse_route_config(opts, preferred_family)?;

    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    let ifindexes = resolve_route_ifindexes(&handle, &config).await?;
    let mut msg = build_route_message(&config, &ifindexes, false)?;

    let need_onlink = config.onlink
        || (msg.header.scope == RouteScope::Link && config.via.is_some());
    if need_onlink {
        msg.header.flags |= rtnetlink::packet_route::route::RouteFlags::Onlink;
    }

    send_route_request(handle, msg, op).await
}

fn build_tunnel_opts(opts: &[RouteEncapOpt]) -> Vec<RouteLwTunnelOpt> {
    let mut ret = Vec::new();
    for opt in opts {
        match opt {
            RouteEncapOpt::Geneve { class, typ, data } => {
                // `iproute2` sends one attribute per Geneve option.
                let mut geneve = RouteGeneveOpt::default();
                geneve.class = *class;
                geneve.typ = *typ;
                geneve.data = data.clone();
                ret.push(RouteLwTunnelOpt::Geneve(vec![geneve]));
            }
            RouteEncapOpt::Vxlan { gbp } => ret
                .push(RouteLwTunnelOpt::Vxlan(vec![RouteVxlanOpt::Gbp(*gbp)])),
            RouteEncapOpt::Erspan {
                ver,
                index,
                dir,
                hwid,
            } => {
                let mut erspan_opts = vec![RouteErspanOpt::Ver(*ver)];
                if let Some(index) = index {
                    erspan_opts.push(RouteErspanOpt::Index(*index));
                }
                if let Some(dir) = dir {
                    erspan_opts.push(RouteErspanOpt::Dir(*dir));
                }
                if let Some(hwid) = hwid {
                    erspan_opts.push(RouteErspanOpt::Hwid(*hwid));
                }
                ret.push(RouteLwTunnelOpt::Erspan(erspan_opts));
            }
        }
    }
    ret
}

fn build_encap(
    encap: &RouteEncapConfig,
    ifindexes: &HashMap<String, u32>,
) -> Result<(RouteLwEnCapType, Vec<RouteLwTunnelEncap>), CliError> {
    let mut attrs = Vec::new();

    let encap_type = match encap {
        RouteEncapConfig::Mpls { dst, ttl } => {
            attrs.push(RouteLwTunnelEncap::Mpls(
                RouteMplsIpTunnel::Destination(dst.clone()),
            ));
            if let Some(ttl) = ttl {
                attrs.push(RouteLwTunnelEncap::Mpls(RouteMplsIpTunnel::Ttl(
                    *ttl,
                )));
            }
            RouteLwEnCapType::Mpls
        }
        RouteEncapConfig::Ip {
            id,
            dst,
            src,
            ttl,
            tos,
            flags,
            opts,
        } => {
            if let Some(id) = id {
                attrs.push(RouteLwTunnelEncap::Ip(RouteIpTunnel::Id(*id)));
            }
            if let Some(dst) = dst {
                attrs.push(RouteLwTunnelEncap::Ip(RouteIpTunnel::Destination(
                    *dst,
                )));
            }
            if let Some(src) = src {
                attrs.push(RouteLwTunnelEncap::Ip(RouteIpTunnel::Source(*src)));
            }
            if let Some(ttl) = ttl {
                attrs.push(RouteLwTunnelEncap::Ip(RouteIpTunnel::Ttl(*ttl)));
            }
            if let Some(tos) = tos {
                attrs.push(RouteLwTunnelEncap::Ip(RouteIpTunnel::Tos(*tos)));
            }
            if !flags.is_empty() {
                attrs
                    .push(RouteLwTunnelEncap::Ip(RouteIpTunnel::Flags(*flags)));
            }
            if !opts.is_empty() {
                attrs.push(RouteLwTunnelEncap::Ip(RouteIpTunnel::Opts(
                    build_tunnel_opts(opts),
                )));
            }
            RouteLwEnCapType::Ip
        }
        RouteEncapConfig::Ip6 {
            id,
            dst,
            src,
            hoplimit,
            tc,
            flags,
            opts,
        } => {
            if let Some(id) = id {
                attrs.push(RouteLwTunnelEncap::Ip6(RouteIp6Tunnel::Id(*id)));
            }
            if let Some(dst) = dst {
                attrs.push(RouteLwTunnelEncap::Ip6(
                    RouteIp6Tunnel::Destination(*dst),
                ));
            }
            if let Some(src) = src {
                attrs.push(RouteLwTunnelEncap::Ip6(RouteIp6Tunnel::Source(
                    *src,
                )));
            }
            if let Some(hoplimit) = hoplimit {
                attrs.push(RouteLwTunnelEncap::Ip6(RouteIp6Tunnel::Hoplimit(
                    *hoplimit,
                )));
            }
            if let Some(tc) = tc {
                attrs.push(RouteLwTunnelEncap::Ip6(RouteIp6Tunnel::Tc(*tc)));
            }
            if !flags.is_empty() {
                attrs.push(RouteLwTunnelEncap::Ip6(RouteIp6Tunnel::Flags(
                    *flags,
                )));
            }
            if !opts.is_empty() {
                attrs.push(RouteLwTunnelEncap::Ip6(RouteIp6Tunnel::Opts(
                    build_tunnel_opts(opts),
                )));
            }
            RouteLwEnCapType::Ip6
        }
        RouteEncapConfig::Seg6 {
            mode,
            segs,
            tunsrc,
            lookup,
            hmac,
        } => {
            let mut header = Seg6Header::default();
            header.mode = *mode;
            header.hmac = *hmac;
            header.segments = segs.clone();
            // `iproute2` appends a zeroed segment to the SRH of inline mode.
            if *mode == Seg6Mode::Inline {
                header.segments.push(Ipv6Addr::UNSPECIFIED);
            }
            attrs.push(RouteLwTunnelEncap::Seg6(RouteSeg6IpTunnel::Seg6(
                header,
            )));
            if let Some(tunsrc) = tunsrc {
                attrs.push(RouteLwTunnelEncap::Seg6(RouteSeg6IpTunnel::Src(
                    *tunsrc,
                )));
            }
            if let Some(lookup) = lookup {
                attrs.push(RouteLwTunnelEncap::Seg6(RouteSeg6IpTunnel::Table(
                    *lookup,
                )));
            }
            RouteLwEnCapType::Seg6
        }
        RouteEncapConfig::Rpl { segs } => {
            // `iproute2` stores the segments in reverse order and sets the
            // `segments_left` field to the number of segments.
            let mut srh = RplSrh::default();
            srh.routing_type = 3;
            srh.segments_left = segs.len() as u8;
            srh.segments = segs.iter().rev().copied().collect();
            attrs.push(RouteLwTunnelEncap::Rpl(RouteRplIpTunnel::Srh(srh)));
            RouteLwEnCapType::Rpl
        }
        RouteEncapConfig::Ioam6 {
            freq_k,
            freq_n,
            mode,
            tunsrc,
            tundst,
            trace_type,
            ns,
            size,
        } => {
            attrs.push(RouteLwTunnelEncap::Ioam6(RouteIoam6Tunnel::FreqK(
                *freq_k,
            )));
            attrs.push(RouteLwTunnelEncap::Ioam6(RouteIoam6Tunnel::FreqN(
                *freq_n,
            )));
            attrs
                .push(RouteLwTunnelEncap::Ioam6(RouteIoam6Tunnel::Mode(*mode)));
            if let Some(tunsrc) = tunsrc {
                attrs.push(RouteLwTunnelEncap::Ioam6(RouteIoam6Tunnel::Src(
                    *tunsrc,
                )));
            }
            if let Some(tundst) = tundst {
                attrs.push(RouteLwTunnelEncap::Ioam6(RouteIoam6Tunnel::Dst(
                    *tundst,
                )));
            }
            let mut trace = Ioam6TraceHdr::default();
            trace.namespace_id = *ns;
            trace.remlen = (size / 4) as u8;
            trace.trace_type = *trace_type;
            attrs.push(RouteLwTunnelEncap::Ioam6(RouteIoam6Tunnel::Trace(
                trace,
            )));
            RouteLwEnCapType::Ioam6
        }
        RouteEncapConfig::Xfrm { if_id, link_dev } => {
            attrs.push(RouteLwTunnelEncap::Xfrm(RouteXfrmTunnel::IfId(*if_id)));
            if let Some(name) = link_dev {
                let index = *ifindexes.get(name).ok_or_else(|| {
                    CliError::from(format!("Device \"{name}\" does not exist"))
                })?;
                attrs.push(RouteLwTunnelEncap::Xfrm(RouteXfrmTunnel::Link(
                    index,
                )));
            }
            RouteLwEnCapType::Xfrm
        }
        RouteEncapConfig::Seg6Local {
            action,
            table,
            vrftable,
            nh4,
            nh6,
            iif,
            oif,
            srh,
        } => {
            attrs.push(RouteLwTunnelEncap::Seg6Local(
                RouteSeg6LocalTunnel::Action(*action),
            ));
            if let Some(srh) = srh {
                attrs.push(RouteLwTunnelEncap::Seg6Local(
                    RouteSeg6LocalTunnel::Srh(srh.clone()),
                ));
            }
            if let Some(table) = table {
                attrs.push(RouteLwTunnelEncap::Seg6Local(
                    RouteSeg6LocalTunnel::Table(*table),
                ));
            }
            if let Some(vrftable) = vrftable {
                attrs.push(RouteLwTunnelEncap::Seg6Local(
                    RouteSeg6LocalTunnel::VrfTable(*vrftable),
                ));
            }
            if let Some(nh4) = nh4 {
                attrs.push(RouteLwTunnelEncap::Seg6Local(
                    RouteSeg6LocalTunnel::Nh4(*nh4),
                ));
            }
            if let Some(nh6) = nh6 {
                attrs.push(RouteLwTunnelEncap::Seg6Local(
                    RouteSeg6LocalTunnel::Nh6(*nh6),
                ));
            }
            for (name, is_input) in [(iif, true), (oif, false)] {
                if let Some(name) = name {
                    let index = *ifindexes.get(name).ok_or_else(|| {
                        CliError::from(format!(
                            "Device \"{name}\" does not exist"
                        ))
                    })?;
                    let attr = if is_input {
                        RouteSeg6LocalTunnel::Iif(index)
                    } else {
                        RouteSeg6LocalTunnel::Oif(index)
                    };
                    attrs.push(RouteLwTunnelEncap::Seg6Local(attr));
                }
            }
            RouteLwEnCapType::Seg6Local
        }
    };

    Ok((encap_type, attrs))
}

pub(crate) fn build_route_message(
    config: &RouteAddConfig,
    ifindexes: &HashMap<String, u32>,
    is_delete: bool,
) -> Result<RouteMessage, CliError> {
    let mut msg = RouteMessage::default();

    let family = config.family.unwrap_or(AddressFamily::Inet);
    msg.header.address_family = family;

    msg.header.protocol = RouteProtocol::Boot;
    msg.header.scope = if is_delete {
        RouteScope::NoWhere
    } else {
        RouteScope::Universe
    };
    msg.header.kind = RouteType::Unicast;
    msg.header.table = 254;

    if let Some(proto) = config.protocol {
        msg.header.protocol = proto;
    }
    if let Some(scope) = config.scope {
        msg.header.scope = scope;
    }
    if let Some(kind) = config.kind {
        msg.header.kind = kind;
    }
    if let Some(tos) = config.tos {
        msg.header.tos = tos;
    }
    if let Some(table) = config.table {
        if table > 255 {
            msg.attributes.push(RouteAttribute::Table(table));
        } else {
            msg.header.table = table as u8;
        }
    }

    if let Some(ref addr) = config.dst {
        msg.header.destination_prefix_length = config.dst_len;
        let rta = match addr {
            IpAddr::V4(a) => {
                RouteAttribute::Destination(RouteAddress::Inet(*a))
            }
            IpAddr::V6(a) => {
                RouteAttribute::Destination(RouteAddress::Inet6(*a))
            }
        };
        msg.attributes.push(rta);
    }

    if let Some(label) = config.mpls_dst {
        msg.header.destination_prefix_length = config.dst_len;
        msg.attributes
            .push(RouteAttribute::Destination(RouteAddress::Mpls(label)));
    }

    if let Some(ref addr) = config.src {
        msg.header.source_prefix_length = config.src_len;
        let rta = match addr {
            IpAddr::V4(a) => RouteAttribute::Source(RouteAddress::Inet(*a)),
            IpAddr::V6(a) => RouteAttribute::Source(RouteAddress::Inet6(*a)),
        };
        msg.attributes.push(rta);
    }

    if let Some(ref addr) = config.via {
        let use_via = matches!(
            (family, addr),
            (AddressFamily::Inet, IpAddr::V6(_))
                | (AddressFamily::Inet6, IpAddr::V4(_))
                | (AddressFamily::Mpls, _)
        );
        let rta = if use_via {
            match addr {
                IpAddr::V4(a) => RouteAttribute::Via(RouteVia::Inet(*a)),
                IpAddr::V6(a) => RouteAttribute::Via(RouteVia::Inet6(*a)),
            }
        } else {
            match addr {
                IpAddr::V4(a) => {
                    RouteAttribute::Gateway(RouteAddress::Inet(*a))
                }
                IpAddr::V6(a) => {
                    RouteAttribute::Gateway(RouteAddress::Inet6(*a))
                }
            }
        };
        msg.attributes.push(rta);
    }

    if let Some(ref labels) = config.mpls_newdst {
        msg.attributes
            .push(RouteAttribute::NewDestination(labels.clone()));
    }

    if let Some(ref addr) = config.prefsrc {
        let rta = match addr {
            IpAddr::V4(a) => RouteAttribute::PrefSource(RouteAddress::Inet(*a)),
            IpAddr::V6(a) => {
                RouteAttribute::PrefSource(RouteAddress::Inet6(*a))
            }
        };
        msg.attributes.push(rta);
    }

    if let Some(m) = config.metric {
        msg.attributes.push(RouteAttribute::Priority(m));
    }

    if !config.metrics.is_empty() {
        msg.attributes
            .push(RouteAttribute::Metrics(config.metrics.clone()));
    }

    if let Some(realm) = config.realm {
        msg.attributes.push(RouteAttribute::Realm(realm));
    }

    if let Some(e) = config.expires {
        msg.attributes.push(RouteAttribute::Expires(e));
    }

    #[cfg(not(target_os = "android"))]
    if let Some(m) = config.mark {
        msg.attributes.push(RouteAttribute::Mark(m));
    }

    if let Some(u) = config.uid {
        msg.attributes.push(RouteAttribute::Uid(u));
    }

    if let Some(p) = config.preference {
        msg.attributes
            .push(RouteAttribute::Preference(RoutePreference::from(p)));
    }

    if let Some(value) = config.ttl_propagate {
        let propagation = if value {
            RouteMplsTtlPropagation::Enabled
        } else {
            RouteMplsTtlPropagation::Disabled
        };
        msg.attributes
            .push(RouteAttribute::TtlPropagate(propagation));
    }

    // `iproute2` adds `RTA_NH_ID` while parsing the `nhid` keyword, which
    // precedes the `RTA_OIF` added for `dev` at the end of `iproute_modify()`.
    if let Some(id) = config.nhid {
        msg.attributes.push(RouteAttribute::NhId(id));
    }

    if let Some(ref dev) = config.dev {
        let index = *ifindexes.get(dev).ok_or_else(|| {
            CliError::from(format!("Device \"{dev}\" does not exist"))
        })?;
        msg.attributes.push(RouteAttribute::Oif(index));
    }

    if !config.nexthops.is_empty() {
        let mut next_hops = Vec::with_capacity(config.nexthops.len());
        for nh in &config.nexthops {
            let mut builder = RouteNextHopBuilder::new(family);
            if let Some(ref addr) = nh.via {
                builder = builder
                    .via(*addr)
                    .map_err(|e| CliError::from(format!("{e}")))?;
            }

            if let Some(ref dev) = nh.dev {
                let index = *ifindexes.get(dev).ok_or_else(|| {
                    CliError::from(format!("Device \"{dev}\" does not exist"))
                })?;
                builder = builder.interface(index);
            }

            if let Some(weight) = nh.weight {
                builder = builder.weight((weight - 1) as u8);
            }

            if nh.onlink {
                builder = builder.onlink();
            }
            builder = builder.pervasive(nh.pervasive);

            next_hops.push(builder.build());
        }
        msg.attributes.push(RouteAttribute::MultiPath(next_hops));
    }

    // `iproute2` adds `RTA_ENCAP` before the final `RTA_OIF` of `dev`.
    if let Some(ref encap) = config.encap {
        let (encap_type, attrs) = build_encap(encap, ifindexes)?;
        msg.attributes.push(RouteAttribute::Encap(attrs));
        msg.attributes.push(RouteAttribute::EncapType(encap_type));
    }

    let kind = msg.header.kind;
    let scope_set = config.scope.is_some();
    if !scope_set {
        msg.header.scope = if family == AddressFamily::Inet6
            || family == AddressFamily::Mpls
        {
            RouteScope::Universe
        } else if kind == RouteType::Local || kind == RouteType::Nat {
            RouteScope::Host
        } else if kind == RouteType::Broadcast
            || kind == RouteType::Multicast
            || kind == RouteType::Anycast
        {
            RouteScope::Link
        } else if kind == RouteType::Unicast || kind == RouteType::Unspec {
            if is_delete {
                RouteScope::NoWhere
            } else if config.via.is_none()
                && config.nexthops.is_empty()
                && config.nhid.unwrap_or(0) == 0
            {
                RouteScope::Link
            } else {
                msg.header.scope
            }
        } else {
            msg.header.scope
        };
    }

    if (kind == RouteType::Local
        || kind == RouteType::Broadcast
        || kind == RouteType::Nat
        || kind == RouteType::Anycast)
        && config.table.is_none()
    {
        msg.header.table = 255;
    }

    Ok(msg)
}

pub(crate) async fn handle_modify_add(
    opts: &[String],
    preferred_family: Option<AddressFamily>,
) -> Result<(), CliError> {
    handle_modify(opts, preferred_family, RouteModifyOp::Add).await
}

pub(crate) async fn handle_modify_append(
    opts: &[String],
    preferred_family: Option<AddressFamily>,
) -> Result<(), CliError> {
    handle_modify(opts, preferred_family, RouteModifyOp::Append).await
}

pub(crate) async fn handle_modify_change(
    opts: &[String],
    preferred_family: Option<AddressFamily>,
) -> Result<(), CliError> {
    handle_modify(opts, preferred_family, RouteModifyOp::Change).await
}

pub(crate) async fn handle_modify_prepend(
    opts: &[String],
    preferred_family: Option<AddressFamily>,
) -> Result<(), CliError> {
    handle_modify(opts, preferred_family, RouteModifyOp::Prepend).await
}

pub(crate) async fn handle_modify_replace(
    opts: &[String],
    preferred_family: Option<AddressFamily>,
) -> Result<(), CliError> {
    handle_modify(opts, preferred_family, RouteModifyOp::Replace).await
}
