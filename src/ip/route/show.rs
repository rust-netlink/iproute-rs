// SPDX-License-Identifier: MIT

use std::{collections::HashMap, net::IpAddr};

use futures_util::TryStreamExt;
use iproute_rs::{CanDisplay, CanOutput, CliColor, write_with_color};
use rtnetlink::packet_route::{
    AddressFamily,
    route::{
        RouteAttribute, RouteCacheInfo, RouteFlags, RouteHeader,
        RouteIoam6Tunnel, RouteIp6Tunnel, RouteIpTunnel, RouteLwEnCapType,
        RouteLwTunnelEncap, RouteMessage, RouteMetric, RouteMplsIpTunnel,
        RouteMplsTtlPropagation, RouteNextHopFlags, RoutePreference,
        RouteProtocol, RouteRplIpTunnel, RouteScope, RouteSeg6IpTunnel,
        RouteSeg6LocalTunnel, RouteType, RouteVia, RouteXfrmTunnel,
        Seg6LocalAction, Seg6Mode,
    },
};
use serde::Serialize;

use crate::CliError;

// `iproute2` converts the route cache jiffies using `get_user_hz()`.
const USER_HZ: u32 = 100;

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
    pub(crate) kind: Option<String>,
    pub(crate) dst: String,
    #[serde(skip)]
    pub(crate) dst_len: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) src: Option<String>,
    #[serde(skip)]
    pub(crate) src_len: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) nhid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "to")]
    pub(crate) newdst: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) encap: Option<CliRouteEncap>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serializer_dsfield"
    )]
    pub(crate) tos: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) gateway: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) via: Option<CliRouteVia>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "dev")]
    pub(crate) oif: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) table: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) prefsrc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) metric: Option<u32>,
    pub(crate) flags: Vec<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) mark: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) flow: Option<CliRouteFlow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) uid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) cache: Option<Vec<&'static str>>,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub(crate) cache_info: Option<CliRouteCacheInfo>,
    #[serde(skip)]
    pub(crate) metrics_raw: Vec<RouteMetric>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) metrics: Option<Vec<CliRouteMetrics>>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "pref")]
    pub(crate) preference: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) iif: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "ttl-propogate")]
    pub(crate) ttl_propagate: Option<bool>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) nexthops: Vec<CliRouteNextHop>,
}

#[derive(Serialize, Default)]
pub(crate) struct CliRouteCacheInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) expires: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<u32>,
}

impl CliRouteCacheInfo {
    fn new(cache_info: &RouteCacheInfo) -> Self {
        Self {
            expires: if cache_info.expires == 0 {
                None
            } else {
                Some(cache_info.expires / USER_HZ)
            },
            error: if cache_info.error == 0 {
                None
            } else {
                Some(cache_info.error)
            },
        }
    }
}

#[derive(Serialize, Default)]
pub(crate) struct CliRouteVia {
    pub(crate) family: String,
    pub(crate) host: String,
}

/// `RTA_ENCAP` of a lightweight tunnel, the JSON object is emitted in the
/// order iproute2 prints the fields of the encapsulation type.
#[derive(Serialize, Default)]
pub(crate) struct CliRouteEncap {
    pub(crate) encap_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) freqk: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) freqn: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) srh: Option<CliRouteEncapSrh>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) table: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) vrftable: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) nh4: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) nh6: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) iif: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) oif: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) if_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) link_dev: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) tunsrc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) tundst: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) trace: Option<()>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) prealloc: Option<()>,
    #[serde(
        rename = "type",
        skip_serializing_if = "Option::is_none",
        serialize_with = "serializer_trace_type"
    )]
    pub(crate) trace_type: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) ns: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) size: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) src: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) dst: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) hoplimit: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) ttl: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) tc: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) tos: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) key: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) csum: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) seq: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) segs: Option<Vec<String>>,
    /// Number of segments shown before the segment list, `iproute2` does
    /// not include it in the JSON output.
    #[serde(skip)]
    pub(crate) segs_count: Option<u8>,
}

/// `SEG6_LOCAL_SRH` of a `seg6local` encapsulation.
#[derive(Serialize, Default)]
pub(crate) struct CliRouteEncapSrh {
    pub(crate) segs: Vec<String>,
}

fn seg6_mode_to_string(mode: Seg6Mode) -> String {
    match mode {
        Seg6Mode::Inline => "inline".to_string(),
        Seg6Mode::Encap => "encap".to_string(),
        _ => "<unknown>".to_string(),
    }
}

fn encap_type_to_string(encap_type: &RouteLwEnCapType) -> String {
    match encap_type {
        // iproute2 spells the SRv6 local encapsulation `seg6local`.
        RouteLwEnCapType::Seg6Local => "seg6local".to_string(),
        _ => encap_type.to_string(),
    }
}

fn serializer_trace_type<S>(
    trace_type: &Option<u32>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match trace_type {
        Some(trace_type) => {
            serializer.serialize_str(&format!("{trace_type:x}"))
        }
        None => serializer.serialize_none(),
    }
}

fn seg6local_action_to_string(action: Seg6LocalAction) -> String {
    match action {
        Seg6LocalAction::Unspec => "unspec".to_string(),
        Seg6LocalAction::End => "End".to_string(),
        Seg6LocalAction::EndX => "End.X".to_string(),
        Seg6LocalAction::EndT => "End.T".to_string(),
        Seg6LocalAction::EndDx2 => "End.DX2".to_string(),
        Seg6LocalAction::EndDx6 => "End.DX6".to_string(),
        Seg6LocalAction::EndDx4 => "End.DX4".to_string(),
        Seg6LocalAction::EndDt6 => "End.DT6".to_string(),
        Seg6LocalAction::EndDt4 => "End.DT4".to_string(),
        Seg6LocalAction::EndB6 => "End.B6".to_string(),
        Seg6LocalAction::EndB6Encap => "End.B6.Encaps".to_string(),
        Seg6LocalAction::EndBm => "End.BM".to_string(),
        Seg6LocalAction::EndS => "End.S".to_string(),
        Seg6LocalAction::EndAs => "End.AS".to_string(),
        Seg6LocalAction::EndAm => "End.AM".to_string(),
        Seg6LocalAction::EndBpf => "End.BPF".to_string(),
        Seg6LocalAction::EndDt46 => "End.DT46".to_string(),
        _ => "<unknown>".to_string(),
    }
}

impl CliRouteEncap {
    fn new(
        encap_type: &RouteLwEnCapType,
        encap: &[RouteLwTunnelEncap],
        link_map: &HashMap<u32, String>,
    ) -> Self {
        let mut ret = Self {
            encap_type: encap_type_to_string(encap_type),
            ..Default::default()
        };
        for item in encap {
            match item {
                RouteLwTunnelEncap::Mpls(RouteMplsIpTunnel::Destination(
                    labels,
                )) => {
                    ret.dst = Some(
                        labels
                            .iter()
                            .map(|label| label.label.to_string())
                            .collect::<Vec<String>>()
                            .join("/"),
                    );
                }
                RouteLwTunnelEncap::Mpls(RouteMplsIpTunnel::Ttl(ttl)) => {
                    ret.ttl = Some(*ttl)
                }
                RouteLwTunnelEncap::Seg6(RouteSeg6IpTunnel::Seg6(header)) => {
                    ret.mode = Some(seg6_mode_to_string(header.mode));
                    ret.segs_count = Some(header.segments.len() as u8);
                    ret.segs = Some(
                        header
                            .segments
                            .iter()
                            .map(|segment| segment.to_string())
                            .collect(),
                    );
                }
                RouteLwTunnelEncap::Rpl(RouteRplIpTunnel::Srh(srh)) => {
                    ret.segs_count = Some(srh.segments_left);
                    ret.segs = Some(
                        srh.segments
                            .iter()
                            .rev()
                            .map(|segment| segment.to_string())
                            .collect(),
                    );
                }
                RouteLwTunnelEncap::Ioam6(RouteIoam6Tunnel::FreqK(freq)) => {
                    ret.freqk = Some(*freq)
                }
                RouteLwTunnelEncap::Ioam6(RouteIoam6Tunnel::FreqN(freq)) => {
                    ret.freqn = Some(*freq)
                }
                RouteLwTunnelEncap::Ioam6(RouteIoam6Tunnel::Mode(mode)) => {
                    ret.mode = Some(mode.to_string())
                }
                RouteLwTunnelEncap::Ioam6(RouteIoam6Tunnel::Src(src)) => {
                    ret.tunsrc = Some(src.to_string())
                }
                RouteLwTunnelEncap::Ioam6(RouteIoam6Tunnel::Dst(dst)) => {
                    ret.tundst = Some(dst.to_string())
                }
                RouteLwTunnelEncap::Ioam6(RouteIoam6Tunnel::Trace(trace)) => {
                    ret.trace = Some(());
                    ret.prealloc = Some(());
                    ret.trace_type = Some(trace.trace_type);
                    ret.ns = Some(trace.namespace_id);
                    ret.size = Some(u16::from(trace.remlen) * 4);
                }
                RouteLwTunnelEncap::Ip6(RouteIp6Tunnel::Id(id)) => {
                    ret.id = Some(*id)
                }
                RouteLwTunnelEncap::Ip6(RouteIp6Tunnel::Source(src)) => {
                    ret.src = Some(src.to_string())
                }
                RouteLwTunnelEncap::Ip6(RouteIp6Tunnel::Destination(dst)) => {
                    ret.dst = Some(dst.to_string())
                }
                RouteLwTunnelEncap::Ip6(RouteIp6Tunnel::Hoplimit(hoplimit)) => {
                    ret.hoplimit = Some(*hoplimit)
                }
                RouteLwTunnelEncap::Ip6(RouteIp6Tunnel::Tc(tc)) => {
                    ret.tc = Some(*tc)
                }
                RouteLwTunnelEncap::Ip6(RouteIp6Tunnel::Flags(flags)) => {
                    set_encap_tunnel_flags(&mut ret, flags.bits())
                }
                RouteLwTunnelEncap::Ip(RouteIpTunnel::Id(id)) => {
                    ret.id = Some(*id)
                }
                RouteLwTunnelEncap::Ip(RouteIpTunnel::Source(src)) => {
                    ret.src = Some(src.to_string())
                }
                RouteLwTunnelEncap::Ip(RouteIpTunnel::Destination(dst)) => {
                    ret.dst = Some(dst.to_string())
                }
                RouteLwTunnelEncap::Ip(RouteIpTunnel::Ttl(ttl)) => {
                    ret.ttl = Some(*ttl)
                }
                RouteLwTunnelEncap::Ip(RouteIpTunnel::Tos(tos)) => {
                    ret.tos = Some(*tos)
                }
                RouteLwTunnelEncap::Ip(RouteIpTunnel::Flags(flags)) => {
                    set_encap_tunnel_flags(&mut ret, flags.bits())
                }
                RouteLwTunnelEncap::Xfrm(RouteXfrmTunnel::IfId(if_id)) => {
                    ret.if_id = Some(u64::from(*if_id))
                }
                RouteLwTunnelEncap::Xfrm(RouteXfrmTunnel::Link(index)) => {
                    ret.link_dev = Some(
                        link_map
                            .get(index)
                            .cloned()
                            .unwrap_or_else(|| format!("if{index}")),
                    )
                }
                RouteLwTunnelEncap::Seg6Local(
                    RouteSeg6LocalTunnel::Action(action),
                ) => ret.action = Some(seg6local_action_to_string(*action)),
                RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalTunnel::Srh(
                    srh,
                )) => {
                    // iproute2 prints the segments from the first segment
                    // down to the last one.
                    let count = usize::from(srh.first_segment) + 1;
                    ret.srh = Some(CliRouteEncapSrh {
                        segs: srh
                            .segments
                            .iter()
                            .take(count)
                            .rev()
                            .map(|segment| segment.to_string())
                            .collect(),
                    });
                }
                RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalTunnel::Table(
                    table,
                )) => ret.table = Some(route_table_u32_to_string(*table)),
                RouteLwTunnelEncap::Seg6Local(
                    RouteSeg6LocalTunnel::VrfTable(table),
                ) => ret.vrftable = Some(route_table_u32_to_string(*table)),
                RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalTunnel::Nh4(
                    addr,
                )) => ret.nh4 = Some(addr.to_string()),
                RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalTunnel::Nh6(
                    addr,
                )) => ret.nh6 = Some(addr.to_string()),
                RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalTunnel::Iif(
                    index,
                )) => {
                    ret.iif = Some(
                        link_map
                            .get(index)
                            .cloned()
                            .unwrap_or_else(|| format!("if{index}")),
                    )
                }
                RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalTunnel::Oif(
                    index,
                )) => {
                    ret.oif = Some(
                        link_map
                            .get(index)
                            .cloned()
                            .unwrap_or_else(|| format!("if{index}")),
                    )
                }
                _ => (),
            }
        }
        ret
    }
}

// `TUNNEL_KEY`, `TUNNEL_CSUM` and `TUNNEL_SEQ` of `LWTUNNEL_IP*_FLAGS`.
const TUNNEL_CSUM: u16 = 1;
const TUNNEL_KEY: u16 = 4;
const TUNNEL_SEQ: u16 = 8;

fn set_encap_tunnel_flags(encap: &mut CliRouteEncap, flags: u16) {
    if flags & TUNNEL_KEY != 0 {
        encap.key = Some(true);
    }
    if flags & TUNNEL_CSUM != 0 {
        encap.csum = Some(true);
    }
    if flags & TUNNEL_SEQ != 0 {
        encap.seq = Some(true);
    }
}

fn route_encap_to_string(encap: &CliRouteEncap) -> String {
    use std::fmt::Write;

    let mut buf = String::new();
    let _ = write!(buf, " encap {} ", encap.encap_type);
    if let Some(ref action) = encap.action {
        let _ = write!(buf, "action {action} ");
    }
    if let Some(ref srh) = encap.srh {
        let _ = write!(buf, "segs {} [ ", srh.segs.len());
        for segment in &srh.segs {
            let _ = write!(buf, "{segment} ");
        }
        buf.push_str("] ");
    }
    if let (Some(freqk), Some(freqn)) = (encap.freqk, encap.freqn) {
        let _ = write!(buf, "freq {freqk}/{freqn} ");
    }
    if let Some(ref table) = encap.table {
        let _ = write!(buf, "table {table} ");
    }
    if let Some(ref vrftable) = encap.vrftable {
        let _ = write!(buf, "vrftable {vrftable} ");
    }
    if let Some(ref nh4) = encap.nh4 {
        let _ = write!(buf, "nh4 {nh4} ");
    }
    if let Some(ref nh6) = encap.nh6 {
        let _ = write!(buf, "nh6 {nh6} ");
    }
    if let Some(ref iif) = encap.iif {
        let _ = write!(buf, "iif {iif} ");
    }
    if let Some(ref oif) = encap.oif {
        let _ = write!(buf, "oif {oif} ");
    }
    if let Some(ref mode) = encap.mode {
        let _ = write!(buf, "mode {mode} ");
    }
    if let Some(if_id) = encap.if_id {
        let _ = write!(buf, "if_id {if_id} ");
    }
    if let Some(ref link_dev) = encap.link_dev {
        let _ = write!(buf, "link_dev {link_dev} ");
    }
    if let Some(ref tunsrc) = encap.tunsrc {
        let _ = write!(buf, "tunsrc {tunsrc} ");
    }
    if let Some(ref tundst) = encap.tundst {
        let _ = write!(buf, "tundst {tundst} ");
    }
    if encap.trace.is_some() && encap.prealloc.is_some() {
        buf.push_str("trace prealloc ");
    }
    if let Some(trace_type) = encap.trace_type {
        let _ = write!(buf, "type {trace_type:#08x} ");
    }
    if let Some(ns) = encap.ns {
        let _ = write!(buf, "ns {ns} ");
    }
    if let Some(size) = encap.size {
        let _ = write!(buf, "size {size} ");
    }
    if let Some(id) = encap.id {
        let _ = write!(buf, "id {id} ");
    }
    if let Some(ref src) = encap.src {
        let _ = write!(buf, "src {src} ");
    }
    if let Some(ref dst) = encap.dst {
        // iproute2 adds a leading space to the MPLS label stack.
        if encap.encap_type == "mpls" {
            let _ = write!(buf, " {dst} ");
        } else {
            let _ = write!(buf, "dst {dst} ");
        }
    }
    if let Some(hoplimit) = encap.hoplimit {
        let _ = write!(buf, "hoplimit {hoplimit} ");
    }
    if let Some(ttl) = encap.ttl {
        let _ = write!(buf, "ttl {ttl} ");
    }
    if let Some(tc) = encap.tc {
        let _ = write!(buf, "tc {tc} ");
    }
    if let Some(tos) = encap.tos {
        let _ = write!(buf, "tos {tos} ");
    }
    if encap.key == Some(true) {
        buf.push_str("key ");
    }
    if encap.csum == Some(true) {
        buf.push_str("csum ");
    }
    if encap.seq == Some(true) {
        buf.push_str("seq ");
    }
    if let Some(ref segs) = encap.segs {
        let _ = write!(
            buf,
            "segs {} [ ",
            encap.segs_count.unwrap_or(segs.len() as u8)
        );
        for segment in segs {
            let _ = write!(buf, "{segment} ");
        }
        buf.push_str("] ");
    }
    buf
}

#[derive(Serialize, Default)]
pub(crate) struct CliRouteFlow {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) from: Option<String>,
    pub(crate) to: String,
}

/// `RTA_METRICS` values as shown by iproute2, the JSON object is emitted in
/// the order of the `RTAX_*` attributes.
#[derive(Serialize, Default)]
pub(crate) struct CliRouteMetrics {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) mtu: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) window: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) rtt: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) rttvar: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) ssthresh: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) cwnd: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) advmss: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) reordering: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) hoplimit: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) initcwnd: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) ecn: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) tcp_usec_ts: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) features: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) rto_min: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) initrwnd: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) quickack: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) fastopen_no_cookie: Option<u32>,
}

// `RTAX_FEATURE_ECN` and `RTAX_FEATURE_TCP_USEC_TS`.
const RTAX_FEATURE_ECN: u32 = 1 << 0;
const RTAX_FEATURE_TCP_USEC_TS: u32 = 1 << 4;

impl CliRouteMetrics {
    fn new(metrics: &[RouteMetric]) -> Self {
        let mut ret = Self::default();
        for metric in metrics {
            match metric {
                RouteMetric::Mtu(v) => ret.mtu = Some(*v),
                RouteMetric::Window(v) => ret.window = Some(*v),
                // The kernel stores RTT in eighths of a millisecond and
                // RTTVAR in quarters of a millisecond.
                RouteMetric::Rtt(v) => ret.rtt = Some(v / 8),
                RouteMetric::RttVar(v) => ret.rttvar = Some(v / 4),
                RouteMetric::SsThresh(v) => ret.ssthresh = Some(*v),
                RouteMetric::Cwnd(v) => ret.cwnd = Some(*v),
                RouteMetric::Advmss(v) => ret.advmss = Some(*v),
                RouteMetric::Reordering(v) => ret.reordering = Some(*v),
                RouteMetric::Hoplimit(v) => {
                    if *v != u32::MAX {
                        ret.hoplimit = Some(*v);
                    }
                }
                RouteMetric::InitCwnd(v) => ret.initcwnd = Some(*v),
                RouteMetric::Features(v) => {
                    if v & RTAX_FEATURE_ECN != 0 {
                        ret.ecn = Some(true);
                    }
                    if v & RTAX_FEATURE_TCP_USEC_TS != 0 {
                        ret.tcp_usec_ts = Some(true);
                    }
                    let remaining =
                        v & !(RTAX_FEATURE_ECN | RTAX_FEATURE_TCP_USEC_TS);
                    if remaining != 0 {
                        ret.features = Some(format!("0x{remaining:x}"));
                    }
                }
                RouteMetric::RtoMin(v) => ret.rto_min = Some(*v),
                RouteMetric::InitRwnd(v) => ret.initrwnd = Some(*v),
                RouteMetric::QuickAck(v) => ret.quickack = Some(*v),
                RouteMetric::FastopenNoCookie(v) => {
                    ret.fastopen_no_cookie = Some(*v)
                }
                _ => (),
            }
        }
        ret
    }
}

// `RTAX_*` attribute names and indices as used by iproute2.
const ROUTE_METRIC_NAMES: &[(u16, &str)] = &[
    (2, "mtu"),
    (3, "window"),
    (4, "rtt"),
    (5, "rttvar"),
    (6, "ssthresh"),
    (7, "cwnd"),
    (8, "advmss"),
    (9, "reordering"),
    (10, "hoplimit"),
    (11, "initcwnd"),
    (12, "features"),
    (13, "rto_min"),
    (14, "initrwnd"),
    (15, "quickack"),
    (16, "congctl"),
    (17, "fastopen_no_cookie"),
];

fn push_route_metric_time(buf: &mut String, milliseconds: u32) {
    use std::fmt::Write;

    if milliseconds >= 1000 {
        // iproute2 prints `%gs` for values of one second and more.
        let _ = write!(buf, "{}s ", f64::from(milliseconds) / 1000.0);
    } else {
        let _ = write!(buf, "{milliseconds}ms ");
    }
}

fn route_metric_index(metric: &RouteMetric) -> Option<(u16, u32)> {
    Some(match metric {
        RouteMetric::Mtu(value) => (2, *value),
        RouteMetric::Window(value) => (3, *value),
        RouteMetric::Rtt(value) => (4, *value),
        RouteMetric::RttVar(value) => (5, *value),
        RouteMetric::SsThresh(value) => (6, *value),
        RouteMetric::Cwnd(value) => (7, *value),
        RouteMetric::Advmss(value) => (8, *value),
        RouteMetric::Reordering(value) => (9, *value),
        RouteMetric::Hoplimit(value) => (10, *value),
        RouteMetric::InitCwnd(value) => (11, *value),
        RouteMetric::Features(value) => (12, *value),
        RouteMetric::RtoMin(value) => (13, *value),
        RouteMetric::InitRwnd(value) => (14, *value),
        RouteMetric::QuickAck(value) => (15, *value),
        RouteMetric::FastopenNoCookie(value) => (17, *value),
        // `RTAX_LOCK` is handled separately, `RTAX_CC_ALGO` is a string and
        // not supported yet.
        RouteMetric::Lock(_)
        | RouteMetric::CcAlgo(_)
        | RouteMetric::Other(_)
        | _ => return None,
    })
}

fn route_metrics_to_string(metrics: &[RouteMetric]) -> String {
    use std::fmt::Write;

    let mut buf = String::new();
    let lock = metrics.iter().find_map(|metric| match metric {
        RouteMetric::Lock(value) => Some(*value),
        _ => None,
    });

    for (index, name) in ROUTE_METRIC_NAMES {
        let value = metrics.iter().find_map(|metric| {
            route_metric_index(metric)
                .filter(|(metric_index, _)| metric_index == index)
                .map(|(_, value)| value)
        });
        let locked = lock.is_some_and(|lock| lock & (1 << index) != 0);
        if value.is_none() && !locked {
            continue;
        }
        let value = value.unwrap_or(0);
        if *index == 10 && value == u32::MAX {
            continue;
        }
        let _ = write!(buf, "{name} ");
        if locked {
            buf.push_str("lock ");
        }
        match index {
            4 => push_route_metric_time(&mut buf, value / 8),
            5 => push_route_metric_time(&mut buf, value / 4),
            12 => {
                if value & RTAX_FEATURE_ECN != 0 {
                    buf.push_str("ecn ");
                }
                if value & RTAX_FEATURE_TCP_USEC_TS != 0 {
                    buf.push_str("tcp_usec_ts ");
                }
                let remaining =
                    value & !(RTAX_FEATURE_ECN | RTAX_FEATURE_TCP_USEC_TS);
                if remaining != 0 {
                    let _ = write!(buf, "0x{remaining:x} ");
                }
            }
            13 => push_route_metric_time(&mut buf, value),
            _ => {
                let _ = write!(buf, "{value} ");
            }
        }
    }
    buf
}

#[derive(Serialize, Default)]
pub(crate) struct CliRouteNextHop {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) gateway: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "dev")]
    pub(crate) oif: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) weight: Option<u32>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) flags: String,
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

// Cached IPv4 routes carry the legacy `RTCF_*` flags in `rtm_flags`.
const ROUTE_CACHE_FLAG_DATA: &[(&str, u32)] = &[
    ("local", 0x8000_0000),
    ("reject", 0x4000_0000),
    ("mc", 0x2000_0000),
    ("brd", 0x1000_0000),
    ("dst-nat", 0x0800_0000),
    ("src-nat", 0x0080_0000),
    ("masq", 0x0040_0000),
    ("dst-direct", 0x0002_0000),
    ("src-direct", 0x0400_0000),
    ("redirected", 0x0004_0000),
    ("redirect", 0x0100_0000),
    ("fastroute", 0x0020_0000),
    ("notify", 0x0001_0000),
    ("proxy", 0x0008_0000),
];

fn route_cache_flags_to_strings(flags: RouteFlags) -> Vec<&'static str> {
    let raw = flags.bits() & !0xFFFF;
    ROUTE_CACHE_FLAG_DATA
        .iter()
        .filter_map(|(name, mask)| (raw & mask != 0).then_some(*name))
        .collect()
}

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
        // MPLS labels are 20 bits.
        AddressFamily::Mpls => 20,
        _ => 32,
    }
}

// Names of `/usr/share/iproute2/rt_dsfield`, as iproute2 prints them.
fn dsfield_to_string(value: u8) -> String {
    match value {
        0x00 => "default".to_string(),
        0x28 => "AF11".to_string(),
        0x30 => "AF12".to_string(),
        0x38 => "AF13".to_string(),
        0x48 => "AF21".to_string(),
        0x50 => "AF22".to_string(),
        0x58 => "AF23".to_string(),
        0x68 => "AF31".to_string(),
        0x70 => "AF32".to_string(),
        0x78 => "AF33".to_string(),
        0x88 => "AF41".to_string(),
        0x90 => "AF42".to_string(),
        0x98 => "AF43".to_string(),
        0x20 => "CS1".to_string(),
        0x40 => "CS2".to_string(),
        0x60 => "CS3".to_string(),
        0x80 => "CS4".to_string(),
        0xa0 => "CS5".to_string(),
        0xc0 => "CS6".to_string(),
        0xe0 => "CS7".to_string(),
        0xb8 => "EF".to_string(),
        _ => format!("0x{value:02x}"),
    }
}

fn serializer_dsfield<S>(
    tos: &Option<u8>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match tos {
        Some(tos) => serializer.serialize_str(&dsfield_to_string(*tos)),
        None => serializer.serialize_none(),
    }
}

fn af_family_to_string(family: AddressFamily) -> String {
    match family {
        AddressFamily::Inet => "inet".to_string(),
        AddressFamily::Inet6 => "inet6".to_string(),
        AddressFamily::Packet => "link".to_string(),
        #[cfg(not(target_os = "android"))]
        AddressFamily::Mpls => "mpls".to_string(),
        AddressFamily::Bridge => "bridge".to_string(),
        _ => "???".to_string(),
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
    // `RTA_ENCAP_TYPE` may be sent after `RTA_ENCAP`.
    let mut encap_attrs: Option<Vec<RouteLwTunnelEncap>> = None;
    let mut encap_type_attr: Option<RouteLwEnCapType> = None;

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
                info.via = Some(match via {
                    RouteVia::Inet(a) => CliRouteVia {
                        family: "inet".to_string(),
                        host: a.to_string(),
                    },
                    RouteVia::Inet6(a) => CliRouteVia {
                        family: "inet6".to_string(),
                        host: a.to_string(),
                    },
                    RouteVia::Other((family, v)) => CliRouteVia {
                        family: af_family_to_string(family),
                        host: hex_encode(&v),
                    },
                    #[cfg(any(target_os = "linux", target_os = "fuchsia"))]
                    RouteVia::Packet(v) => CliRouteVia {
                        family: "link".to_string(),
                        host: hex_encode(&v),
                    },
                    _ => CliRouteVia::default(),
                });
            }
            RouteAttribute::NewDestination(labels) => {
                info.newdst = Some(
                    labels
                        .iter()
                        .map(|label| label.label.to_string())
                        .collect::<Vec<String>>()
                        .join("/"),
                );
            }
            RouteAttribute::TtlPropagate(value) => {
                info.ttl_propagate =
                    Some(value == RouteMplsTtlPropagation::Enabled);
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
            RouteAttribute::NhId(id) => info.nhid = Some(id),
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
            // RTA_FLOW holds the realm as `source`/`destination` pair, which
            // iproute2 displays as `realm TO` or `realms FROM/TO`.
            RouteAttribute::Realm(realm) => {
                info.flow = Some(CliRouteFlow {
                    from: if realm.source == 0 {
                        None
                    } else {
                        Some(realm.source.to_string())
                    },
                    to: realm.destination.to_string(),
                })
            }
            RouteAttribute::Uid(u) => info.uid = Some(u),
            RouteAttribute::Preference(p) => {
                info.preference = Some(route_preference_to_string(p))
            }
            RouteAttribute::CacheInfo(c) => {
                info.cache_info = Some(CliRouteCacheInfo::new(&c))
            }
            RouteAttribute::EncapType(encap_type) => {
                if let Some(encap) = encap_attrs.take() {
                    info.encap =
                        Some(CliRouteEncap::new(&encap_type, &encap, link_map));
                } else {
                    encap_type_attr = Some(encap_type);
                }
            }
            RouteAttribute::Encap(encap) => {
                if let Some(encap_type) = encap_type_attr.take() {
                    info.encap =
                        Some(CliRouteEncap::new(&encap_type, &encap, link_map));
                } else {
                    encap_attrs = Some(encap);
                }
            }
            RouteAttribute::Metrics(metrics) => {
                info.metrics = Some(vec![CliRouteMetrics::new(&metrics)]);
                info.metrics_raw = metrics;
            }
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

    if nl_msg.header.tos != 0 {
        info.tos = Some(nl_msg.header.tos);
    }

    let is_cloned = nl_msg.header.flags.contains(RouteFlags::Cloned);
    info.cloned = is_cloned;

    // iproute2 hides the protocol and scope of cached routes.
    if is_cloned {
        info.protocol = None;
        info.scope = None;
    }

    if is_cloned && family == AddressFamily::Inet {
        info.cache = Some(route_cache_flags_to_strings(nl_msg.header.flags));
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

        // Nexthop ID
        if let Some(nhid) = self.nhid {
            write!(buf, "nhid {nhid} ")?;
        }

        // MPLS new destination
        if let Some(ref newdst) = self.newdst {
            write!(buf, "as to {newdst} ")?;
        }

        // Encapsulation of a lightweight tunnel
        if let Some(ref encap) = self.encap {
            buf.push_str(&route_encap_to_string(encap));
        }

        // TOS
        if let Some(tos) = self.tos {
            write!(buf, "tos {} ", dsfield_to_string(tos))?;
        }

        // Gateway (via)
        if let Some(ref gw) = self.gateway {
            write!(buf, "via ")?;
            write_with_color!(buf, color, "{gw}")?;
            buf.push(' ');
        }

        // Gateway of another address family
        if let Some(ref via) = self.via {
            write!(buf, "via {} {} ", via.family, via.host)?;
        }

        // Device
        if let Some(ref dev) = self.oif {
            write!(buf, "dev {dev} ")?;
        }

        if let Some(ref table) = self.table {
            write!(buf, "table {table} ")?;
        }

        // Skip protocol/scope for cloned routes (matching iproute2)
        if !self.cloned {
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

        // Mark
        if let Some(mark) = self.mark {
            if mark >= 16 {
                write!(buf, "mark 0x{mark:x} ")?;
            } else {
                write!(buf, "mark {mark} ")?;
            }
        }

        // Realms
        if let Some(ref flow) = self.flow {
            match flow.from {
                Some(ref from) => write!(buf, "realms {from}/{} ", flow.to)?,
                None => write!(buf, "realm {} ", flow.to)?,
            }
        }

        // UID
        if let Some(uid) = self.uid {
            write!(buf, "uid {uid} ")?;
        }

        // IPv4 cached routes are shown on a dedicated `cache` line, the
        // remaining cache info follows on the same line as iproute2.
        if self.family == AddressFamily::Inet && self.cloned {
            buf.push_str("\n    cache ");
            if let Some(ref cache) = self.cache
                && !cache.is_empty()
            {
                write!(buf, "<{}> ", cache.join(","))?;
            }
        }

        if let Some(ref ci) = self.cache_info {
            if let Some(expires) = ci.expires {
                write!(buf, "expires {expires}sec ")?;
            }
            if let Some(error) = ci.error {
                write!(buf, "error {error} ")?;
            }
        }

        // Metrics
        if !self.metrics_raw.is_empty() {
            buf.push_str(&route_metrics_to_string(&self.metrics_raw));
        }

        // IIF
        if let Some(ref iif_dev) = self.iif {
            write!(buf, "iif {iif_dev} ")?;
        }

        // Preference (no trailing space - matches iproute2 behavior)
        if let Some(ref pref) = self.preference {
            write!(buf, "pref {pref}")?;
        }

        // TTL propagate
        if let Some(ttl) = self.ttl_propagate {
            if ttl {
                buf.push_str("ttl-propogate enabled");
            } else {
                buf.push_str("ttl-propogate disabled");
            }
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
    /// Routes inside the subtree of the prefix, `root PREFIX`.
    pub(crate) root_dst: Option<(IpAddr, u8)>,
    /// Routes covering the prefix, `match PREFIX`.
    pub(crate) match_dst: Option<(IpAddr, u8)>,
    /// Source address variant of `root PREFIX`.
    pub(crate) root_src: Option<(IpAddr, u8)>,
    /// Source address variant of `match PREFIX`.
    pub(crate) match_src: Option<(IpAddr, u8)>,
    /// Name of the VRF device, resolved to a table ID before dumping.
    pub(crate) vrf: Option<String>,
    /// MPLS label selector of `-f mpls route show LABEL`.
    pub(crate) mpls_dst: Option<u32>,
    pub(crate) dev_name: Option<String>,
}

impl RouteShowFilter {
    pub(crate) fn parse(
        opts: &[&str],
        family: Option<AddressFamily>,
    ) -> Result<(Self, Vec<String>), CliError> {
        // `-f mpls` selects the routes by label instead of IP prefix.
        let mpls = family == Some(AddressFamily::Mpls);
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
        let mut root_dst: Option<(IpAddr, u8)> = None;
        let mut match_dst: Option<(IpAddr, u8)> = None;
        let mut root_src: Option<(IpAddr, u8)> = None;
        let mut match_src: Option<(IpAddr, u8)> = None;
        let mut vrf: Option<String> = None;
        let mut mpls_dst: Option<u32> = None;
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
                    match *val {
                        "root" => {
                            let val = iter.next().ok_or_else(|| {
                                CliError::from("\"from root\" requires a value")
                            })?;
                            root_src = Some(parse_prefix_val(val)?);
                        }
                        "match" => {
                            let val = iter.next().ok_or_else(|| {
                                CliError::from(
                                    "\"from match\" requires a value",
                                )
                            })?;
                            match_src = Some(parse_prefix_val(val)?);
                        }
                        "exact" => {
                            let val = iter.next().ok_or_else(|| {
                                CliError::from(
                                    "\"from exact\" requires a value",
                                )
                            })?;
                            rsrc = Some(parse_prefix_val(val)?);
                        }
                        v => rsrc = Some(parse_prefix_val(v)?),
                    }
                }
                "to" => {
                    let val = iter.next().ok_or_else(|| {
                        CliError::from("\"to\" requires a value")
                    })?;
                    match *val {
                        "root" => {
                            let val = iter.next().ok_or_else(|| {
                                CliError::from("\"to root\" requires a value")
                            })?;
                            match parse_dst_selector(val, mpls)? {
                                DstSelector::Ip(addr, plen) => {
                                    root_dst = Some((addr, plen))
                                }
                                DstSelector::Mpls(label) => {
                                    mpls_dst = Some(label)
                                }
                            }
                        }
                        "match" => {
                            let val = iter.next().ok_or_else(|| {
                                CliError::from("\"to match\" requires a value")
                            })?;
                            match parse_dst_selector(val, mpls)? {
                                DstSelector::Ip(addr, plen) => {
                                    match_dst = Some((addr, plen))
                                }
                                DstSelector::Mpls(label) => {
                                    mpls_dst = Some(label)
                                }
                            }
                        }
                        "exact" => {
                            let val = iter.next().ok_or_else(|| {
                                CliError::from("\"to exact\" requires a value")
                            })?;
                            match parse_dst_selector(val, mpls)? {
                                DstSelector::Ip(addr, plen) => {
                                    rdst = Some((addr, plen))
                                }
                                DstSelector::Mpls(label) => {
                                    mpls_dst = Some(label)
                                }
                            }
                        }
                        v => match parse_dst_selector(v, mpls)? {
                            DstSelector::Ip(addr, plen) => {
                                rdst = Some((addr, plen))
                            }
                            DstSelector::Mpls(label) => mpls_dst = Some(label),
                        },
                    }
                }
                "root" => {
                    let val = iter.next().ok_or_else(|| {
                        CliError::from("\"root\" requires a value")
                    })?;
                    match parse_dst_selector(val, mpls)? {
                        DstSelector::Ip(addr, plen) => {
                            root_dst = Some((addr, plen))
                        }
                        DstSelector::Mpls(label) => mpls_dst = Some(label),
                    }
                }
                "match" => {
                    let val = iter.next().ok_or_else(|| {
                        CliError::from("\"match\" requires a value")
                    })?;
                    match parse_dst_selector(val, mpls)? {
                        DstSelector::Ip(addr, plen) => {
                            match_dst = Some((addr, plen))
                        }
                        DstSelector::Mpls(label) => mpls_dst = Some(label),
                    }
                }
                "exact" => {
                    let val = iter.next().ok_or_else(|| {
                        CliError::from("\"exact\" requires a value")
                    })?;
                    match parse_dst_selector(val, mpls)? {
                        DstSelector::Ip(addr, plen) => {
                            rdst = Some((addr, plen))
                        }
                        DstSelector::Mpls(label) => mpls_dst = Some(label),
                    }
                }
                "vrf" => {
                    let val = iter.next().ok_or_else(|| {
                        CliError::from("\"vrf\" requires a value")
                    })?;
                    vrf = Some(val.to_string());
                }
                _ => {
                    if rdst.is_none()
                        && mpls_dst.is_none()
                        && !arg.starts_with('-')
                    {
                        // Try parsing as destination prefix first
                        match parse_dst_selector(arg, mpls) {
                            Ok(DstSelector::Ip(addr, plen)) => {
                                rdst = Some((addr, plen))
                            }
                            Ok(DstSelector::Mpls(label)) => {
                                mpls_dst = Some(label)
                            }
                            Err(_) if dev_name.is_none() => {
                                dev_name = Some(arg.to_string())
                            }
                            Err(_) => {
                                link_opts.push(arg.to_string());
                            }
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
                root_dst,
                match_dst,
                root_src,
                match_src,
                vrf,
                mpls_dst,
                dev_name,
            },
            link_opts,
        ))
    }

    /// Destination prefix of a dumped route, `None` when it cannot be
    /// parsed as an address.
    fn route_dst_prefix(route: &CliRouteInfo) -> Option<(IpAddr, u8)> {
        parse_route_prefix(&route.dst, route.family, route.dst_len)
    }

    /// Source prefix of a dumped route.
    fn route_src_prefix(route: &CliRouteInfo) -> Option<(IpAddr, u8)> {
        parse_route_prefix(route.src.as_deref()?, route.family, route.src_len)
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

        // `root PREFIX` selects the routes inside the subtree of the prefix.
        if let Some((ref addr, plen)) = self.root_dst {
            match Self::route_dst_prefix(route) {
                Some((route_addr, route_plen))
                    if route.family == ip_addr_family(addr)
                        && route_plen >= plen
                        && prefix_match(&route_addr, addr, plen) => {}
                _ => return false,
            }
        }

        // `match PREFIX` selects the routes covering the prefix.
        if let Some((ref addr, plen)) = self.match_dst {
            match Self::route_dst_prefix(route) {
                Some((route_addr, route_plen))
                    if route.family == ip_addr_family(addr)
                        && route_plen <= plen
                        && prefix_match(&route_addr, addr, route_plen) => {}
                _ => return false,
            }
        }

        // `exact PREFIX` and a plain prefix select one exact prefix.
        if let Some((ref addr, plen)) = self.rdst {
            match Self::route_dst_prefix(route) {
                Some((route_addr, route_plen))
                    if route.family == ip_addr_family(addr)
                        && route_plen == plen
                        && prefix_match(&route_addr, addr, plen) => {}
                _ => return false,
            }
        }

        if let Some((ref addr, plen)) = self.root_src {
            match Self::route_src_prefix(route) {
                Some((route_addr, route_plen))
                    if route.family == ip_addr_family(addr)
                        && route_plen >= plen
                        && prefix_match(&route_addr, addr, plen) => {}
                _ => return false,
            }
        }

        if let Some((ref addr, plen)) = self.match_src {
            match Self::route_src_prefix(route) {
                Some((route_addr, route_plen))
                    if route.family == ip_addr_family(addr)
                        && route_plen <= plen
                        && prefix_match(&route_addr, addr, route_plen) => {}
                _ => return false,
            }
        }

        if let Some((ref addr, plen)) = self.rsrc {
            match Self::route_src_prefix(route) {
                Some((route_addr, route_plen))
                    if route.family == ip_addr_family(addr)
                        && route_plen == plen
                        && prefix_match(&route_addr, addr, plen) => {}
                _ => return false,
            }
        }

        // `vrf NAME` also filters out the local and broadcast routes of the
        // VRF table, matching iproute2.
        if self.vrf.is_some() {
            let kind = route.kind.as_deref().unwrap_or("unicast");
            if kind == "local" || kind == "broadcast" {
                return false;
            }
        }

        // `-f mpls route show LABEL` selects one label.
        if let Some(label) = self.mpls_dst
            && (route.family != AddressFamily::Mpls
                || route.dst != label.to_string())
        {
            return false;
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
        if matches!(self.tb, Some(tb) if tb != 0) {
            // The table filter is not shown by iproute2.
            route.table = None;
        }
    }
}

/// Address family of a parsed address.
fn ip_addr_family(addr: &IpAddr) -> AddressFamily {
    match addr {
        IpAddr::V4(_) => AddressFamily::Inet,
        IpAddr::V6(_) => AddressFamily::Inet6,
    }
}

/// Compare the first `plen` bits of two addresses of the same family.
fn prefix_match(prefix: &IpAddr, addr: &IpAddr, plen: u8) -> bool {
    match (prefix, addr) {
        (IpAddr::V4(prefix), IpAddr::V4(addr)) => {
            let plen = plen.min(32);
            let mask = if plen == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(plen))
            };
            (u32::from(*prefix) & mask) == (u32::from(*addr) & mask)
        }
        (IpAddr::V6(prefix), IpAddr::V6(addr)) => {
            let plen = plen.min(128);
            let mask = if plen == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(plen))
            };
            (u128::from(*prefix) & mask) == (u128::from(*addr) & mask)
        }
        _ => false,
    }
}

/// Prefix of a route address as displayed, e.g. `10.1.0.0/16` or `default`.
fn parse_route_prefix(
    addr: &str,
    family: AddressFamily,
    prefix_len: u8,
) -> Option<(IpAddr, u8)> {
    let (addr_str, plen_str) = match addr.split_once('/') {
        Some((addr_str, plen_str)) => (addr_str, Some(plen_str)),
        None => (addr, None),
    };
    let addr = match addr_str {
        "default" | "0" => match family {
            AddressFamily::Inet6 => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            _ => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        },
        v => v.parse::<IpAddr>().ok()?,
    };
    let plen = match plen_str {
        Some(plen_str) => plen_str.parse::<u8>().ok()?,
        None => match family {
            AddressFamily::Inet => 32,
            AddressFamily::Inet6 => 128,
            _ => prefix_len,
        },
    };
    Some((addr, plen))
}

/// Routing table ID of a VRF device.
pub(crate) async fn vrf_table_id(
    handle: &rtnetlink::Handle,
    name: &str,
) -> Result<u32, CliError> {
    let mut links = handle.link().get().match_name(name.to_string()).execute();
    let link = links.try_next().await?.ok_or_else(|| {
        CliError::from(format!(
            "Error: argument \"{name}\" is wrong: Invalid VRF"
        ))
    })?;
    for attr in &link.attributes {
        if let rtnetlink::packet_route::link::LinkAttribute::LinkInfo(infos) =
            attr
        {
            for info in infos {
                if let rtnetlink::packet_route::link::LinkInfo::Data(
                    rtnetlink::packet_route::link::InfoData::Vrf(nlas),
                ) = info
                {
                    for nla in nlas {
                        if let rtnetlink::packet_route::link::InfoVrf::TableId(
                            table_id,
                        ) = nla
                        {
                            return Ok(*table_id);
                        }
                    }
                }
            }
        }
    }
    Err(CliError::from(format!(
        "Error: argument \"{name}\" is wrong: Invalid VRF"
    )))
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

/// Destination selector of `ip route show`.
enum DstSelector {
    Ip(IpAddr, u8),
    Mpls(u32),
}

/// Parses the destination selector as an MPLS label when the address family
/// is `mpls`, as an IP prefix otherwise.
fn parse_dst_selector(s: &str, mpls: bool) -> Result<DstSelector, CliError> {
    if !mpls {
        let (addr, plen) = parse_prefix_val(s)?;
        return Ok(DstSelector::Ip(addr, plen));
    }
    let (radix, digits) =
        match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            Some(digits) => (16, digits),
            None => (10, s),
        };
    let label = u32::from_str_radix(digits, radix)
        .map_err(|_| CliError::from(format!("invalid MPLS label: {s}")))?;
    if label > 0xfffff {
        return Err(CliError::from(format!("invalid MPLS label: {s}")));
    }
    Ok(DstSelector::Mpls(label))
}

pub(crate) async fn handle_show(
    opts: &[&str],
    preferred_family: Option<AddressFamily>,
    show_details: bool,
) -> Result<Vec<CliRouteInfo>, CliError> {
    let (mut filter, _link_opts) =
        RouteShowFilter::parse(opts, preferred_family)?;

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

    // `vrf NAME` selects the routing table of the VRF device.
    if let Some(ref vrf_name) = filter.vrf {
        filter.tb = Some(vrf_table_id(&handle, vrf_name).await?);
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
        // A table selector restricts the output to that table.
        if !show_all_tables && filter.tb.is_none() && !is_main_table {
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
