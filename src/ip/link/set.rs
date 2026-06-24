// SPDX-License-Identifier: MIT

use std::os::unix::io::AsRawFd;

use futures_util::TryStreamExt;
use iproute_rs::{CliError, parse_mac_str};
use rtnetlink::packet_route::link::{
    AfSpecInet6, AfSpecUnspec, In6AddrGenMode, InfoKind, LinkAttribute,
    LinkFlags, LinkHeader, LinkInfo, LinkMessage, LinkProtocolDownReason,
    LinkVfInfo, State, VfInfo, VfInfoGuid, VfInfoLinkState, VfInfoMac,
    VfInfoRate, VfInfoRssQueryEn, VfInfoSpoofCheck, VfInfoTrust, VfInfoTxRate,
    VfInfoVlan, VfLinkState, VfVlan, VfVlanInfo, VlanProtocol,
};

use super::{
    ifaces::{
        bareudp::IfaceBareudp,
        bond::IfaceBond,
        bridge::IfaceBridge,
        gtp::IfaceGtp,
        hsr::IfaceHsr,
        parse::{parse_eui64, parse_i32, parse_on_off, parse_u32},
        vlan::IfaceVlan,
        vrf::IfaceVrf,
        wwan::IfaceWwan,
    },
    xdp::{XdpConfig, build_xdp_attrs, parse_xdp_args},
};
use crate::link::CliLinkInfo;

pub(crate) struct LinkSetCommand;

impl LinkSetCommand {
    pub(crate) const CMD: &'static str = "set";

    pub(crate) fn gen_command() -> clap::Command {
        clap::Command::new(Self::CMD)
            .about("change device attributes")
            .alias("s")
            .alias("se")
            .alias("c")
            .alias("ch")
            .alias("cha")
            .alias("chan")
            .alias("chang")
            .alias("change")
            .arg(
                clap::Arg::new("options")
                    .action(clap::ArgAction::Append)
                    .trailing_var_arg(true),
            )
    }

    pub(crate) async fn handle(
        matches: &clap::ArgMatches,
    ) -> Result<Vec<CliLinkInfo>, CliError> {
        let opts: Vec<String> = matches
            .get_many::<String>("options")
            .unwrap_or_default()
            .map(|o| o.to_string())
            .collect();

        let conf = LinkSetConf::parse(&opts)?;

        let (connection, handle, _) = rtnetlink::new_connection()?;
        tokio::spawn(connection);

        let mut header = LinkHeader::default();
        let mut attrs: Vec<LinkAttribute> = Vec::new();

        let ifindex = get_ifindex_by_name(&handle, &conf.dev).await?;
        header.index = ifindex;

        if let Some(v) = conf.up {
            if v {
                header.flags |= LinkFlags::Up;
            } else {
                header.flags.remove(LinkFlags::Up);
            }
            header.change_mask |= LinkFlags::Up;
        }

        if let Some(v) = conf.name {
            attrs.push(LinkAttribute::IfName(v));
        }
        if let Some(v) = conf.mtu {
            attrs.push(LinkAttribute::Mtu(v));
        }
        if let Some(v) = conf.address {
            attrs.push(LinkAttribute::Address(v));
        }
        if let Some(v) = conf.broadcast {
            attrs.push(LinkAttribute::Broadcast(v));
        }
        if let Some(v) = conf.txqueuelen {
            attrs.push(LinkAttribute::TxQueueLen(v));
        }
        if let Some(v) = conf.arp {
            if !v {
                header.flags |= LinkFlags::Noarp;
            }
            header.change_mask |= LinkFlags::Noarp;
        }
        if let Some(v) = conf.multicast {
            if v {
                header.flags |= LinkFlags::Multicast;
            }
            header.change_mask |= LinkFlags::Multicast;
        }
        if let Some(v) = conf.allmulticast {
            if v {
                header.flags |= LinkFlags::Allmulti;
            }
            header.change_mask |= LinkFlags::Allmulti;
        }
        if let Some(v) = conf.promisc {
            if v {
                header.flags |= LinkFlags::Promisc;
            }
            header.change_mask |= LinkFlags::Promisc;
        }
        if let Some(v) = conf.dynamic {
            if v {
                header.flags |= LinkFlags::Dynamic;
            }
            header.change_mask |= LinkFlags::Dynamic;
        }
        if let Some(v) = conf.notrailers {
            if v {
                header.flags.remove(LinkFlags::Notrailers);
            } else {
                header.flags |= LinkFlags::Notrailers;
            }
            header.change_mask |= LinkFlags::Notrailers;
        }
        if let Some(master) = conf.master {
            let ctrl_index = get_ifindex_by_name(&handle, &master).await?;
            attrs.push(LinkAttribute::Controller(ctrl_index));
        }
        if conf.nomaster {
            attrs.push(LinkAttribute::Controller(0));
        }
        if let Some(v) = conf.group {
            attrs.push(LinkAttribute::Group(v));
        }
        if let Some(v) = conf.netns_pid {
            attrs.push(LinkAttribute::NetNsPid(v));
        }
        if let Some(ref file) = conf.netns_file {
            attrs.push(LinkAttribute::NetNsFd(file.as_raw_fd()));
        }
        if let Some(v) = conf.protodown {
            attrs.push(LinkAttribute::ProtoDown(if v { 1 } else { 0 }));
        }
        if let Some(v) = conf.carrier {
            attrs.push(LinkAttribute::Carrier(if v { 1 } else { 0 }));
        }
        if let Some(v) = conf.state {
            attrs.push(LinkAttribute::OperState(v));
        }
        if let Some(v) = conf.alias {
            attrs.push(LinkAttribute::IfAlias(v));
        }
        if let Some((preason, on)) = conf.proto_down_reason {
            let mask = 1u32.checked_shl(preason).unwrap_or(0);
            let value = if on { mask } else { 0 };
            attrs.push(LinkAttribute::ProtoDownReason(vec![
                LinkProtocolDownReason::Mask(mask),
                LinkProtocolDownReason::Value(value),
            ]));
        }
        if let Some(v) = conf.gso_max_size {
            attrs.push(LinkAttribute::GsoMaxSize(v));
        }
        if let Some(v) = conf.gso_ipv4_max_size {
            attrs.push(LinkAttribute::GsoIpv4MaxSize(v));
        }
        if let Some(v) = conf.gso_max_segs {
            attrs.push(LinkAttribute::GsoMaxSegs(v));
        }
        if let Some(v) = conf.gro_max_size {
            attrs.push(LinkAttribute::GroMaxSize(v));
        }
        if let Some(v) = conf.gro_ipv4_max_size {
            attrs.push(LinkAttribute::GroIpv4MaxSize(v));
        }
        if let Some(v) = conf.link_netnsid {
            attrs.push(LinkAttribute::LinkNetNsId(v));
        }
        if let Some(v) = conf.addrgenmode {
            attrs.push(LinkAttribute::AfSpecUnspec(vec![AfSpecUnspec::Inet6(
                vec![AfSpecInet6::AddrGenMode(v)],
            )]));
        }
        if let Some(v) = conf.parentdev_name {
            attrs.push(LinkAttribute::ParentDevName(v));
        }

        if !conf.vf_configs.is_empty() {
            let mut vf_info_list: Vec<LinkVfInfo> = Vec::new();
            for vf in &conf.vf_configs {
                let mut infos: Vec<VfInfo> = Vec::new();
                if let Some(mac) = vf.mac {
                    infos
                        .push(VfInfo::Mac(VfInfoMac::new(vf.vf_num, &mac[..])));
                }
                if let Some(vlan) = vf.vlan {
                    infos.push(VfInfo::Vlan(vlan));
                }
                if !vf.vlan_list.is_empty() {
                    let vlan_nlas: Vec<VfVlan> = vf
                        .vlan_list
                        .iter()
                        .map(|vi| VfVlan::Info(*vi))
                        .collect();
                    infos.push(VfInfo::VlanList(vlan_nlas));
                }
                if let Some(tx) = vf.tx_rate {
                    infos.push(VfInfo::TxRate(tx));
                }
                if let Some(rate) = vf.rate {
                    infos.push(VfInfo::Rate(rate));
                }
                if let Some(enabled) = vf.spoofchk {
                    infos.push(VfInfo::SpoofCheck(VfInfoSpoofCheck::new(
                        vf.vf_num, enabled,
                    )));
                }
                if let Some(enabled) = vf.query_rss {
                    infos.push(VfInfo::RssQueryEn(VfInfoRssQueryEn::new(
                        vf.vf_num, enabled,
                    )));
                }
                if let Some(enabled) = vf.trust {
                    infos.push(VfInfo::Trust(VfInfoTrust::new(
                        vf.vf_num, enabled,
                    )));
                }
                if let Some(state) = vf.link_state {
                    infos.push(VfInfo::LinkState(VfInfoLinkState::new(
                        vf.vf_num, state,
                    )));
                }
                if let Some(guid) = vf.node_guid {
                    infos.push(VfInfo::IbNodeGuid(VfInfoGuid::new(
                        vf.vf_num, guid,
                    )));
                }
                if let Some(guid) = vf.port_guid {
                    infos.push(VfInfo::IbPortGuid(VfInfoGuid::new(
                        vf.vf_num, guid,
                    )));
                }
                vf_info_list.push(LinkVfInfo(infos));
            }
            attrs.push(LinkAttribute::VfInfoList(vf_info_list));
        }

        if let Some(iface_type) = conf.iface_type {
            let link_infos =
                build_type_link_info(&handle, iface_type, &conf.iface_specific)
                    .await?;
            if !link_infos.is_empty() {
                attrs.push(LinkAttribute::LinkInfo(link_infos));
            }
        }

        if let Some(ref xdp_conf) = conf.xdp {
            let xdp_attrs = build_xdp_attrs(xdp_conf)?;
            attrs.push(LinkAttribute::Xdp(xdp_attrs));
        }

        let mut message = LinkMessage::default();
        message.header = header;
        message.attributes = attrs;
        handle.link().change(message).execute().await?;

        Ok(vec![])
    }
}

async fn get_ifindex_by_name(
    handle: &rtnetlink::Handle,
    name: &str,
) -> Result<u32, CliError> {
    let mut links = handle.link().get().match_name(name.to_string()).execute();
    let link = links.try_next().await?.ok_or_else(|| {
        CliError::from(format!("Device \"{name}\" does not exist"))
    })?;
    Ok(link.header.index)
}

#[derive(Debug, Default)]
struct VfConfig {
    vf_num: u32,
    mac: Option<[u8; 32]>,
    vlan: Option<VfInfoVlan>,
    vlan_list: Vec<VfVlanInfo>,
    tx_rate: Option<VfInfoTxRate>,
    rate: Option<VfInfoRate>,
    spoofchk: Option<bool>,
    query_rss: Option<bool>,
    trust: Option<bool>,
    link_state: Option<VfLinkState>,
    node_guid: Option<u64>,
    port_guid: Option<u64>,
}

#[derive(Debug)]
struct LinkSetConf {
    dev: String,
    up: Option<bool>,
    name: Option<String>,
    mtu: Option<u32>,
    address: Option<Vec<u8>>,
    broadcast: Option<Vec<u8>>,
    txqueuelen: Option<u32>,
    arp: Option<bool>,
    multicast: Option<bool>,
    allmulticast: Option<bool>,
    promisc: Option<bool>,
    dynamic: Option<bool>,
    notrailers: Option<bool>,
    master: Option<String>,
    nomaster: bool,
    group: Option<u32>,
    netns_pid: Option<u32>,
    netns_file: Option<std::fs::File>,
    protodown: Option<bool>,
    proto_down_reason: Option<(u32, bool)>,
    carrier: Option<bool>,
    state: Option<State>,
    alias: Option<String>,
    gso_max_size: Option<u32>,
    gso_ipv4_max_size: Option<u32>,
    gso_max_segs: Option<u32>,
    gro_max_size: Option<u32>,
    gro_ipv4_max_size: Option<u32>,
    link_netnsid: Option<i32>,
    addrgenmode: Option<In6AddrGenMode>,
    parentdev_name: Option<String>,
    vf_configs: Vec<VfConfig>,
    iface_type: Option<InfoKind>,
    iface_specific: Vec<String>,
    xdp: Option<XdpConfig>,
}

impl LinkSetConf {
    fn parse(args: &[String]) -> Result<Self, CliError> {
        let mut dev = None;
        let mut up = None;
        let mut name = None;
        let mut mtu = None;
        let mut address = None;
        let mut broadcast = None;
        let mut txqueuelen = None;
        let mut arp = None;
        let mut multicast = None;
        let mut allmulticast = None;
        let mut promisc = None;
        let mut dynamic = None;
        let mut notrailers = None;
        let mut master = None;
        let mut nomaster = false;
        let mut group = None;
        let mut netns_pid = None;
        let mut netns_file = None;
        let mut protodown = None;
        let mut proto_down_reason = None;
        let mut carrier = None;
        let mut state = None;
        let mut alias = None;
        let mut gso_max_size = None;
        let mut gso_ipv4_max_size = None;
        let mut gso_max_segs = None;
        let mut gro_max_size = None;
        let mut gro_ipv4_max_size = None;
        let mut link_netnsid = None;
        let mut addrgenmode = None;
        let mut parentdev_name = None;
        let mut vf_configs: Vec<VfConfig> = Vec::new();
        let mut iface_type = None;
        let mut iface_specific = Vec::new();
        let mut xdp = None;

        let mut iter = args.iter().peekable();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "dev" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from("\"dev\" requires a value"));
                    };
                    dev = Some(v.clone());
                }
                "up" => up = Some(true),
                "down" => up = Some(false),
                "name" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "\"name\" requires a value",
                        ));
                    };
                    name = Some(v.clone());
                }
                "mtu" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from("\"mtu\" requires a value"));
                    };
                    mtu = Some(parse_u32(v, "mtu")?);
                }
                "address" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "\"address\" requires a value",
                        ));
                    };
                    address = Some(parse_mac_str(v)?);
                }
                "broadcast" | "brd" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "\"broadcast\" requires a value",
                        ));
                    };
                    broadcast = Some(parse_mac_str(v)?);
                }
                "txqueuelen" | "qlen" | "txqlen" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "\"txqueuelen\" requires a value",
                        ));
                    };
                    txqueuelen = Some(parse_u32(v, "txqueuelen")?);
                }
                "arp" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from("\"arp\" requires a value"));
                    };
                    arp = Some(parse_on_off(v)?);
                }
                "multicast" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "\"multicast\" requires a value",
                        ));
                    };
                    multicast = Some(parse_on_off(v)?);
                }
                "allmulticast" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "\"allmulticast\" requires a value",
                        ));
                    };
                    allmulticast = Some(parse_on_off(v)?);
                }
                "promisc" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "\"promisc\" requires a value",
                        ));
                    };
                    promisc = Some(parse_on_off(v)?);
                }
                "dynamic" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "\"dynamic\" requires a value",
                        ));
                    };
                    dynamic = Some(parse_on_off(v)?);
                }
                "trailers" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "\"trailers\" requires a value",
                        ));
                    };
                    notrailers = Some(parse_on_off(v)?);
                }
                "master" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "\"master\" requires a value",
                        ));
                    };
                    master = Some(v.clone());
                }
                "vrf" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from("\"vrf\" requires a value"));
                    };
                    master = Some(v.clone());
                }
                "nomaster" => nomaster = true,
                "group" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "\"group\" requires a value",
                        ));
                    };
                    group = Some(parse_u32(v, "group")?);
                }
                "netns" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "\"netns\" requires a value",
                        ));
                    };
                    if let Ok(pid) = v.parse::<u32>() {
                        netns_pid = Some(pid);
                    } else if let Ok(file) =
                        std::fs::File::open(format!("/run/netns/{v}"))
                    {
                        netns_file = Some(file);
                    } else {
                        return Err(CliError::from(format!(
                            "Cannot find network namespace \"{v}\""
                        )));
                    }
                }
                "protodown" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "\"protodown\" requires a value",
                        ));
                    };
                    protodown = Some(parse_on_off(v)?);
                }
                "protodown_reason" => {
                    let Some(preason_str) = iter.next() else {
                        return Err(CliError::from(
                            "\"protodown_reason\" requires a value",
                        ));
                    };
                    let preason = parse_u32(preason_str, "protodown_reason")?;
                    let Some(on_off) = iter.next() else {
                        return Err(CliError::from(
                            "\"protodown_reason\" requires on or off",
                        ));
                    };
                    proto_down_reason = Some((preason, parse_on_off(on_off)?));
                }
                "carrier" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "\"carrier\" requires a value",
                        ));
                    };
                    carrier = Some(parse_on_off(v)?);
                }
                "state" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "\"state\" requires a value",
                        ));
                    };
                    state = Some(
                        v.parse::<State>()
                            .map_err(|e| CliError::from(format!("{e}")))?,
                    );
                }
                "alias" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "\"alias\" requires a value",
                        ));
                    };
                    alias = Some(v.clone());
                }
                "gso_max_size" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "\"gso_max_size\" requires a value",
                        ));
                    };
                    gso_max_size = Some(parse_u32(v, "gso_max_size")?);
                }
                "gso_ipv4_max_size" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "\"gso_ipv4_max_size\" requires a value",
                        ));
                    };
                    gso_ipv4_max_size =
                        Some(parse_u32(v, "gso_ipv4_max_size")?);
                }
                "gso_max_segs" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "\"gso_max_segs\" requires a value",
                        ));
                    };
                    gso_max_segs = Some(parse_u32(v, "gso_max_segs")?);
                }
                "gro_max_size" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "\"gro_max_size\" requires a value",
                        ));
                    };
                    gro_max_size = Some(parse_u32(v, "gro_max_size")?);
                }
                "gro_ipv4_max_size" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "\"gro_ipv4_max_size\" requires a value",
                        ));
                    };
                    gro_ipv4_max_size =
                        Some(parse_u32(v, "gro_ipv4_max_size")?);
                }
                "parentdev" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "\"parentdev\" requires a value",
                        ));
                    };
                    parentdev_name = Some(v.clone());
                }
                "link-netnsid" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "\"link-netnsid\" requires a value",
                        ));
                    };
                    link_netnsid = Some(parse_i32(v, "link-netnsid")?);
                }
                "addrgenmode" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "\"addrgenmode\" requires a value",
                        ));
                    };
                    addrgenmode = Some(match v.as_str() {
                        "eui64" => In6AddrGenMode::Eui64,
                        "none" => In6AddrGenMode::None,
                        "stable_secret" => In6AddrGenMode::StablePrivacy,
                        "random" => In6AddrGenMode::Random,
                        _ => {
                            return Err(CliError::from(format!(
                                "Invalid address generation mode: {v}"
                            )));
                        }
                    });
                }
                "vf" => {
                    let Some(vf_num_str) = iter.next() else {
                        return Err(CliError::from("\"vf\" requires a value"));
                    };
                    let vf_num = parse_u32(vf_num_str, "vf")?;
                    let mut cfg = VfConfig {
                        vf_num,
                        ..Default::default()
                    };
                    loop {
                        match iter.peek() {
                            None => break,
                            Some(keyword) => match keyword.as_str() {
                                "mac" => {
                                    iter.next();
                                    let Some(v) = iter.next() else {
                                        return Err(CliError::from(
                                            "\"mac\" requires a value",
                                        ));
                                    };
                                    let addr = parse_mac_str(v)?;
                                    let mut mac = [0u8; 32];
                                    mac[..addr.len()].copy_from_slice(&addr);
                                    cfg.mac = Some(mac);
                                }
                                "vlan" => {
                                    iter.next();
                                    let Some(vid_str) = iter.next() else {
                                        return Err(CliError::from(
                                            "\"vlan\" requires a value",
                                        ));
                                    };
                                    let vlan_id = parse_u32(vid_str, "vlan")?;
                                    let mut qos = 0u32;
                                    let mut proto = VlanProtocol::Ieee8021Q;
                                    if let Some(next) = iter.peek()
                                        && next.as_str() == "qos"
                                    {
                                        iter.next();
                                        let Some(qos_str) = iter.next() else {
                                            return Err(CliError::from(
                                                "\"qos\" requires a value",
                                            ));
                                        };
                                        qos = parse_u32(qos_str, "qos")?;
                                    }
                                    if let Some(next) = iter.peek()
                                        && next.as_str() == "proto"
                                    {
                                        iter.next();
                                        let Some(proto_str) = iter.next()
                                        else {
                                            return Err(CliError::from(
                                                "\"proto\" requires a value",
                                            ));
                                        };
                                        proto = proto_str
                                            .parse::<VlanProtocol>()
                                            .map_err(|e| {
                                                CliError::from(format!("{e}"))
                                            })?;
                                    }
                                    if proto == VlanProtocol::Ieee8021Q
                                        && cfg.vlan.is_none()
                                        && cfg.vlan_list.is_empty()
                                    {
                                        cfg.vlan = Some(VfInfoVlan::new(
                                            vf_num, vlan_id, qos,
                                        ));
                                    } else {
                                        if let Some(v) = cfg.vlan.take() {
                                            cfg.vlan_list.push(
                                                VfVlanInfo::new(
                                                    vf_num,
                                                    v.vlan_id,
                                                    v.qos,
                                                    VlanProtocol::Ieee8021Q,
                                                ),
                                            );
                                        }
                                        cfg.vlan_list.push(VfVlanInfo::new(
                                            vf_num, vlan_id, qos, proto,
                                        ));
                                    }
                                }
                                "rate" => {
                                    iter.next();
                                    let Some(v) = iter.next() else {
                                        return Err(CliError::from(
                                            "\"rate\" requires a value",
                                        ));
                                    };
                                    let rate = parse_u32(v, "rate")?;
                                    cfg.tx_rate =
                                        Some(VfInfoTxRate::new(vf_num, rate));
                                }
                                "max_tx_rate" => {
                                    iter.next();
                                    let Some(v) = iter.next() else {
                                        return Err(CliError::from(
                                            "\"max_tx_rate\" requires a value",
                                        ));
                                    };
                                    let max_rate = parse_u32(v, "max_tx_rate")?;
                                    let min = cfg
                                        .rate
                                        .map(|r| r.min_tx_rate)
                                        .unwrap_or(0);
                                    cfg.rate = Some(VfInfoRate::new(
                                        vf_num, min, max_rate,
                                    ));
                                }
                                "min_tx_rate" => {
                                    iter.next();
                                    let Some(v) = iter.next() else {
                                        return Err(CliError::from(
                                            "\"min_tx_rate\" requires a value",
                                        ));
                                    };
                                    let min_rate = parse_u32(v, "min_tx_rate")?;
                                    let max = cfg
                                        .rate
                                        .map(|r| r.max_tx_rate)
                                        .unwrap_or(0);
                                    cfg.rate = Some(VfInfoRate::new(
                                        vf_num, min_rate, max,
                                    ));
                                }
                                "spoofchk" => {
                                    iter.next();
                                    let Some(v) = iter.next() else {
                                        return Err(CliError::from(
                                            "\"spoofchk\" requires a value",
                                        ));
                                    };
                                    cfg.spoofchk = Some(parse_on_off(v)?);
                                }
                                "query_rss" => {
                                    iter.next();
                                    let Some(v) = iter.next() else {
                                        return Err(CliError::from(
                                            "\"query_rss\" requires a value",
                                        ));
                                    };
                                    cfg.query_rss = Some(parse_on_off(v)?);
                                }
                                "trust" => {
                                    iter.next();
                                    let Some(v) = iter.next() else {
                                        return Err(CliError::from(
                                            "\"trust\" requires a value",
                                        ));
                                    };
                                    cfg.trust = Some(parse_on_off(v)?);
                                }
                                "state" => {
                                    iter.next();
                                    let Some(v) = iter.next() else {
                                        return Err(CliError::from(
                                            "\"state\" requires a value",
                                        ));
                                    };
                                    cfg.link_state = Some(match v.as_str() {
                                        "auto" => VfLinkState::Auto,
                                        "enable" => VfLinkState::Enable,
                                        "disable" => VfLinkState::Disable,
                                        _ => {
                                            return Err(CliError::from(
                                                format!(
                                                    "Invalid VF state: {v}"
                                                ),
                                            ));
                                        }
                                    });
                                }
                                "node_guid" => {
                                    iter.next();
                                    let Some(v) = iter.next() else {
                                        return Err(CliError::from(
                                            "\"node_guid\" requires a value",
                                        ));
                                    };
                                    cfg.node_guid = Some(parse_eui64(v)?);
                                }
                                "port_guid" => {
                                    iter.next();
                                    let Some(v) = iter.next() else {
                                        return Err(CliError::from(
                                            "\"port_guid\" requires a value",
                                        ));
                                    };
                                    cfg.port_guid = Some(parse_eui64(v)?);
                                }
                                _ => break,
                            },
                        }
                    }
                    vf_configs.push(cfg);
                }
                "type" => {
                    let Some(kind_str) = iter.next() else {
                        return Err(CliError::from(
                            "\"type\" requires a value",
                        ));
                    };
                    iface_type = Some(InfoKind::from(kind_str.as_str()));
                    iface_specific = iter.cloned().collect();
                    break;
                }
                "xdp" | "xdpgeneric" | "xdpdrv" | "xdpoffload" => {
                    let cfg = parse_xdp_args(&mut iter, arg.as_str())?;
                    if xdp.is_some() {
                        return Err(CliError::from(
                            "Duplicate XDP configuration",
                        ));
                    }
                    xdp = Some(cfg);
                }
                _ => {
                    if dev.is_none() {
                        dev = Some(arg.clone());
                    } else {
                        return Err(CliError::from(format!(
                            "Unknown argument: {arg}"
                        )));
                    }
                }
            }
        }

        let dev =
            dev.ok_or_else(|| CliError::from("Device name is required"))?;

        Ok(Self {
            dev,
            up,
            name,
            mtu,
            address,
            broadcast,
            txqueuelen,
            arp,
            multicast,
            allmulticast,
            promisc,
            dynamic,
            notrailers,
            master,
            nomaster,
            group,
            netns_pid,
            netns_file,
            protodown,
            proto_down_reason,
            carrier,
            state,
            alias,
            gso_max_size,
            gso_ipv4_max_size,
            gso_max_segs,
            gro_max_size,
            gro_ipv4_max_size,
            link_netnsid,
            addrgenmode,
            parentdev_name,
            vf_configs,
            iface_type,
            iface_specific,
            xdp,
        })
    }
}

fn build_kind_only(kind: InfoKind) -> Vec<LinkInfo> {
    vec![LinkInfo::Kind(kind)]
}

fn clean_extracted(infos: &mut Vec<LinkInfo>, kind: InfoKind) {
    if infos.is_empty() {
        infos.push(LinkInfo::Kind(kind));
    } else if !infos.iter().any(|i| matches!(i, LinkInfo::Kind(_))) {
        infos.insert(0, LinkInfo::Kind(kind));
    }
}

async fn build_type_link_info(
    _handle: &rtnetlink::Handle,
    kind: InfoKind,
    args: &[String],
) -> Result<Vec<LinkInfo>, CliError> {
    match kind {
        InfoKind::Dummy
        | InfoKind::Nlmon
        | InfoKind::Team
        | InfoKind::Vcan
        | InfoKind::Netdevsim
        | InfoKind::VirtWifi
        | InfoKind::Veth
        | InfoKind::Vxcan
        | InfoKind::Xfrm
        | InfoKind::MacSec
        | InfoKind::Geneve
        | InfoKind::GreTun
        | InfoKind::GreTap
        | InfoKind::GreTun6
        | InfoKind::GreTap6
        | InfoKind::IpIp
        | InfoKind::Ip6Tnl => Ok(build_kind_only(kind)),
        InfoKind::Vlan => {
            let mut infos = IfaceVlan::build_entries(args)?;
            clean_extracted(&mut infos, kind);
            Ok(infos)
        }
        InfoKind::Bond => {
            let mut infos = IfaceBond::build_entries(args)?;
            clean_extracted(&mut infos, kind);
            Ok(infos)
        }
        InfoKind::Bridge => {
            let mut infos = IfaceBridge::build_entries(args)?;
            clean_extracted(&mut infos, kind);
            Ok(infos)
        }
        InfoKind::Hsr => {
            let mut infos = IfaceHsr::build_entries(args)?;
            clean_extracted(&mut infos, kind);
            Ok(infos)
        }
        InfoKind::Netkit => Ok(build_kind_only(InfoKind::Netkit)),
        InfoKind::Vrf => {
            let mut infos = IfaceVrf::build_entries(args)?;
            clean_extracted(&mut infos, kind);
            Ok(infos)
        }
        InfoKind::Gtp => {
            let mut infos = IfaceGtp::build_entries(args)?;
            clean_extracted(&mut infos, kind);
            Ok(infos)
        }
        InfoKind::IpVlan => Ok(build_kind_only(InfoKind::IpVlan)),
        InfoKind::IpVtap => Ok(build_kind_only(InfoKind::IpVtap)),
        InfoKind::MacVlan => Ok(build_kind_only(InfoKind::MacVlan)),
        InfoKind::MacVtap => Ok(build_kind_only(InfoKind::MacVtap)),
        InfoKind::Wwan => {
            let mut infos = IfaceWwan::build_entries(args)?;
            clean_extracted(&mut infos, kind);
            Ok(infos)
        }
        InfoKind::BareUdp => {
            let mut infos = IfaceBareudp::build_entries(args)?;
            clean_extracted(&mut infos, kind);
            Ok(infos)
        }
        _ => Err(CliError::from(format!("Unsupported device type: {kind}"))),
    }
}
