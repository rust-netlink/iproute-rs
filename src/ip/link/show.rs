// SPDX-License-Identifier: MIT

use std::collections::HashMap;
use std::ffi::CStr;

use futures_util::stream::TryStreamExt;
use rtnetlink::packet_core::DefaultNla;
use rtnetlink::packet_route::link::InfoData;
use rtnetlink::packet_route::link::LinkInfo;
use rtnetlink::{
    packet_core::Nla as _,
    packet_route::link::{
        AfSpecInet6, AfSpecUnspec, LinkAttribute, LinkLayerType, LinkMessage,
    },
};
use serde::Serialize;

use super::flags::link_flags_to_string;
use iproute_rs::{
    CanDisplay, CanOutput, CliColor, CliError, mac_to_string, write_with_color,
};

// Use constants until support is added to netlink-packet-route
const IFLA_PARENT_DEV_NAME: u16 = 56;
const IFLA_PARENT_DEV_BUS_NAME: u16 = 57;
const IFLA_GRO_MAX_SIZE: u16 = 58;
const IFLA_TSO_MAX_SIZE: u16 = 59;
const IFLA_TSO_MAX_SEGS: u16 = 60;
const IFLA_ALLMULTI: u16 = 61;

fn default_nla_to_string(default_nla: &DefaultNla) -> String {
    let val_len = default_nla.value_len();
    let mut val = vec![0u8; val_len];
    default_nla.emit_value(&mut val);
    CStr::from_bytes_with_nul(&val)
        .expect("String nla to be nul-terminated and not contain interior nuls")
        .to_str()
        .expect("To be valid UTF-8")
        .to_string()
}

#[derive(Serialize)]
#[serde(untagged)]
enum CliLinkInfoData {}

impl CliLinkInfoData {
    fn new(info_data: &InfoData) -> Self {
        match info_data {
            InfoData::Bridge(_info_bridge) => todo!(),
            InfoData::Tun(_info_tun) => todo!(),
            InfoData::Vlan(_info_vlan) => todo!(),
            InfoData::Veth(_info_veth) => todo!(),
            InfoData::Vxlan(_info_vxlan) => todo!(),
            InfoData::Bond(_info_bond) => todo!(),
            InfoData::IpVlan(_info_ip_vlan) => todo!(),
            InfoData::IpVtap(_info_ip_vtap) => todo!(),
            InfoData::MacVlan(_info_mac_vlan) => todo!(),
            InfoData::MacVtap(_info_mac_vtap) => todo!(),
            InfoData::GreTap(_info_gre_tap) => todo!(),
            InfoData::GreTap6(_info_gre_tap6) => todo!(),
            InfoData::SitTun(_info_sit_tun) => todo!(),
            InfoData::GreTun(_info_gre_tun) => todo!(),
            InfoData::GreTun6(_info_gre_tun6) => todo!(),
            InfoData::Vti(_info_vti) => todo!(),
            InfoData::Vrf(_info_vrf) => todo!(),
            InfoData::Gtp(_info_gtp) => todo!(),
            InfoData::Ipoib(_info_ipoib) => todo!(),
            InfoData::Xfrm(_info_xfrm) => todo!(),
            InfoData::MacSec(_info_mac_sec) => todo!(),
            InfoData::Hsr(_info_hsr) => todo!(),
            InfoData::Geneve(_info_geneve) => todo!(),
            InfoData::Other(_items) => todo!(),
            _ => todo!(),
        }
    }
}

impl std::fmt::Display for CliLinkInfoData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            _ => todo!(),
        }

        Ok(())
    }
}

#[derive(Serialize)]
pub(crate) struct CliLinkInfoKindNData {
    info_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    info_data: Option<CliLinkInfoData>,
}

impl std::fmt::Display for CliLinkInfoKindNData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "\n    ")?;
        write!(f, "{} ", self.info_kind)?;
        if let Some(data) = &self.info_data {
            write!(f, "{data} ")?;
        }
        Ok(())
    }
}

#[derive(Serialize)]
pub(crate) struct CliLinkInfoDetails {
    promiscuity: u32,
    allmulti: u32,
    min_mtu: u32,
    max_mtu: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    linkinfo: Option<CliLinkInfoKindNData>,
    #[serde(skip_serializing_if = "String::is_empty")]
    inet6_addr_gen_mode: String,
    num_tx_queues: u32,
    num_rx_queues: u32,
    gso_max_size: u32,
    gso_max_segs: u32,
    tso_max_size: u32,
    tso_max_segs: u32,
    gro_max_size: u32,
    #[serde(skip_serializing_if = "String::is_empty")]
    parentbus: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    parentdev: String,
}

impl CliLinkInfoDetails {
    fn new_with_type(
        link_type: LinkLayerType,
        nl_attrs: &[LinkAttribute],
    ) -> Self {
        let mut linkinfo = None;
        let mut promiscuity = 0;
        let mut allmulti = 0;
        let mut min_mtu = 0;
        let mut max_mtu = 0;
        let mut num_tx_queues = 0;
        let mut num_rx_queues = 0;
        let mut gso_max_size = 0;
        let mut gso_max_segs = 0;
        let mut tso_max_size = 0;
        let mut tso_max_segs = 0;
        let mut gro_max_size = 0;
        let mut inet6_addr_gen_mode = String::new();
        let mut parentbus = String::new();
        let mut parentdev = String::new();

        for nl_attr in nl_attrs {
            match nl_attr {
                LinkAttribute::Promiscuity(p) => promiscuity = *p,
                LinkAttribute::MinMtu(m) => min_mtu = *m,
                LinkAttribute::MaxMtu(m) => max_mtu = *m,
                LinkAttribute::AfSpecUnspec(a) => {
                    inet6_addr_gen_mode = get_addr_gen_mode(a)
                }
                LinkAttribute::NumTxQueues(n) => num_tx_queues = *n,
                LinkAttribute::NumRxQueues(n) => num_rx_queues = *n,
                LinkAttribute::GsoMaxSize(g) => gso_max_size = *g,
                LinkAttribute::GsoMaxSegs(g) => gso_max_segs = *g,
                LinkAttribute::Other(default_nla) => match default_nla.kind() {
                    IFLA_PARENT_DEV_BUS_NAME => {
                        parentbus = default_nla_to_string(default_nla);
                    }
                    IFLA_PARENT_DEV_NAME => {
                        parentdev = default_nla_to_string(default_nla);
                    }
                    IFLA_GRO_MAX_SIZE => {
                        let mut val = [0u8; 4];
                        default_nla.emit_value(&mut val);
                        gro_max_size = u32::from_ne_bytes(val);
                    }
                    IFLA_TSO_MAX_SIZE => {
                        let mut val = [0u8; 4];
                        default_nla.emit_value(&mut val);
                        tso_max_size = u32::from_ne_bytes(val);
                    }
                    IFLA_TSO_MAX_SEGS => {
                        let mut val = [0u8; 4];
                        default_nla.emit_value(&mut val);
                        tso_max_segs = u32::from_ne_bytes(val);
                    }
                    IFLA_ALLMULTI => {
                        let mut val = [0u8; 4];
                        default_nla.emit_value(&mut val);
                        allmulti = u32::from_ne_bytes(val);
                    }
                    _ => { /* println!("Remains {:?}", default_nla); */ }
                },
                LinkAttribute::LinkInfo(info) => {
                    // println!("LinkInfo: {:?}", info);
                    let mut info_kind = String::new();
                    let mut info_data = Option::None;
                    for nla in info {
                        match nla {
                            LinkInfo::Kind(t) => {
                                info_kind = t.to_string();
                            }
                            LinkInfo::Data(data) => {
                                info_data = Some(CliLinkInfoData::new(data));
                            }
                            _ => (),
                        }
                    }

                    linkinfo = Some(CliLinkInfoKindNData {
                        info_kind,
                        info_data,
                    });
                }
                _ => {
                    // println!("Remains {:?}", nl_attr);
                }
            }
        }

        Self {
            promiscuity,
            allmulti,
            min_mtu,
            max_mtu,
            linkinfo,
            inet6_addr_gen_mode,
            num_tx_queues,
            num_rx_queues,
            gso_max_size,
            gso_max_segs,
            tso_max_size,
            tso_max_segs,
            gro_max_size,
            parentbus,
            parentdev,
        }
    }
}

impl std::fmt::Display for CliLinkInfoDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            " promiscuity {}  allmulti {} minmtu {} maxmtu {} ",
            self.promiscuity, self.allmulti, self.min_mtu, self.max_mtu,
        )?;

        if let Some(linkinfo) = &self.linkinfo {
            write!(f, "{linkinfo}")?;
        }

        write!(
            f,
            "addrgenmode {} numtxqueues {} numrxqueues {} gso_max_size {} gso_max_segs {} tso_max_size {} tso_max_segs {} gro_max_size {} ",
            self.inet6_addr_gen_mode,
            self.num_tx_queues,
            self.num_rx_queues,
            self.gso_max_size,
            self.gso_max_segs,
            self.tso_max_size,
            self.tso_max_segs,
            self.gro_max_size,
        )?;

        if !self.parentbus.is_empty() {
            write!(f, "parentbus {} ", self.parentbus)?;
        }
        if !self.parentdev.is_empty() {
            write!(f, "parentdev {} ", self.parentdev)?;
        }

        Ok(())
    }
}

#[derive(Serialize, Default)]
pub(crate) struct CliLinkInfo {
    ifindex: u32,
    ifname: String,
    flags: Vec<String>,
    mtu: u32,
    qdisc: String,
    #[serde(skip_serializing_if = "Option::is_none", rename = "master")]
    controller: Option<String>,
    #[serde(skip)]
    controller_ifindex: Option<u32>,
    operstate: String,
    linkmode: String,
    group: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    txqlen: Option<u32>,
    link_type: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    address: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    broadcast: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    details: Option<CliLinkInfoDetails>,
}

impl std::fmt::Display for CliLinkInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: ", self.ifindex)?;
        write_with_color!(f, CliColor::IfaceName, "{}: ", self.ifname)?;
        write!(
            f,
            "<{}> mtu {} qdisc {}",
            self.flags.as_slice().join(","),
            self.mtu,
            self.qdisc,
        )?;
        if let Some(ctrl) = self.controller.as_ref() {
            write!(f, " master {ctrl}")?;
        }
        write!(f, " state ")?;
        if self.operstate == "UP" {
            write_with_color!(f, CliColor::StateUp, "{} ", self.operstate)?;
        } else if self.operstate == "DOWN" {
            write_with_color!(f, CliColor::StateDown, "{} ", self.operstate)?;
        } else {
            write!(f, "{} ", self.operstate)?;
        }
        write!(f, "mode {} group {} ", self.linkmode, self.group,)?;
        if let Some(v) = self.txqlen {
            write!(f, "qlen {v}")?;
        }
        write!(f, "\n    ")?;
        write!(f, "link/{} ", self.link_type)?;
        if !self.address.is_empty() {
            write_with_color!(f, CliColor::Mac, "{}", self.address)?;
            write!(f, " brd ")?;
            write_with_color!(f, CliColor::Mac, "{}", self.broadcast)?;
        }

        if let Some(details) = &self.details {
            write!(f, "{details}",)?;
        }
        Ok(())
    }
}

impl CanDisplay for CliLinkInfo {
    fn gen_string(&self) -> String {
        self.to_string()
    }
}

impl CanOutput for CliLinkInfo {}

pub(crate) async fn handle_show(
    _opts: &[&str],
    include_details: bool,
) -> Result<Vec<CliLinkInfo>, CliError> {
    let (connection, handle, _) = rtnetlink::new_connection()?;

    tokio::spawn(connection);

    let link_get_handle = handle.link().get();

    /*
    if let Some(iface_name) = filter.iface_name.as_ref() {
        link_get_handle = link_get_handle.match_name(iface_name.to_string());
    }
    */

    let mut links = link_get_handle.execute();
    let mut ifaces: Vec<CliLinkInfo> = Vec::new();

    while let Some(nl_msg) = links.try_next().await? {
        ifaces.push(parse_nl_msg_to_iface(nl_msg, include_details)?);
    }

    resolve_controller_name(&mut ifaces);

    Ok(ifaces)
}

pub(crate) fn parse_nl_msg_to_iface(
    nl_msg: LinkMessage,
    include_details: bool,
) -> Result<CliLinkInfo, CliError> {
    let mut ret = CliLinkInfo {
        ifindex: nl_msg.header.index,
        flags: link_flags_to_string(nl_msg.header.flags),
        link_type: nl_msg.header.link_layer_type.to_string().to_lowercase(),
        ..Default::default()
    };

    ret.details = include_details.then_some(CliLinkInfoDetails::new_with_type(
        nl_msg.header.link_layer_type,
        &nl_msg.attributes,
    ));

    for nl_attr in nl_msg.attributes {
        match nl_attr {
            LinkAttribute::IfName(name) => ret.ifname = name,
            LinkAttribute::Mtu(mtu) => ret.mtu = mtu,
            LinkAttribute::Address(mac) => ret.address = mac_to_string(&mac),
            LinkAttribute::Broadcast(mac) => {
                ret.broadcast = mac_to_string(&mac)
            }
            LinkAttribute::Qdisc(qdisc) => ret.qdisc = qdisc,
            LinkAttribute::OperState(state) => {
                // TODO: impl Display for State in rust-netlink
                ret.operstate = format!("{state:?}").to_uppercase()
            }
            LinkAttribute::TxQueueLen(v) => {
                if v > 0 {
                    ret.txqlen = Some(v)
                }
            }
            LinkAttribute::Group(v) => {
                ret.group = resolve_ip_link_group_name(v)
            }
            LinkAttribute::Mode(v) => ret.linkmode = v.to_string(),
            LinkAttribute::Controller(d) => ret.controller_ifindex = Some(d),
            _ => {
                // println!("Remains {:?}", nl_attr);
            }
        }
    }

    Ok(ret)
}

fn get_addr_gen_mode(af_spec_unspec: &[AfSpecUnspec]) -> String {
    af_spec_unspec
        .iter()
        .filter_map(|s| {
            let AfSpecUnspec::Inet6(v) = s else {
                return None;
            };
            v.iter()
                .filter_map(|i| {
                    if let AfSpecInet6::AddrGenMode(mode) = i {
                        Some(mode)
                    } else {
                        None
                    }
                })
                .next()
        })
        .next()
        .copied()
        .unwrap_or_default()
        .to_string()
}

fn resolve_ip_link_group_name(id: u32) -> String {
    // TODO: Read `/usr/share/iproute2/group` and `/etc/iproute2/group`
    match id {
        0 => "default".into(),
        _ => id.to_string(),
    }
}

fn resolve_controller_name(links: &mut [CliLinkInfo]) {
    let index_2_name: HashMap<u32, String> = links
        .iter()
        .map(|l| (l.ifindex, l.ifname.to_string()))
        .collect();

    for link in links.iter_mut() {
        if let Some(ctrl_ifindex) = link.controller_ifindex
            && let Some(name) = index_2_name.get(&ctrl_ifindex)
        {
            link.controller = Some(name.to_string());
        }
    }
}
