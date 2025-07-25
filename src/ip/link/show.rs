// SPDX-License-Identifier: MIT

use std::collections::HashMap;

use futures_util::stream::TryStreamExt;
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
const IFLA_GRO_MAX_SIZE: u16 = 58;
const IFLA_TSO_MAX_SIZE: u16 = 59;
const IFLA_TSO_MAX_SEGS: u16 = 60;
const IFLA_ALLMULTI: u16 = 61;

#[derive(Serialize)]
#[serde(untagged)]
enum CliLinkTypeDetails {}

impl CliLinkTypeDetails {
    fn new(link_type: LinkLayerType, nl_attrs: &[LinkAttribute]) -> Self {
        match link_type {
            LinkLayerType::Loopback => todo!(),
            LinkLayerType::Ether => todo!(),
            LinkLayerType::Netrom => todo!(),
            LinkLayerType::Eether => todo!(),
            LinkLayerType::Ax25 => todo!(),
            LinkLayerType::Pronet => todo!(),
            LinkLayerType::Chaos => todo!(),
            LinkLayerType::Ieee802 => todo!(),
            LinkLayerType::Arcnet => todo!(),
            LinkLayerType::Appletlk => todo!(),
            LinkLayerType::Dlci => todo!(),
            LinkLayerType::Atm => todo!(),
            LinkLayerType::Metricom => todo!(),
            LinkLayerType::Ieee1394 => todo!(),
            LinkLayerType::Eui64 => todo!(),
            LinkLayerType::Infiniband => todo!(),
            LinkLayerType::Slip => todo!(),
            LinkLayerType::Cslip => todo!(),
            LinkLayerType::Slip6 => todo!(),
            LinkLayerType::Cslip6 => todo!(),
            LinkLayerType::Rsrvd => todo!(),
            LinkLayerType::Adapt => todo!(),
            LinkLayerType::Rose => todo!(),
            LinkLayerType::X25 => todo!(),
            LinkLayerType::Hwx25 => todo!(),
            LinkLayerType::Can => todo!(),
            LinkLayerType::Ppp => todo!(),
            LinkLayerType::Hdlc => todo!(),
            LinkLayerType::Lapb => todo!(),
            LinkLayerType::Ddcmp => todo!(),
            LinkLayerType::Rawhdlc => todo!(),
            LinkLayerType::Rawip => todo!(),
            LinkLayerType::Tunnel => todo!(),
            LinkLayerType::Tunnel6 => todo!(),
            LinkLayerType::Frad => todo!(),
            LinkLayerType::Skip => todo!(),
            LinkLayerType::Localtlk => todo!(),
            LinkLayerType::Fddi => todo!(),
            LinkLayerType::Bif => todo!(),
            LinkLayerType::Sit => todo!(),
            LinkLayerType::Ipddp => todo!(),
            LinkLayerType::Ipgre => todo!(),
            LinkLayerType::Pimreg => todo!(),
            LinkLayerType::Hippi => todo!(),
            LinkLayerType::Ash => todo!(),
            LinkLayerType::Econet => todo!(),
            LinkLayerType::Irda => todo!(),
            LinkLayerType::Fcpp => todo!(),
            LinkLayerType::Fcal => todo!(),
            LinkLayerType::Fcpl => todo!(),
            LinkLayerType::Fcfabric => todo!(),
            LinkLayerType::Ieee802Tr => todo!(),
            LinkLayerType::Ieee80211 => todo!(),
            LinkLayerType::Ieee80211Prism => todo!(),
            LinkLayerType::Ieee80211Radiotap => todo!(),
            LinkLayerType::Ieee802154 => todo!(),
            LinkLayerType::Ieee802154Monitor => todo!(),
            LinkLayerType::Phonet => todo!(),
            LinkLayerType::PhonetPipe => todo!(),
            LinkLayerType::Caif => todo!(),
            LinkLayerType::Ip6gre => todo!(),
            LinkLayerType::Netlink => todo!(),
            LinkLayerType::Sixlowpan => todo!(),
            LinkLayerType::Vsockmon => todo!(),
            LinkLayerType::Void => todo!(),
            LinkLayerType::None => todo!(),
            _ => todo!(),
        }
    }
}

impl std::fmt::Display for CliLinkTypeDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Ok(())
    }
}

#[derive(Serialize)]
pub(crate) struct CliLinkInfoDetails {
    promiscuity: u32,
    allmulti: u32,
    min_mtu: u32,
    max_mtu: u32,
    #[serde(skip_serializing_if = "String::is_empty")]
    inet6_addr_gen_mode: String,
    num_tx_queues: u32,
    num_rx_queues: u32,
    gso_max_size: u32,
    gso_max_segs: u32,
    tso_max_size: u32,
    tso_max_segs: u32,
    gro_max_size: u32,
    #[serde(flatten)]
    link_type_details: CliLinkTypeDetails,
}

impl CliLinkInfoDetails {
    fn new_with_type(
        link_type: LinkLayerType,
        nl_attrs: &[LinkAttribute],
    ) -> Self {
        let link_type_details = CliLinkTypeDetails::new(link_type, nl_attrs);

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
            inet6_addr_gen_mode,
            num_tx_queues,
            num_rx_queues,
            gso_max_size,
            gso_max_segs,
            link_type_details,
            tso_max_size,
            tso_max_segs,
            gro_max_size,
        }
    }
}

impl std::fmt::Display for CliLinkInfoDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            " promiscuity {}  allmulti {} minmtu {} maxmtu {} addrgenmode {} numtxqueues {} numrxqueues {} gso_max_size {} gso_max_segs {} tso_max_size {} tso_max_segs {} gro_max_size {} {}",
            self.promiscuity,
            self.allmulti,
            self.min_mtu,
            self.max_mtu,
            self.inet6_addr_gen_mode,
            self.num_tx_queues,
            self.num_rx_queues,
            self.gso_max_size,
            self.gso_max_segs,
            self.tso_max_size,
            self.tso_max_segs,
            self.gro_max_size,
            self.link_type_details
        )?;
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
