// SPDX-License-Identifier: MIT

use std::collections::HashMap;
use std::os::fd::AsRawFd;

use futures_util::stream::StreamExt;
use futures_util::stream::TryStreamExt;
use rtnetlink::packet_route::link::{LinkAttribute, LinkMessage, Prop};
use serde::Serialize;

use super::flags::link_flags_to_string;
use iproute_rs::{
    CanDisplay, CanOutput, CliColor, CliError, mac_to_string, write_with_color,
};

use crate::link::link_details::CliLinkInfoDetails;

#[derive(Serialize, Default)]
pub(crate) struct CliLinkInfo {
    ifindex: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    link: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    link_index: Option<u32>,
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
    #[serde(skip_serializing_if = "String::is_empty")]
    permaddr: String,
    #[serde(skip)]
    link_netns: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    link_netnsid: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    details: Option<CliLinkInfoDetails>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    altnames: Vec<String>,
}

impl std::fmt::Display for CliLinkInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: ", self.ifindex)?;
        let link = if self.link_index.is_some() || self.link.is_some() {
            let display_name = if let Some(link_name) = &self.link {
                link_name
            } else if let Some(link_index) = self.link_index {
                &format!("if{link_index}")
            } else {
                "NONE"
            };
            format!("@{display_name}")
        } else {
            String::new()
        };

        write_with_color!(f, CliColor::IfaceName, "{}{link}: ", self.ifname)?;
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
        if !self.permaddr.is_empty() {
            write!(f, " permaddr ")?;
            write_with_color!(f, CliColor::Mac, "{}", self.permaddr)?;
        }

        if !self.link_netns.is_empty() {
            write!(f, " link-netns {}", self.link_netns)?;
        } else if let Some(netns_id) = self.link_netnsid {
            write!(f, " link-netnsid {netns_id}")?;
        }

        if let Some(details) = &self.details {
            write!(f, "{details}",)?;
        }

        for altname in &self.altnames {
            write!(f, "\n    altname {altname}")?;
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
    opts: &[&str],
    include_details: bool,
) -> Result<Vec<CliLinkInfo>, CliError> {
    let (connection, handle, _) = rtnetlink::new_connection()?;

    tokio::spawn(connection);

    let mut link_get_handle = handle.link().get();

    if let Some(iface_name) = opts.first() {
        link_get_handle = link_get_handle.match_name(iface_name.to_string());
    }

    let mut links = link_get_handle.execute();
    let mut ifaces: Vec<CliLinkInfo> = Vec::new();

    while let Some(nl_msg) = links.try_next().await? {
        ifaces.push(parse_nl_msg_to_iface(nl_msg, include_details).await?);
    }

    resolve_controller_and_link_names(&mut ifaces);
    resolve_netns_names(&mut ifaces).await?;

    Ok(ifaces)
}

pub(crate) async fn parse_nl_msg_to_iface(
    nl_msg: LinkMessage,
    include_details: bool,
) -> Result<CliLinkInfo, CliError> {
    let mut ret = CliLinkInfo {
        ifindex: nl_msg.header.index,
        flags: link_flags_to_string(nl_msg.header.flags),
        link_type: nl_msg.header.link_layer_type.to_string().to_lowercase(),
        ..Default::default()
    };

    ret.details =
        include_details.then(|| CliLinkInfoDetails::new(&nl_msg.attributes));

    let mut temp_permaddr = String::new();

    for nl_attr in nl_msg.attributes {
        match nl_attr {
            LinkAttribute::IfName(name) => ret.ifname = name,
            LinkAttribute::Mtu(mtu) => ret.mtu = mtu,
            LinkAttribute::Address(mac) => ret.address = mac_to_string(&mac),
            LinkAttribute::Broadcast(mac) => {
                ret.broadcast = mac_to_string(&mac)
            }
            LinkAttribute::PermAddress(mac) => {
                temp_permaddr = mac_to_string(&mac)
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
            LinkAttribute::Link(i) => ret.link_index = Some(i),
            LinkAttribute::LinkNetNsId(i) => ret.link_netnsid = Some(i),
            LinkAttribute::PropList(props) => {
                for prop in props {
                    if let Prop::AltIfName(altname) = prop {
                        ret.altnames.push(altname);
                    }
                }
            }
            _ => {
                // println!("Remains {:?}", nl_attr);
            }
        }
    }

    // Only set permaddr if it differs from the current address
    if !temp_permaddr.is_empty() && temp_permaddr != ret.address {
        ret.permaddr = temp_permaddr;
    }

    Ok(ret)
}

/// Try to resolve a netns id to its name using rtnetlink.
/// If not found, returns the id as a string.
async fn get_netns_id_from_fd(
    handle: &mut rtnetlink::Handle,
    fd: u32,
) -> Option<i32> {
    let mut nsid_msg = rtnetlink::packet_route::nsid::NsidMessage::default();
    nsid_msg
        .attributes
        .push(rtnetlink::packet_route::nsid::NsidAttribute::Fd(fd));
    let mut nsid_req = rtnetlink::packet_core::NetlinkMessage::new(
        rtnetlink::packet_core::NetlinkHeader::default(),
        rtnetlink::packet_core::NetlinkPayload::InnerMessage(
            rtnetlink::packet_route::RouteNetlinkMessage::GetNsId(nsid_msg),
        ),
    );
    nsid_req.header.flags = rtnetlink::packet_core::NLM_F_REQUEST;

    let mut netns = handle.request(nsid_req.clone()).unwrap();

    if let Some(msg) = netns.next().await {
        let rtnetlink::packet_core::NetlinkPayload::InnerMessage(
            rtnetlink::packet_route::RouteNetlinkMessage::NewNsId(payload),
        ) = msg.payload
        else {
            return None;
        };
        for attr in payload.attributes {
            if let rtnetlink::packet_route::nsid::NsidAttribute::Id(id) = attr {
                return Some(id);
            }
        }
    }

    None
}

fn resolve_ip_link_group_name(id: u32) -> String {
    // TODO: Read `/usr/share/iproute2/group` and `/etc/iproute2/group`
    match id {
        0 => "default".into(),
        _ => id.to_string(),
    }
}

async fn resolve_netns_names(
    links: &mut [CliLinkInfo],
) -> Result<(), CliError> {
    let (conn, mut handle, _) = rtnetlink::new_connection().unwrap();
    tokio::spawn(conn);

    // Read netns names from /run/netns
    let netnses = std::fs::read_dir("/run/netns");
    if let Err(e) = &netnses
        && e.kind() == std::io::ErrorKind::NotFound
    {
        // No /run/netns, nothing to resolve
        return Ok(());
    }
    let netnses = netnses?;

    let mut id_to_name: HashMap<i32, String> = HashMap::new();
    for netns in netnses {
        let netns = netns?;
        let name = netns.file_name().into_string().unwrap_or_default();
        let file = std::fs::File::open(netns.path())?;

        if let Some(id) =
            get_netns_id_from_fd(&mut handle, file.as_raw_fd() as u32).await
        {
            id_to_name.insert(id, name);
        }
    }

    for link in links.iter_mut() {
        if let Some(link_netns_id) = link.link_netnsid
            && let Some(name) = id_to_name.get(&link_netns_id)
        {
            link.link_netns = name.to_string();
        }
    }

    Ok(())
}

fn resolve_controller_and_link_names(links: &mut [CliLinkInfo]) {
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
        if let Some(link_ifindex) = link.link_index {
            if link_ifindex == 0 {
                continue;
            }

            // Only set link name if the link is from the current netns
            if let Some(name) = index_2_name.get(&link_ifindex)
                && link.link_netnsid.is_none()
            {
                link.link = Some(name.to_string());
                // Clear link_index if we have a name
                // We want to serialize one or the other
                link.link_index = None;
            }
        }
    }
}
