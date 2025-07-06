// SPDX-License-Identifier: MIT

use std::collections::HashMap;

use futures_util::stream::TryStreamExt;
use rtnetlink::packet_route::link::{LinkAttribute, LinkMessage};
use serde::Serialize;

use super::flags::link_flags_to_string;
use iproute_rs::{
    CanDisplay, CanOutput, CliColor, CliError, mac_to_string, write_with_color,
};

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
    txqlen: u32,
    link_type: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    address: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    broadcast: String,
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
        write!(
            f,
            "mode {} group {} qlen {}",
            self.linkmode, self.group, self.txqlen,
        )?;
        write!(f, "\n    ")?;
        write!(f, "link/{} ", self.link_type)?;
        if !self.address.is_empty() {
            write_with_color!(f, CliColor::Mac, "{}", self.address)?;
            write!(f, " brd ")?;
            write_with_color!(f, CliColor::Mac, "{}", self.broadcast)?;
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
        ifaces.push(parse_nl_msg_to_iface(nl_msg)?);
    }

    resolve_controller_name(&mut ifaces);

    Ok(ifaces)
}

pub(crate) fn parse_nl_msg_to_iface(
    nl_msg: LinkMessage,
) -> Result<CliLinkInfo, CliError> {
    let mut ret = CliLinkInfo {
        ifindex: nl_msg.header.index,
        flags: link_flags_to_string(nl_msg.header.flags),
        link_type: nl_msg.header.link_layer_type.to_string().to_lowercase(),
        ..Default::default()
    };

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
            LinkAttribute::TxQueueLen(v) => ret.txqlen = v,
            LinkAttribute::Group(v) => {
                ret.group = resolve_ip_link_group_name(v)
            }
            LinkAttribute::Mode(v) => ret.linkmode = link_mode_to_string(v),
            LinkAttribute::Controller(d) => ret.controller_ifindex = Some(d),
            _ => {
                // println!("Remains {:?}", nl_attr);
            }
        }
    }
    Ok(ret)
}

fn resolve_ip_link_group_name(id: u32) -> String {
    // TODO: Read `/usr/share/iproute2/group` and `/etc/iproute2/group`
    match id {
        0 => "default".into(),
        _ => id.to_string(),
    }
}

// TODO: https://github.com/rust-netlink/netlink-packet-route/pull/171
fn link_mode_to_string(mode: u8) -> String {
    match mode {
        0 => "DEFAULT".into(),
        1 => "DORMANT".into(),
        2 => "TESTING".into(),
        _ => format!("UNKNOWN:{mode}"),
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
