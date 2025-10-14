// SPDX-License-Identifier: MIT

use std::collections::HashMap;

use futures_util::TryStreamExt;
use iproute_rs::{CanDisplay, CanOutput, CliColor, write_with_color};
use rtnetlink::packet_route::{
    AddressFamily,
    address::{
        AddressAttribute, AddressFlags, AddressMessage, AddressProtocol,
        AddressScope,
    },
};
use serde::Serialize;

use crate::{CliError, link::CliLinkInfo};

#[derive(Serialize, Default)]
pub(crate) struct CliAddressInfo {
    #[serde(skip)]
    index: u32,
    family: String,
    local: String,
    prefixlen: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    broadcast: Option<String>,
    scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    tentative: Option<bool>,
    #[serde(skip_serializing_if = "String::is_empty")]
    protocol: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    label: String,
    valid_life_time: u32,
    preferred_life_time: u32,
}

impl std::fmt::Display for CliAddressInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ", self.family)?;
        write_with_color!(
            f,
            CliColor::address_color(&self.family),
            "{}",
            self.local
        )?;
        write!(f, "/{}", self.prefixlen)?;
        if let Some(broadcast) = &self.broadcast {
            write!(f, " brd ")?;
            write_with_color!(
                f,
                CliColor::address_color(&self.family),
                "{}",
                broadcast
            )?;
        }
        write!(f, " scope {} ", self.scope)?;
        if Some(true) == self.tentative {
            write!(f, "tentative ")?;
        }

        if !self.protocol.is_empty() {
            write!(f, "proto {} ", self.protocol)?;
        }

        write!(f, "{}", self.label)?;

        write!(
            f,
            "\n       valid_lft {} preferred_lft {}",
            if self.valid_life_time == u32::MAX {
                "forever".to_string()
            } else {
                self.valid_life_time.to_string()
            },
            if self.preferred_life_time == u32::MAX {
                "forever".to_string()
            } else {
                self.preferred_life_time.to_string()
            }
        )?;
        Ok(())
    }
}

impl CanDisplay for CliAddressInfo {
    fn gen_string(&self) -> String {
        self.to_string()
    }
}

impl CanOutput for CliAddressInfo {}

fn addr_family_to_cli_string(addr_family: &AddressFamily) -> String {
    match addr_family {
        AddressFamily::Unspec => "unspec".to_string(),
        AddressFamily::Local => "local".to_string(),
        AddressFamily::Unix => "unix".to_string(),
        AddressFamily::Inet => "inet".to_string(),
        AddressFamily::Ax25 => "ax25".to_string(),
        AddressFamily::Ipx => "ipx".to_string(),
        AddressFamily::Appletalk => "appletalk".to_string(),
        AddressFamily::Netrom => "netrom".to_string(),
        AddressFamily::Bridge => "bridge".to_string(),
        AddressFamily::Atmpvc => "atmpvc".to_string(),
        AddressFamily::X25 => "x25".to_string(),
        AddressFamily::Inet6 => "inet6".to_string(),
        AddressFamily::Rose => "rose".to_string(),
        AddressFamily::Decnet => "decnet".to_string(),
        AddressFamily::Netbeui => "netbeui".to_string(),
        AddressFamily::Security => "security".to_string(),
        AddressFamily::Key => "key".to_string(),
        AddressFamily::Route => "route".to_string(),
        AddressFamily::Netlink => "netlink".to_string(),
        AddressFamily::Packet => "packet".to_string(),
        AddressFamily::Ash => "ash".to_string(),
        AddressFamily::Econet => "econet".to_string(),
        AddressFamily::Atmsvc => "atmsvc".to_string(),
        AddressFamily::Rds => "rds".to_string(),
        AddressFamily::Sna => "sna".to_string(),
        AddressFamily::Irda => "irda".to_string(),
        AddressFamily::Pppox => "pppox".to_string(),
        AddressFamily::Wanpipe => "wanpipe".to_string(),
        AddressFamily::Llc => "llc".to_string(),
        #[cfg(not(target_os = "android"))]
        AddressFamily::Ib => "ib".to_string(),
        #[cfg(not(target_os = "android"))]
        AddressFamily::Mpls => "mpls".to_string(),
        AddressFamily::Can => "can".to_string(),
        AddressFamily::Tipc => "tipc".to_string(),
        AddressFamily::Bluetooth => "bluetooth".to_string(),
        AddressFamily::Iucv => "iucv".to_string(),
        AddressFamily::Rxrpc => "rxrpc".to_string(),
        AddressFamily::Isdn => "isdn".to_string(),
        AddressFamily::Phonet => "phonet".to_string(),
        AddressFamily::Ieee802154 => "ieee802154".to_string(),
        AddressFamily::Caif => "caif".to_string(),
        AddressFamily::Alg => "alg".to_string(),
        AddressFamily::Nfc => "nfc".to_string(),
        AddressFamily::Vsock => "vsock".to_string(),
        AddressFamily::Kcm => "kcm".to_string(),
        AddressFamily::Qipcrtr => "qipcrtr".to_string(),
        AddressFamily::Smc => "smc".to_string(),
        AddressFamily::Xdp => "xdp".to_string(),
        AddressFamily::Mctp => "mctp".to_string(),
        AddressFamily::Other(_) | _ => "unknown".to_string(),
    }
}

fn addr_scope_to_cli_string(addr_scope: &AddressScope) -> String {
    match addr_scope {
        AddressScope::Universe => "global",
        AddressScope::Site => "site",
        AddressScope::Link => "link",
        AddressScope::Host => "host",
        AddressScope::Nowhere => "nowhere",
        AddressScope::Other(_) | _ => "unknown",
    }
    .to_string()
}

fn addr_protocol_to_string(protocol: &AddressProtocol) -> String {
    match protocol {
        AddressProtocol::Loopback => "kernel_lo",
        AddressProtocol::RouterAnnouncement => "kernel_ra",
        AddressProtocol::LinkLocal => "kernel_ll",
        _ => "unknown",
    }
    .to_string()
}

fn parse_nl_msg_to_address(
    nl_msg: AddressMessage,
) -> Result<CliAddressInfo, CliError> {
    let index = nl_msg.header.index;
    let family = addr_family_to_cli_string(&nl_msg.header.family);
    let mut local = String::new();
    let prefixlen = nl_msg.header.prefix_len;
    let mut broadcast = None;
    let scope = addr_scope_to_cli_string(&nl_msg.header.scope);
    let mut tentative = None;
    let mut label = String::new();
    let mut valid_life_time = u32::MAX;
    let mut preferred_life_time = u32::MAX;
    let mut protocol = String::new();

    for nla in nl_msg.attributes {
        match nla {
            AddressAttribute::Local(a) => {
                local = a.to_string();
            }
            AddressAttribute::Address(a) if local.is_empty() => {
                local = a.to_string();
            }
            AddressAttribute::Broadcast(a) => {
                broadcast = Some(a.to_string());
            }
            AddressAttribute::Label(s) => {
                label = s;
            }
            AddressAttribute::CacheInfo(c) => {
                valid_life_time = c.ifa_valid;
                preferred_life_time = c.ifa_preferred;
            }
            AddressAttribute::Flags(f) => {
                // If there is no tentative flag the field should be None
                tentative = (nl_msg.header.family == AddressFamily::Inet6
                    && f.contains(AddressFlags::Tentative))
                .then_some(true);
            }
            AddressAttribute::Protocol(p) => {
                protocol = addr_protocol_to_string(&p)
            }
            _ => {
                // println!("Remains {:?}", nla);
            }
        }
    }

    Ok(CliAddressInfo {
        index,
        family,
        local,
        prefixlen,
        broadcast,
        scope,
        tentative,
        label,
        valid_life_time,
        preferred_life_time,
        protocol,
    })
}

pub(crate) async fn handle_show(
    opts: &[&str],
    include_details: bool,
) -> Result<Vec<CliLinkInfo>, CliError> {
    let (connection, handle, _) = rtnetlink::new_connection()?;

    tokio::spawn(connection);

    let mut address_get_handle = handle.address().get();

    if let Some(iface_name) = opts.first() {
        let link_get_handle =
            handle.link().get().match_name(iface_name.to_string());
        let link =
            link_get_handle.execute().try_next().await?.ok_or_else(|| {
                CliError::from(
                    format!("Device \"{iface_name}\" does not exist.").as_str(),
                )
            })?;
        address_get_handle =
            address_get_handle.set_link_index_filter(link.header.index);
    }

    let mut addresses = address_get_handle.execute();
    let mut addresses_infos: Vec<CliAddressInfo> = Vec::new();

    while let Some(nl_msg) = addresses.try_next().await? {
        addresses_infos.push(parse_nl_msg_to_address(nl_msg)?);
    }

    let mut links_info: HashMap<u32, _> =
        crate::link::handle_show(opts, include_details)
            .await?
            .into_iter()
            .map(|mut link_info| {
                link_info.show_only_addr_details();
                link_info
            })
            .map(|link_info| (link_info.get_ifindex(), link_info))
            .collect();

    for addr_info in addresses_infos {
        if let Some(link_info) = links_info.get_mut(&addr_info.index) {
            link_info.add_address(addr_info);
        }
    }

    let mut result: Vec<CliLinkInfo> = links_info.into_values().collect();
    result.sort_by_key(|link| link.get_ifindex());

    Ok(result)
}
