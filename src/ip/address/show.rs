// SPDX-License-Identifier: MIT

use std::collections::HashMap;

use futures_util::TryStreamExt;
use indexmap::IndexMap;
use iproute_rs::{CanDisplay, CanOutput, CliColor, write_with_color};
use rtnetlink::packet_route::{
    AddressFamily,
    address::{AddressAttribute, AddressFlags, AddressMessage, AddressScope},
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
    #[serde(flatten, skip_serializing_if = "IndexMap::is_empty")]
    flags: IndexMap<String, bool>,
    #[serde(skip_serializing_if = "String::is_empty")]
    protocol: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    label: String,
    valid_life_time: u32,
    preferred_life_time: u32,
}

#[derive(Clone, Copy)]
struct AddressFlagData {
    name: &'static str,
    mask: AddressFlags,
}

// equal to iproute2 `struct ifa_flag_data_t` in `ipaddress.c`
const ADDRESS_FLAG_DATA: &[AddressFlagData] = &[
    AddressFlagData {
        name: "secondary",
        mask: AddressFlags::Secondary,
    },
    AddressFlagData {
        name: "temporary",
        mask: AddressFlags::Secondary,
    },
    AddressFlagData {
        name: "nodad",
        mask: AddressFlags::Nodad,
    },
    AddressFlagData {
        name: "optimistic",
        mask: AddressFlags::Optimistic,
    },
    AddressFlagData {
        name: "dadfailed",
        mask: AddressFlags::Dadfailed,
    },
    AddressFlagData {
        name: "home",
        mask: AddressFlags::Homeaddress,
    },
    AddressFlagData {
        name: "deprecated",
        mask: AddressFlags::Deprecated,
    },
    AddressFlagData {
        name: "tentative",
        mask: AddressFlags::Tentative,
    },
    AddressFlagData {
        name: "permanent",
        mask: AddressFlags::Permanent,
    },
    AddressFlagData {
        name: "mngtmpaddr",
        mask: AddressFlags::Managetempaddr,
    },
    AddressFlagData {
        name: "noprefixroute",
        mask: AddressFlags::Noprefixroute,
    },
    AddressFlagData {
        name: "autojoin",
        mask: AddressFlags::Mcautojoin,
    },
    AddressFlagData {
        name: "stable-privacy",
        mask: AddressFlags::StablePrivacy,
    },
];

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
        self.write_flags(f)?;

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
                format!("{}sec", self.valid_life_time)
            },
            if self.preferred_life_time == u32::MAX {
                "forever".to_string()
            } else {
                format!("{}sec", self.preferred_life_time)
            }
        )?;
        Ok(())
    }
}

impl CliAddressInfo {
    fn write_flags(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for flag_name in self.flags.iter().filter_map(|(flag_name, value)| {
            if *value { Some(flag_name) } else { None }
        }) {
            write!(f, "{} ", flag_name)?;
        }
        Ok(())
    }
}

impl CanDisplay for CliAddressInfo {
    fn gen_string(&self) -> String {
        self.to_string()
    }
}

impl CanOutput for CliAddressInfo {}

fn addr_scope_to_cli_string(addr_scope: &AddressScope) -> String {
    match addr_scope {
        AddressScope::Universe => "global".to_string(),
        _ => addr_scope.to_string(),
    }
}

fn get_address_flags(
    family: AddressFamily,
    flags: AddressFlags,
) -> IndexMap<String, bool> {
    let mut ret = IndexMap::new();
    let mut flags = flags;

    for flag_data in ADDRESS_FLAG_DATA {
        if flag_data.mask == AddressFlags::Permanent {
            if !flags.contains(flag_data.mask) {
                ret.insert("dynamic".to_string(), true);
            }
        } else if flags.contains(flag_data.mask) {
            if flag_data.mask == AddressFlags::Secondary
                && family == AddressFamily::Inet6
            {
                ret.insert("temporary".to_string(), true);
            } else {
                ret.insert(flag_data.name.to_string(), true);
            }
        }
        flags.remove(flag_data.mask);
    }
    // iproute2 shows unknown flags in hex format, to support so
    // the IndexMap<String, bool> need to be changed to IndexMap<String, String>
    // which is overskill for this unknown flags. Let's just log a debug info
    // and wait bug report.
    if !flags.is_empty() {
        log::debug!("Unknown address flags: {:02x}", flags.bits());
    }
    ret
}

fn parse_nl_msg_to_address(
    nl_msg: AddressMessage,
) -> Result<CliAddressInfo, CliError> {
    let index = nl_msg.header.index;
    let family = nl_msg.header.family.to_string();
    let mut local = String::new();
    let prefixlen = nl_msg.header.prefix_len;
    let mut broadcast = None;
    let scope = addr_scope_to_cli_string(&nl_msg.header.scope);
    let mut flags =
        AddressFlags::from_bits_retain(nl_msg.header.flags.bits().into());
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
                flags = f;
            }
            AddressAttribute::Protocol(p) => {
                protocol = p.to_string();
            }
            _ => {
                // println!("Remains {:?}", nla);
            }
        }
    }

    let cli_addr_info = CliAddressInfo {
        index,
        family,
        local,
        prefixlen,
        broadcast,
        scope,
        flags: get_address_flags(nl_msg.header.family, flags),
        label,
        valid_life_time,
        preferred_life_time,
        protocol,
    };

    Ok(cli_addr_info)
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
