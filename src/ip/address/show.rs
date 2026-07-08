// SPDX-License-Identifier: MIT

use std::{collections::HashMap, net::IpAddr};

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
    #[serde(skip_serializing_if = "Option::is_none")]
    peer: Option<String>,
    prefixlen: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    broadcast: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    anycast: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    multicast: Option<String>,
    scope: String,
    #[serde(flatten, skip_serializing_if = "IndexMap::is_empty")]
    flags: IndexMap<String, bool>,
    #[serde(skip_serializing_if = "String::is_empty")]
    protocol: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    label: String,
    valid_life_time: u32,
    preferred_life_time: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    metric: Option<u32>,
}

#[derive(Clone, Copy)]
struct AddressFlagData {
    name: &'static str,
    mask: AddressFlags,
}

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
    // iproute2 never prints "permanent". When Permanent is not set,
    // it prints "dynamic" instead. The entry must be before mngtmpaddr
    // to match iproute2's flag display order.
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
        if let Some(peer) = &self.peer {
            write!(f, " peer ")?;
            write_with_color!(
                f,
                CliColor::address_color(&self.family),
                "{}",
                peer
            )?;
        }
        write!(f, "/{}", self.prefixlen)?;
        if let Some(m) = self.metric {
            write!(f, " metric {m}")?;
        }
        if let Some(broadcast) = &self.broadcast {
            write!(f, " brd ")?;
            write_with_color!(
                f,
                CliColor::address_color(&self.family),
                "{}",
                broadcast
            )?;
        }
        if let Some(anycast) = &self.anycast {
            write!(f, " anycast ")?;
            write_with_color!(
                f,
                CliColor::address_color(&self.family),
                "{}",
                anycast
            )?;
        }
        write!(f, " scope {}", self.scope)?;
        if let Some(ref mcast) = self.multicast {
            write!(f, " mcast {mcast}")?;
        }
        write!(f, " ")?;
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

    if !flags.is_empty() {
        log::debug!("Unknown address flags: {:02x}", flags.bits());
    }
    ret
}

pub(crate) fn parse_nl_msg_to_address(
    nl_msg: AddressMessage,
) -> Result<CliAddressInfo, CliError> {
    let index = nl_msg.header.index;
    let family = nl_msg.header.family.to_string();
    let mut local = String::new();
    let mut address_attr = String::new();
    let prefixlen = nl_msg.header.prefix_len;
    let mut broadcast = None;
    let mut anycast = None;
    let mut multicast = None;
    let mut metric = None;
    let scope = addr_scope_to_cli_string(&nl_msg.header.scope);
    let mut flags =
        AddressFlags::from_bits_retain(nl_msg.header.flags.bits().into());
    let mut label = String::new();
    let mut valid_life_time = u32::MAX;
    let mut preferred_life_time = u32::MAX;
    let mut protocol = String::new();

    for nla in nl_msg.attributes {
        match nla {
            AddressAttribute::Local(a) => local = a.to_string(),
            AddressAttribute::Address(a) => address_attr = a.to_string(),
            AddressAttribute::Broadcast(a) => broadcast = Some(a.to_string()),
            AddressAttribute::Anycast(a) => anycast = Some(a.to_string()),
            AddressAttribute::Multicast(a) => multicast = Some(a.to_string()),
            AddressAttribute::RoutePriority(m) => metric = Some(m),
            AddressAttribute::Label(s) => label = s,
            AddressAttribute::CacheInfo(c) => {
                valid_life_time = c.ifa_valid;
                preferred_life_time = c.ifa_preferred;
            }
            AddressAttribute::Flags(f) => flags = f,
            AddressAttribute::Protocol(p) => protocol = p.to_string(),
            _ => {}
        }
    }

    // If no IFA_LOCAL, use IFA_ADDRESS as local
    if local.is_empty() {
        local = address_attr;
        address_attr = String::new();
    }

    // Set peer only when IFA_ADDRESS differs from IFA_LOCAL
    let peer = if !address_attr.is_empty() && address_attr != local {
        Some(address_attr)
    } else {
        None
    };

    let cli_addr_info = CliAddressInfo {
        index,
        family,
        local,
        peer,
        prefixlen,
        broadcast,
        anycast,
        multicast,
        scope,
        flags: get_address_flags(nl_msg.header.family, flags),
        label,
        valid_life_time,
        preferred_life_time,
        protocol,
        metric,
    };

    Ok(cli_addr_info)
}

pub(crate) struct AddressShowFilter {
    pub(crate) dev_name: Option<String>,
    pub(crate) scope: Option<u8>,
    pub(crate) to_prefix: Option<IpAddr>,
    pub(crate) to_prefix_len: Option<u8>,
    pub(crate) label: Option<String>,
    pub(crate) proto: Option<u8>,
    pub(crate) flags_set: AddressFlags,
    pub(crate) flags_not_set: AddressFlags,
}

/// Simple fnmatch-like pattern matching supporting * and ?
fn fnmatch_simple(pattern: &str, text: &str) -> bool {
    let pattern_chars: Vec<char> = pattern.chars().collect();
    let text_chars: Vec<char> = text.chars().collect();

    fn match_helper(pattern: &[char], text: &[char]) -> bool {
        let mut pi = 0;
        let mut ti = 0;

        while pi < pattern.len() || ti < text.len() {
            if pi < pattern.len() && pattern[pi] == '*' {
                pi += 1;
                // Try matching rest of pattern at every position
                for i in ti..=text.len() {
                    if match_helper(&pattern[pi..], &text[i..]) {
                        return true;
                    }
                }
                return false;
            } else if pi < pattern.len() && pattern[pi] == '?' {
                pi += 1;
                if ti >= text.len() {
                    return false;
                }
                ti += 1;
            } else if pi < pattern.len()
                && ti < text.len()
                && pattern[pi] == text[ti]
            {
                pi += 1;
                ti += 1;
            } else {
                return false;
            }
        }
        true
    }

    match_helper(&pattern_chars, &text_chars)
}

impl AddressShowFilter {
    pub(crate) fn parse(
        opts: &[&str],
    ) -> Result<(Self, Vec<String>), CliError> {
        let mut dev_name: Option<String> = None;
        let mut scope: Option<u8> = None;
        let mut to_prefix: Option<IpAddr> = None;
        let mut to_prefix_len: Option<u8> = None;
        let mut label: Option<String> = None;
        let mut proto: Option<u8> = None;
        let mut flags_set = AddressFlags::empty();
        let mut flags_not_set = AddressFlags::empty();
        let mut link_opts: Vec<String> = Vec::new();
        let mut positional_dev: Option<String> = None;

        let mut iter = opts.iter().peekable();
        while let Some(arg) = iter.next() {
            match *arg {
                "dev" => {
                    let val = iter.next().ok_or_else(|| {
                        CliError::from("\"dev\" requires a value")
                    })?;
                    dev_name = Some(val.to_string());
                }
                "scope" => {
                    let val = iter.next().ok_or_else(|| {
                        CliError::from("\"scope\" requires a value")
                    })?;
                    scope = Some(parse_scope_value(val)?);
                }
                "to" => {
                    let val = iter.next().ok_or_else(|| {
                        CliError::from("\"to\" requires a value")
                    })?;
                    let (addr, plen) = parse_prefix(val)?;
                    to_prefix = Some(addr);
                    to_prefix_len = plen;
                }
                "label" => {
                    let val = iter.next().ok_or_else(|| {
                        CliError::from("\"label\" requires a value")
                    })?;
                    label = Some(val.to_string());
                }
                "proto" => {
                    let val = iter.next().ok_or_else(|| {
                        CliError::from("\"proto\" requires a value")
                    })?;
                    proto = Some(parse_protocol_value(val)?);
                }
                "permanent" => {
                    flags_set |= AddressFlags::Permanent;
                }
                "dynamic" => {
                    flags_not_set |= AddressFlags::Permanent;
                }
                "secondary" | "temporary" => {
                    flags_set |= AddressFlags::Secondary;
                }
                "primary" => {
                    flags_not_set |= AddressFlags::Secondary;
                }
                "nodad" => flags_set |= AddressFlags::Nodad,
                "optimistic" => flags_set |= AddressFlags::Optimistic,
                "dadfailed" => flags_set |= AddressFlags::Dadfailed,
                "home" => flags_set |= AddressFlags::Homeaddress,
                "deprecated" => flags_set |= AddressFlags::Deprecated,
                "tentative" => flags_set |= AddressFlags::Tentative,
                "mngtmpaddr" => flags_set |= AddressFlags::Managetempaddr,
                "noprefixroute" => flags_set |= AddressFlags::Noprefixroute,
                "autojoin" => flags_set |= AddressFlags::Mcautojoin,
                "stable-privacy" => flags_set |= AddressFlags::StablePrivacy,
                "up" | "down" | "master" | "vrf" | "type" | "group"
                | "nomaster" | "novf" | "name" => {
                    // Link-level options: pass through
                    link_opts.push(arg.to_string());
                    if let Some(val) = iter.peek()
                        && !val.starts_with('-')
                    {
                        link_opts.push(iter.next().unwrap().to_string());
                    }
                }
                _ => {
                    // If starts with "-", it's a negated flag
                    if let Some(flag_name) = arg.strip_prefix('-') {
                        match flag_name {
                            "permanent" => {
                                flags_not_set |= AddressFlags::Permanent;
                            }
                            "dynamic" => {
                                flags_set |= AddressFlags::Permanent;
                            }
                            "secondary" | "temporary" => {
                                flags_not_set |= AddressFlags::Secondary;
                            }
                            "primary" => {
                                flags_set |= AddressFlags::Secondary;
                            }
                            "nodad" => flags_not_set |= AddressFlags::Nodad,
                            "optimistic" => {
                                flags_not_set |= AddressFlags::Optimistic
                            }
                            "dadfailed" => {
                                flags_not_set |= AddressFlags::Dadfailed
                            }
                            "home" => {
                                flags_not_set |= AddressFlags::Homeaddress
                            }
                            "deprecated" => {
                                flags_not_set |= AddressFlags::Deprecated
                            }
                            "tentative" => {
                                flags_not_set |= AddressFlags::Tentative
                            }
                            "mngtmpaddr" => {
                                flags_not_set |= AddressFlags::Managetempaddr
                            }
                            "noprefixroute" => {
                                flags_not_set |= AddressFlags::Noprefixroute
                            }
                            "autojoin" => {
                                flags_not_set |= AddressFlags::Mcautojoin
                            }
                            "stable-privacy" => {
                                flags_not_set |= AddressFlags::StablePrivacy
                            }
                            _ => {
                                if positional_dev.is_none() {
                                    positional_dev = Some(arg.to_string());
                                } else {
                                    link_opts.push(arg.to_string());
                                }
                            }
                        }
                    } else if positional_dev.is_none() {
                        positional_dev = Some(arg.to_string());
                    } else {
                        link_opts.push(arg.to_string());
                    }
                }
            }
        }

        let dev = dev_name.clone().or(positional_dev);

        // Forward device name to link-level opts
        if let Some(ref d) = dev {
            link_opts.push(d.clone());
        }

        Ok((
            AddressShowFilter {
                dev_name: dev,
                scope,
                to_prefix,
                to_prefix_len,
                label,
                proto,
                flags_set,
                flags_not_set,
            },
            link_opts,
        ))
    }

    pub(crate) fn matches(
        &self,
        addr: &CliAddressInfo,
        msg: &AddressMessage,
    ) -> bool {
        if let Some(s) = self.scope {
            let scope_val: u8 = msg.header.scope.into();
            if scope_val != s {
                return false;
            }
        }

        if let Some(ref label_pat) = self.label
            && !fnmatch_simple(label_pat.as_str(), &addr.label)
        {
            return false;
        }

        if let Some(p) = self.proto {
            let addr_proto = msg
                .attributes
                .iter()
                .find_map(|a| {
                    if let AddressAttribute::Protocol(ap) = a {
                        Some(u8::from(*ap))
                    } else {
                        None
                    }
                })
                .unwrap_or(0);
            if addr_proto != p {
                return false;
            }
        }

        if let Some(ref target) = self.to_prefix {
            let addr_ip: IpAddr = match addr.local.parse() {
                Ok(ip) => ip,
                Err(_) => return false,
            };
            if addr_ip != *target {
                return false;
            }
            if let Some(plen) = self.to_prefix_len
                && addr.prefixlen != plen
            {
                return false;
            }
        }

        if !self.flags_set.is_empty() {
            let addr_flags = get_addr_flags_from_msg(msg);
            if !addr_flags.contains(self.flags_set) {
                return false;
            }
        }

        if !self.flags_not_set.is_empty() {
            let addr_flags = get_addr_flags_from_msg(msg);
            if addr_flags.intersects(self.flags_not_set) {
                return false;
            }
        }

        true
    }
}

pub(crate) fn get_addr_flags_from_msg(msg: &AddressMessage) -> AddressFlags {
    let mut flags =
        AddressFlags::from_bits_retain(msg.header.flags.bits().into());
    for nla in &msg.attributes {
        if let AddressAttribute::Flags(f) = nla {
            flags = *f;
        }
    }
    flags
}

pub(crate) fn parse_scope_value(s: &str) -> Result<u8, CliError> {
    match s {
        "global" | "universe" => Ok(0),
        "site" => Ok(200),
        "link" => Ok(253),
        "host" => Ok(254),
        "nowhere" => Ok(255),
        "all" => Ok(255), // special: match any
        _ => s
            .parse::<u8>()
            .map_err(|_| CliError::from(format!("invalid scope: {s}"))),
    }
}

pub(crate) fn parse_prefix(s: &str) -> Result<(IpAddr, Option<u8>), CliError> {
    if let Some((addr_str, plen_str)) = s.split_once('/') {
        let addr: IpAddr = addr_str.parse().map_err(|_| {
            CliError::from(format!("invalid address: {addr_str}"))
        })?;
        let plen = plen_str.parse::<u8>().map_err(|_| {
            CliError::from(format!("invalid prefix length: {plen_str}"))
        })?;
        Ok((addr, Some(plen)))
    } else {
        let addr: IpAddr = s
            .parse()
            .map_err(|_| CliError::from(format!("invalid address: {s}")))?;
        Ok((addr, None))
    }
}

pub(crate) fn parse_protocol_value(s: &str) -> Result<u8, CliError> {
    match s {
        "kernel_lo" => Ok(1),
        "kernel_ra" => Ok(2),
        "kernel_ll" => Ok(3),
        _ => s
            .parse::<u8>()
            .map_err(|_| CliError::from(format!("invalid protocol: {s}"))),
    }
}

pub(crate) async fn handle_show(
    opts: &[&str],
    include_details: bool,
    preferred_family: Option<AddressFamily>,
) -> Result<Vec<CliLinkInfo>, CliError> {
    let (addr_filter, link_opts) = AddressShowFilter::parse(opts)?;
    let link_opts_refs: Vec<&str> =
        link_opts.iter().map(String::as_str).collect();

    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    let mut address_get_handle = handle.address().get();

    if let Some(ref iface_name) = addr_filter.dev_name {
        let mut links =
            handle.link().get().match_name(iface_name.clone()).execute();
        let link = links.try_next().await?.ok_or_else(|| {
            CliError::from(
                format!("Device \"{iface_name}\" does not exist.").as_str(),
            )
        })?;
        address_get_handle =
            address_get_handle.set_link_index_filter(link.header.index);
    }

    if let Some(ref addr) = addr_filter.to_prefix {
        address_get_handle = address_get_handle.set_address_filter(*addr);
    }

    if let Some(plen) = addr_filter.to_prefix_len {
        address_get_handle = address_get_handle.set_prefix_length_filter(plen);
    }

    let mut addresses = address_get_handle.execute();
    let mut addresses_infos: Vec<CliAddressInfo> = Vec::new();
    let mut address_msgs: Vec<AddressMessage> = Vec::new();

    while let Some(nl_msg) = addresses.try_next().await? {
        address_msgs.push(nl_msg);
    }

    for msg in &address_msgs {
        if let Some(family) = preferred_family
            && msg.header.family != family
        {
            continue;
        }
        let addr_info = parse_nl_msg_to_address(msg.clone())?;
        if addr_filter.matches(&addr_info, msg) {
            addresses_infos.push(addr_info);
        }
    }

    let mut links_info: HashMap<u32, _> =
        crate::link::handle_show(&link_opts_refs, include_details)
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
