// SPDX-License-Identifier: MIT

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
};

use futures_util::TryStreamExt;
use indexmap::IndexMap;
use iproute_rs::{CanDisplay, CanOutput, CliColor, write_with_color};
use rtnetlink::packet_route::{
    AddressFamily,
    address::{
        AddressAttribute, AddressFlags, AddressMessage, AddressProtocol,
        AddressScope,
    },
};
use serde::Serialize;

use crate::{
    CliError,
    link::{BriefMode, CliAddrBriefLink, CliLinkBrief, CliLinkInfo},
};

#[derive(Default)]
pub(crate) struct CliAddressInfo {
    index: u32,
    brief: bool,
    /// Whether an address filter rejected this address. iproute2
    /// `print_addrinfo()` returns before printing anything for such an
    /// address, which makes `-j` emit an empty JSON object.
    rejected: bool,
    family: String,
    local: String,
    peer: Option<String>,
    prefixlen: u8,
    metric: Option<u32>,
    broadcast: Option<String>,
    anycast: Option<String>,
    multicast: Option<String>,
    scope: String,
    flags: IndexMap<String, bool>,
    protocol: String,
    label: String,
    valid_life_time: u32,
    preferred_life_time: u32,
}

/// iproute2 `print_addrinfo()` opens the JSON object before applying the
/// address filters, so rejected addresses are serialized as `{}` while all
/// other addresses serialize their fields.
impl Serialize for CliAddressInfo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;

        if self.rejected {
            return serializer.serialize_map(Some(0))?.end();
        }

        // `ip address show -br` only serializes the address and its prefix
        // length, matching `print_addrinfo()` brief mode.
        if self.brief {
            let mut map = serializer.serialize_map(None)?;
            map.serialize_entry("local", &self.local)?;
            if let Some(peer) = &self.peer {
                map.serialize_entry("address", peer)?;
            }
            map.serialize_entry("prefixlen", &self.prefixlen)?;
            if let Some(metric) = self.metric {
                map.serialize_entry("metric", &metric)?;
            }
            return map.end();
        }

        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("family", &self.family)?;
        map.serialize_entry("local", &self.local)?;
        if let Some(peer) = &self.peer {
            map.serialize_entry("peer", peer)?;
        }
        map.serialize_entry("prefixlen", &self.prefixlen)?;
        if let Some(metric) = self.metric {
            map.serialize_entry("metric", &metric)?;
        }
        if let Some(broadcast) = &self.broadcast {
            map.serialize_entry("broadcast", broadcast)?;
        }
        if let Some(anycast) = &self.anycast {
            map.serialize_entry("anycast", anycast)?;
        }
        if let Some(multicast) = &self.multicast {
            map.serialize_entry("multicast", multicast)?;
        }
        map.serialize_entry("scope", &self.scope)?;
        for (flag, value) in &self.flags {
            map.serialize_entry(flag, value)?;
        }
        if !self.protocol.is_empty() {
            map.serialize_entry("protocol", &self.protocol)?;
        }
        if !self.label.is_empty() {
            map.serialize_entry("label", &self.label)?;
        }
        map.serialize_entry("valid_life_time", &self.valid_life_time)?;
        map.serialize_entry("preferred_life_time", &self.preferred_life_time)?;
        map.end()
    }
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
        // In brief mode, skip family prefix
        if !self.brief {
            write!(f, "{} ", self.family)?;
        }
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

        // In brief mode, skip everything else
        if self.brief {
            return Ok(());
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
            } else if self.flags.get("deprecated") == Some(&true) {
                // Deprecated addresses can have negative preferred_lft
                format!("{}sec", self.preferred_life_time as i32)
            } else {
                format!("{}sec", self.preferred_life_time)
            }
        )?;
        Ok(())
    }
}

impl CliAddressInfo {
    pub(crate) fn set_rejected(&mut self) {
        self.rejected = true;
    }

    pub(crate) fn is_rejected(&self) -> bool {
        self.rejected
    }

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

/// iproute2 `rtnl_addrprot_n2a()` prints protocols unknown to it as hex
/// numbers, e.g. `proto 0x63` instead of `proto 99`.
fn addr_proto_to_string(proto: AddressProtocol) -> String {
    match proto {
        AddressProtocol::Loopback => "kernel_lo".to_string(),
        AddressProtocol::RouterAnnouncement => "kernel_ra".to_string(),
        AddressProtocol::LinkLocal => "kernel_ll".to_string(),
        _ => {
            let proto: u8 = proto.into();
            format!("0x{proto:x}")
        }
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
    brief: bool,
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
            AddressAttribute::Protocol(p) => protocol = addr_proto_to_string(p),
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
        brief,
        rejected: false,
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
    pub(crate) scope_mask: u8,
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
        let mut scope_mask: u8 = 0xff;
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
                    let (scope_val, mask) = parse_scope_value(val)?;
                    scope = Some(scope_val);
                    scope_mask = mask;
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
                scope_mask,
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
        ifname: Option<&str>,
    ) -> bool {
        self.link_matches(addr, msg, ifname) && self.proto_matches(msg)
    }

    /// Whether iproute2 `ipaddr_filter()` would keep the link of this
    /// address. The protocol filter is not part of it because iproute2
    /// applies it while printing each address.
    pub(crate) fn link_matches(
        &self,
        addr: &CliAddressInfo,
        msg: &AddressMessage,
        ifname: Option<&str>,
    ) -> bool {
        if let Some(s) = self.scope {
            let scope_val: u8 = msg.header.scope.into();
            if (scope_val ^ s) & self.scope_mask != 0 {
                return false;
            }
        }

        if let Some(ref label_pat) = self.label {
            // iproute2 `ifa_label_match_rta()` falls back to the interface
            // name for addresses without an `IFA_LABEL` attribute.
            let label = if addr.label.is_empty() {
                ifname.unwrap_or("")
            } else {
                addr.label.as_str()
            };
            if !fnmatch_simple(label_pat.as_str(), label) {
                return false;
            }
        }

        if let Some(ref target) = self.to_prefix {
            let addr_ip: IpAddr = match addr.local.parse() {
                Ok(ip) => ip,
                Err(_) => return false,
            };

            // Check if address falls within the target prefix
            if let Some(plen) = self.to_prefix_len {
                // Network prefix containment check
                match (target, &addr_ip) {
                    (IpAddr::V4(target_v4), IpAddr::V4(addr_v4)) => {
                        let target_u32 = u32::from(*target_v4);
                        let addr_u32 = u32::from(*addr_v4);
                        let mask = if plen == 0 {
                            0u32
                        } else {
                            !0u32 << (32 - plen)
                        };
                        if (target_u32 & mask) != (addr_u32 & mask) {
                            return false;
                        }
                    }
                    (IpAddr::V6(target_v6), IpAddr::V6(addr_v6)) => {
                        let target_u128 = u128::from(*target_v6);
                        let addr_u128 = u128::from(*addr_v6);
                        let mask = if plen == 0 {
                            0u128
                        } else {
                            !0u128 << (128 - plen)
                        };
                        if (target_u128 & mask) != (addr_u128 & mask) {
                            return false;
                        }
                    }
                    _ => return false, // IPv4/IPv6 mismatch
                }
            } else {
                // No prefix length specified, do exact match
                if addr_ip != *target {
                    return false;
                }
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

    /// iproute2 `print_addrinfo()` only rejects addresses which carry an
    /// `IFA_PROTO` attribute differing from the requested protocol.
    fn proto_matches(&self, msg: &AddressMessage) -> bool {
        let Some(proto) = self.proto else {
            return true;
        };
        match msg.attributes.iter().find_map(|a| {
            if let AddressAttribute::Protocol(ap) = a {
                Some(u8::from(*ap))
            } else {
                None
            }
        }) {
            Some(addr_proto) => addr_proto == proto,
            None => true,
        }
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

pub(crate) fn parse_scope_value(s: &str) -> Result<(u8, u8), CliError> {
    match s {
        "global" | "universe" => Ok((0, 0xff)),
        "site" => Ok((200, 0xff)),
        "link" => Ok((253, 0xff)),
        "host" => Ok((254, 0xff)),
        "nowhere" => Ok((255, 0xff)),
        "all" => Ok((255, 0)), // special: match any scope
        _ => {
            let v = s
                .parse::<u8>()
                .map_err(|_| CliError::from(format!("invalid scope: {s}")))?;
            Ok((v, 0xff))
        }
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
    // iproute2 `ipaddr_list_flush_or_save()` parses the `proto` filter with
    // `get_u8(..., 0)`, which only accepts decimal, hex and octal numbers,
    // unlike `rtnl_addrprot_a2n()` used when adding an address.
    let (radix, digits) = if let Some(hex) =
        s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))
    {
        (16, hex)
    } else if s.len() > 1 && s.starts_with('0') {
        (8, &s[1..])
    } else {
        (10, s)
    };
    u8::from_str_radix(digits, radix)
        .map_err(|_| CliError::from(format!("invalid protocol: {s}")))
}

/// One link of `ip -o address show` output. iproute2 omits the link
/// information in oneline mode and only prints the address entries, each
/// prefixed with the link index and name.
#[derive(Serialize)]
pub(crate) struct CliAddrOnelineLink {
    addr_info: Vec<CliAddrOnelineEntry>,
}

impl CliAddrOnelineLink {
    fn new(ifindex: u32, ifname: &str, addr_info: Vec<CliAddressInfo>) -> Self {
        Self {
            addr_info: addr_info
                .into_iter()
                .map(|addr| CliAddrOnelineEntry {
                    index: ifindex,
                    dev: ifname.to_string(),
                    addr,
                })
                .collect(),
        }
    }

    fn gen_string(&self) -> String {
        self.addr_info
            .iter()
            .filter_map(CliAddrOnelineEntry::gen_string)
            .collect::<Vec<String>>()
            .join("\n")
    }
}

struct CliAddrOnelineEntry {
    index: u32,
    dev: String,
    addr: CliAddressInfo,
}

/// The fields of an address entry printed in oneline mode.
#[derive(Serialize)]
struct CliAddrOnelineInfo<'a> {
    index: u32,
    dev: &'a str,
    #[serde(flatten)]
    addr: &'a CliAddressInfo,
}

impl Serialize for CliAddrOnelineEntry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // iproute2 serializes an address rejected by `print_addrinfo()` as
        // an empty JSON object without the `index` and `dev` keys.
        if self.addr.is_rejected() {
            use serde::ser::SerializeMap;

            return serializer.serialize_map(Some(0))?.end();
        }
        CliAddrOnelineInfo {
            index: self.index,
            dev: &self.dev,
            addr: &self.addr,
        }
        .serialize(serializer)
    }
}

impl CliAddrOnelineEntry {
    fn gen_string(&self) -> Option<String> {
        if self.addr.is_rejected() {
            return None;
        }
        // iproute2 replaces the newline of the continuation lines with a
        // backslash in oneline mode.
        Some(
            format!("{}: {}    {}", self.index, self.dev, self.addr)
                .replace('\n', "\\"),
        )
    }
}

/// `ip address show label PATTERN`: iproute2 `print_linkinfo()` returns
/// before printing the link information when a label filter is active, so
/// only the address list of each link is printed.
#[derive(Serialize)]
pub(crate) struct CliAddrOnlyLink {
    #[serde(skip)]
    brief: bool,
    /// `None` for the link family (`ip -0`), which does not dump any address.
    #[serde(skip_serializing_if = "Option::is_none")]
    addr_info: Option<Vec<CliAddressInfo>>,
}

impl std::fmt::Display for CliAddrOnlyLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Some(addr_info) = &self.addr_info else {
            return Ok(());
        };
        let mut first = true;
        for addr in addr_info.iter().filter(|a| !a.is_rejected()) {
            if self.brief {
                write!(f, "{addr} ")?;
            } else {
                if !first {
                    writeln!(f)?;
                }
                write!(f, "    {addr}")?;
            }
            first = false;
        }
        Ok(())
    }
}

impl CanDisplay for CliAddrOnlyLink {
    fn gen_string(&self) -> String {
        self.to_string()
    }
}

impl CanOutput for CliAddrOnlyLink {}

/// Output of the `ip address` subcommands.
pub(crate) enum AddressOutput {
    /// Full link information including the address list, used by
    /// `ip address show`.
    Links(Vec<CliLinkInfo>),
    /// `ip -o address show` only prints the address entries.
    Oneline(Vec<CliAddrOnelineLink>),
    /// `ip address show label PATTERN` only prints the address entries.
    Label(Vec<CliAddrOnlyLink>),
}

impl Serialize for AddressOutput {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Links(v) => {
                // `ip -br link show` and `ip -br address show` have their
                // own JSON shapes.
                if v.iter().any(CliLinkInfo::is_brief_link) {
                    let brief: Vec<CliLinkBrief<'_>> =
                        v.iter().map(CliLinkBrief::from).collect();
                    brief.serialize(serializer)
                } else if v.iter().any(CliLinkInfo::is_brief_address) {
                    let brief: Vec<CliAddrBriefLink<'_>> =
                        v.iter().map(CliAddrBriefLink::from).collect();
                    brief.serialize(serializer)
                } else {
                    v.serialize(serializer)
                }
            }
            Self::Oneline(v) => v.serialize(serializer),
            Self::Label(v) => v.serialize(serializer),
        }
    }
}

impl CanDisplay for AddressOutput {
    fn gen_string(&self) -> String {
        match self {
            Self::Links(v) => v.gen_string(),
            Self::Oneline(v) => v
                .iter()
                .map(CliAddrOnelineLink::gen_string)
                .filter(|s| !s.is_empty())
                .collect::<Vec<String>>()
                .join("\n"),
            Self::Label(v) => v
                .iter()
                .map(CliAddrOnlyLink::gen_string)
                .filter(|s| !s.is_empty())
                .collect::<Vec<String>>()
                .join("\n"),
        }
    }
}

impl CanOutput for AddressOutput {}

pub(crate) async fn handle_show(
    opts: &[&str],
    include_details: bool,
    preferred_family: Option<AddressFamily>,
    brief: bool,
    oneline: bool,
    statistics: u8,
) -> Result<AddressOutput, CliError> {
    let (addr_filter, link_opts) = AddressShowFilter::parse(opts)?;
    let link_opts_refs: Vec<&str> =
        link_opts.iter().map(String::as_str).collect();

    // iproute2 `ipaddr_list_flush_or_save()` restricts the dump to the
    // family of the `to PREFIX` when no other family was requested.
    let preferred_family = preferred_family.or_else(|| {
        addr_filter.to_prefix.map(|ip| match ip {
            IpAddr::V4(_) => AddressFamily::Inet,
            IpAddr::V6(_) => AddressFamily::Inet6,
        })
    });

    // `ip -0 address show` (link family) prints the link information like
    // `ip link show` does.
    let link_only = preferred_family == Some(AddressFamily::Unspec);
    // With an address family requested, iproute2 only prints the `link/...`
    // line when `-d` is used.
    let hide_link_info =
        !link_only && preferred_family.is_some() && !include_details;
    // iproute2 does not print the link statistics when the link information
    // is skipped or printed in brief form.
    let statistics = if brief || (oneline && !link_only) {
        0
    } else {
        statistics
    };

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

    // Note: We don't use netlink-level filters for "to" prefix because
    // the kernel does exact matching, not prefix containment. Instead,
    // we rely on the application-level matches() function which has
    // the correct prefix containment logic.

    let mut addresses = address_get_handle.execute();
    let mut address_msgs: Vec<AddressMessage> = Vec::new();

    while let Some(nl_msg) = addresses.try_next().await? {
        address_msgs.push(nl_msg);
    }

    let dumped_indexes: HashSet<u32> =
        address_msgs.iter().map(|msg| msg.header.index).collect();

    // The link information is collected before matching the addresses so
    // the label filter can fall back to the interface name.
    let mut links_info: HashMap<u32, _> = crate::link::handle_show(
        &link_opts_refs,
        include_details,
        statistics,
        oneline,
        false,
    )
    .await?
    .into_iter()
    .map(|mut link_info| {
        link_info.show_only_addr_details();
        if link_only {
            link_info.hide_addr_info();
        }
        if hide_link_info {
            link_info.hide_link_info();
        }
        if brief {
            link_info.set_brief(if link_only {
                BriefMode::Link
            } else {
                BriefMode::Address
            });
        }
        link_info.move_stats_after_addr_info();
        link_info
    })
    .map(|link_info| (link_info.get_ifindex(), link_info))
    .collect();

    let mut matched_indexes: HashSet<u32> = HashSet::new();

    for msg in &address_msgs {
        if let Some(family) = preferred_family
            && msg.header.family != family
        {
            continue;
        }
        let Some(link_info) = links_info.get_mut(&msg.header.index) else {
            continue;
        };
        let mut addr_info = parse_nl_msg_to_address(msg.clone(), brief)?;
        let ifname = link_info.get_ifname().to_string();
        if addr_filter.link_matches(&addr_info, msg, Some(&ifname)) {
            matched_indexes.insert(addr_info.index);
        }
        // iproute2 keeps showing the address of a matched link even when an
        // address filter rejects it, as an empty JSON object.
        if !addr_filter.matches(&addr_info, msg, Some(&ifname)) {
            addr_info.set_rejected();
        }
        link_info.add_address(addr_info);
    }

    // Like iproute2 `ipaddr_filter()`, drop links whose addresses are all
    // filtered out. Links without any address are kept when no address
    // family was requested.
    if preferred_family != Some(AddressFamily::Unspec) {
        links_info.retain(|index, _| {
            if dumped_indexes.contains(index) {
                matched_indexes.contains(index)
            } else {
                preferred_family.is_none()
            }
        });
    }

    let mut result: Vec<CliLinkInfo> = links_info.into_values().collect();
    result.sort_by_key(|link| link.get_ifindex());

    if oneline && !brief && !link_only {
        let links: Vec<CliAddrOnelineLink> = result
            .into_iter()
            .map(|mut link| {
                let addr_info = link.take_addr_info();
                CliAddrOnelineLink::new(
                    link.get_ifindex(),
                    link.get_ifname(),
                    addr_info,
                )
            })
            .collect();
        Ok(AddressOutput::Oneline(links))
    } else if addr_filter.label.is_some() {
        // `print_linkinfo()` returns early when a label filter is active,
        // so the link information is not printed at all.
        let links: Vec<CliAddrOnlyLink> = result
            .into_iter()
            .map(|mut link| CliAddrOnlyLink {
                brief,
                addr_info: if link_only {
                    None
                } else {
                    Some(link.take_addr_info())
                },
            })
            .collect();
        Ok(AddressOutput::Label(links))
    } else {
        Ok(AddressOutput::Links(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fnmatch_simple() {
        // Test exact match
        assert!(fnmatch_simple("test:0", "test:0"));
        assert!(!fnmatch_simple("test:0", "test:1"));

        // Test * wildcard
        assert!(fnmatch_simple("test:*", "test:0"));
        assert!(fnmatch_simple("test:*", "test:1"));
        assert!(fnmatch_simple("test:*", "test:"));
        assert!(!fnmatch_simple("test:*", "other:0"));

        // Test ? wildcard
        assert!(fnmatch_simple("test:?", "test:0"));
        assert!(fnmatch_simple("test:?", "test:1"));
        assert!(!fnmatch_simple("test:?", "test:"));
        assert!(!fnmatch_simple("test:?", "test:01"));

        // Test combined
        assert!(fnmatch_simple("*:0", "test:0"));
        assert!(fnmatch_simple("*:0", "other:0"));
        assert!(!fnmatch_simple("*:0", "test:1"));
    }
}
