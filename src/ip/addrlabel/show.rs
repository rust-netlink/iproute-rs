// SPDX-License-Identifier: MIT

use std::collections::HashMap;

use futures_util::TryStreamExt;
use iproute_rs::{CanDisplay, CanOutput, CliColor, write_with_color};
use rtnetlink::{
    IpVersion,
    packet_route::{
        AddressFamily,
        addrlabel::{AddrLabelAttribute, AddrLabelMessage},
    },
};
use serde::Serialize;

use crate::CliError;

#[derive(Serialize, Default)]
pub(crate) struct CliAddrLabel {
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    prefixlen: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ifname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<u32>,
    #[serde(skip)]
    family: String,
}

impl std::fmt::Display for CliAddrLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let (Some(address), Some(prefixlen)) =
            (&self.address, self.prefixlen)
        {
            write!(f, "prefix ")?;
            write_with_color!(
                f,
                CliColor::address_color(&self.family),
                "{}",
                address
            )?;
            write!(f, "/{prefixlen} ")?;
        }
        if let Some(ifname) = &self.ifname {
            write!(f, "dev ")?;
            write_with_color!(f, CliColor::IfaceName, "{}", ifname)?;
            write!(f, " ")?;
        }
        if let Some(label) = self.label {
            write!(f, "label {label} ")?;
        }
        Ok(())
    }
}

impl CanDisplay for CliAddrLabel {
    fn gen_string(&self) -> String {
        self.to_string()
    }
}

impl CanOutput for CliAddrLabel {}

fn parse_nl_msg_to_addr_label(
    nl_msg: AddrLabelMessage,
    ifnames: &HashMap<u32, String>,
) -> CliAddrLabel {
    let prefix_len = nl_msg.header.prefix_len;
    let mut ret = CliAddrLabel {
        ifname: index_to_name(nl_msg.header.index, ifnames),
        family: nl_msg.header.family.to_string(),
        ..Default::default()
    };

    for nla in nl_msg.attributes {
        match nla {
            AddrLabelAttribute::Address(address) => {
                ret.address = Some(address.to_string());
                // iproute2 only prints the prefix length together with the
                // address attribute.
                ret.prefixlen = Some(prefix_len);
            }
            AddrLabelAttribute::Label(label) => ret.label = Some(label),
            _ => {}
        }
    }
    ret
}

/// iproute2 `ll_index_to_name()` falls back to `if%u` when the interface
/// index is unknown, e.g. the device was removed after the address label was
/// added.
fn index_to_name(index: u32, ifnames: &HashMap<u32, String>) -> Option<String> {
    if index == 0 {
        // iproute2 only prints `dev` when the interface index is not zero.
        return None;
    }
    Some(
        ifnames
            .get(&index)
            .cloned()
            .unwrap_or_else(|| format!("if{index}")),
    )
}

/// iproute2 defaults `ip addrlabel` to the IPv6 address family.
pub(crate) fn resolve_family(
    preferred_family: Option<AddressFamily>,
) -> AddressFamily {
    match preferred_family {
        None => AddressFamily::Inet6,
        // `ip -0 addrlabel` uses the packet family which the kernel does not
        // support for address labels.
        Some(AddressFamily::Unspec) => AddressFamily::Packet,
        Some(family) => family,
    }
}

pub(crate) async fn handle_show(
    preferred_family: Option<AddressFamily>,
) -> Result<Vec<CliAddrLabel>, CliError> {
    let links = crate::link::handle_show(&[], false, 0, false).await?;
    let ifnames: HashMap<u32, String> = links
        .into_iter()
        .map(|link| (link.get_ifindex(), link.get_ifname().to_string()))
        .collect();

    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    let mut request = handle.addrlabel().get(IpVersion::V6);
    request.message_mut().header.family = resolve_family(preferred_family);

    let mut labels = request.execute();
    let mut ret: Vec<CliAddrLabel> = Vec::new();
    while let Some(nl_msg) = labels.try_next().await? {
        ret.push(parse_nl_msg_to_addr_label(nl_msg, &ifnames));
    }

    Ok(ret)
}
