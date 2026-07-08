// SPDX-License-Identifier: MIT

use iproute_rs::CliError;
use rtnetlink::{
    LinkMessageBuilder, LinkXfrm,
    packet_route::link::{InfoKind, InfoXfrm, LinkInfo},
};
use serde::{Serialize, Serializer};

use super::parse::extract_link_info;
use crate::link::LinkBaseConf;

pub(crate) struct CliLinkInfoDataXfrm {
    if_id: u32,
}

impl Serialize for CliLinkInfoDataXfrm {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("CliLinkInfoDataXfrm", 1)?;
        s.serialize_field("if_id", &format_args!("{:#x}", self.if_id))?;
        s.end()
    }
}

impl From<&[InfoXfrm]> for CliLinkInfoDataXfrm {
    fn from(info: &[InfoXfrm]) -> Self {
        let mut if_id = 0;
        for i in info {
            if let InfoXfrm::IfId(v) = i {
                if_id = *v;
            }
        }
        Self { if_id }
    }
}

impl std::fmt::Display for CliLinkInfoDataXfrm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "if_id {:#x}", self.if_id)
    }
}

async fn parse_xfrm_dev(
    handle: &rtnetlink::Handle,
    name: &str,
) -> Result<u32, CliError> {
    let mut links = handle.link().get().match_name(name.to_string()).execute();
    use futures_util::TryStreamExt;
    let link = links.try_next().await?.ok_or_else(|| {
        CliError::from(format!("Device \"{name}\" does not exist"))
    })?;
    Ok(link.header.index)
}

async fn parse_xfrm_args<'a>(
    mut builder: LinkMessageBuilder<LinkXfrm>,
    iter: &mut impl Iterator<Item = &'a str>,
    handle: &rtnetlink::Handle,
) -> Result<LinkMessageBuilder<LinkXfrm>, CliError> {
    let mut dev: Option<u32> = None;
    let mut if_id: Option<u32> = None;

    while let Some(arg) = iter.next() {
        match arg {
            "dev" => {
                let Some(dev_name) = iter.next() else {
                    return Err(CliError::from("xfrm dev requires a value"));
                };
                dev = Some(parse_xfrm_dev(handle, dev_name).await?);
            }
            "if_id" => {
                let Some(val) = iter.next() else {
                    return Err(CliError::from("xfrm if_id requires a value"));
                };
                if_id = Some(parse_if_id(val)?);
            }
            other => {
                return Err(CliError::from(format!(
                    "xfrm: unknown argument {other}"
                )));
            }
        }
    }

    if let Some(if_id) = if_id {
        builder = builder.if_id(if_id);
    }
    if let Some(dev_index) = dev {
        builder = builder.dev(dev_index);
    }

    Ok(builder)
}

impl LinkBaseConf {
    pub(crate) async fn apply_xfrm(
        &self,
        handle: &rtnetlink::Handle,
    ) -> Result<LinkMessageBuilder<LinkXfrm>, CliError> {
        let builder = LinkXfrm::new(&self.name, 0, 0);
        let mut has_if_id = false;
        for arg in &self.iface_specific {
            if arg == "if_id" {
                has_if_id = true;
                break;
            }
        }
        let mut iter = self.iface_specific.iter().map(|s| s.as_str());
        let builder = parse_xfrm_args(builder, &mut iter, handle).await?;
        if !has_if_id {
            return Err(CliError::from("xfrm requires if_id argument"));
        }
        Ok(builder)
    }
}

fn parse_if_id(val: &str) -> Result<u32, CliError> {
    let v = val
        .strip_prefix("0x")
        .or_else(|| val.strip_prefix("0X"))
        .map_or_else(|| val.parse::<u32>(), |hex| u32::from_str_radix(hex, 16));
    v.map_err(|_| CliError::from(format!("invalid if_id value: {val}")))
}

pub(crate) struct IfaceXfrm;

impl IfaceXfrm {
    pub(crate) async fn build_entries(
        handle: &rtnetlink::Handle,
        args: &[String],
    ) -> Result<Vec<LinkInfo>, CliError> {
        let builder =
            LinkMessageBuilder::<LinkXfrm>::new_with_info_kind(InfoKind::Xfrm);
        let mut iter = args.iter().map(|s| s.as_str());
        let builder = parse_xfrm_args(builder, &mut iter, handle).await?;
        Ok(extract_link_info(builder.build()))
    }

    #[rustfmt::skip]
    pub(crate) fn print_help() -> &'static str {
        r"Usage: ... xfrm dev [ PHYS_DEV ] [ if_id IF-ID ]
                [ external ]

Where: IF-ID := { 0x1..0xffffffff }
"
    }
}
