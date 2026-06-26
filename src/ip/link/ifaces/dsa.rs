// SPDX-License-Identifier: MIT

use std::collections::HashMap;

use futures_util::TryStreamExt;
use iproute_rs::CliError;
use rtnetlink::{
    LinkDsa, LinkMessageBuilder,
    packet_route::link::{InfoDsa, InfoKind, LinkInfo},
};
use serde::Serialize;

use super::parse::extract_link_info;
use crate::link::LinkBaseConf;

#[derive(Serialize)]
pub(crate) struct CliLinkInfoDataDsa {
    conduit: String,
}

impl From<&[InfoDsa]> for CliLinkInfoDataDsa {
    fn from(info: &[InfoDsa]) -> Self {
        let mut conduit = String::new();
        for nla in info {
            match nla {
                InfoDsa::Conduit(v) => {
                    conduit = v.to_string();
                }
                _ => {}
            }
        }
        Self { conduit }
    }
}

impl CliLinkInfoDataDsa {
    pub(crate) fn resolve_link(&mut self, index_2_name: &HashMap<u32, String>) {
        if let Ok(ifindex) = self.conduit.parse::<u32>() {
            if let Some(name) = index_2_name.get(&ifindex) {
                self.conduit = name.clone();
            } else {
                self.conduit = format!("if{ifindex}");
            }
        }
    }
}

impl std::fmt::Display for CliLinkInfoDataDsa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "conduit {}", self.conduit)
    }
}

async fn get_ifindex_by_name(
    handle: &rtnetlink::Handle,
    name: &str,
) -> Result<u32, CliError> {
    let mut links = handle.link().get().match_name(name.to_string()).execute();
    let link = links.try_next().await?.ok_or_else(|| {
        CliError::from(format!("Device \"{name}\" does not exist"))
    })?;
    Ok(link.header.index)
}

async fn apply_dsa_args<'a>(
    mut builder: LinkMessageBuilder<LinkDsa>,
    handle: &rtnetlink::Handle,
    iter: &mut impl Iterator<Item = &'a str>,
) -> Result<LinkMessageBuilder<LinkDsa>, CliError> {
    while let Some(key) = iter.next() {
        match key {
            "conduit" | "master" => {
                let Some(v) = iter.next() else {
                    return Err(CliError::from(format!(
                        "\"{key}\" requires a value"
                    )));
                };
                let ifindex = get_ifindex_by_name(handle, v).await?;
                builder = builder.conduit(ifindex);
            }
            _ => {
                return Err(CliError::from(format!(
                    "dsa: unknown option \"{key}\""
                )));
            }
        }
    }
    Ok(builder)
}

impl LinkBaseConf {
    pub(crate) async fn apply_dsa(
        &self,
        handle: &rtnetlink::Handle,
    ) -> Result<LinkMessageBuilder<LinkDsa>, CliError> {
        let builder = LinkMessageBuilder::<LinkDsa>::new(&self.name);
        if self.iface_specific.is_empty() {
            return Ok(builder);
        }
        let mut iter = self.iface_specific.iter().map(|s| s.as_str());
        apply_dsa_args(builder, handle, &mut iter).await
    }
}

pub(crate) struct IfaceDsa;

impl IfaceDsa {
    pub(crate) async fn build_entries(
        handle: &rtnetlink::Handle,
        args: &[String],
    ) -> Result<Vec<LinkInfo>, CliError> {
        let builder =
            LinkMessageBuilder::<LinkDsa>::new_with_info_kind(InfoKind::Dsa);
        if args.is_empty() {
            return Ok(extract_link_info(builder.build()));
        }
        let mut iter = args.iter().map(|s| s.as_str());
        let builder = apply_dsa_args(builder, handle, &mut iter).await?;
        Ok(extract_link_info(builder.build()))
    }

    #[rustfmt::skip]
    pub(crate) fn print_help() -> &'static str {
        r"Usage: ... dsa [ conduit DEVICE ]"
    }
}
