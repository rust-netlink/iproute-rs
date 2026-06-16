// SPDX-License-Identifier: MIT

use iproute_rs::CliError;
use rtnetlink::{
    LinkMessageBuilder, LinkVrf,
    packet_route::link::{InfoKind, InfoVrf, LinkInfo},
};
use serde::Serialize;

use super::parse::{extract_link_info, parse_u32};
use crate::link::LinkBaseConf;

#[derive(Serialize)]
pub(crate) struct CliLinkInfoDataVrf {
    table: u32,
}

impl From<&[InfoVrf]> for CliLinkInfoDataVrf {
    fn from(info: &[InfoVrf]) -> Self {
        let mut table = 0;
        for nla in info {
            if let InfoVrf::TableId(id) = nla {
                table = *id;
            }
        }
        Self { table }
    }
}

fn apply_vrf_args<'a>(
    mut builder: LinkMessageBuilder<LinkVrf>,
    iter: &mut impl Iterator<Item = &'a str>,
) -> Result<LinkMessageBuilder<LinkVrf>, CliError> {
    while let Some(key) = iter.next() {
        let Some(v) = iter.next() else {
            return Err(CliError::from(format!("\"{key}\" requires a value")));
        };
        match key {
            "table" => {
                builder = builder.table_id(parse_u32(v, "table")?);
            }
            _ => {
                return Err(CliError::from(format!(
                    "vrf: unknown option \"{key}\"",
                )));
            }
        }
    }
    Ok(builder)
}

impl LinkBaseConf {
    pub(crate) fn apply_vrf(
        &self,
    ) -> Result<LinkMessageBuilder<LinkVrf>, CliError> {
        let mut table_set = false;
        let mut remaining: Vec<&str> = Vec::new();
        let mut iter = self.iface_specific.iter();
        while let Some(key) = iter.next() {
            match key.as_str() {
                "help" => {
                    return Err(CliError::from("Usage: ... vrf table TABLEID"));
                }
                "table" => {
                    table_set = true;
                    remaining.push(key);
                    if let Some(v) = iter.next() {
                        remaining.push(v);
                    }
                }
                _ => {
                    remaining.push(key);
                    if let Some(v) = iter.next() {
                        remaining.push(v);
                    }
                }
            }
        }

        if !table_set {
            return Err(CliError::from("vrf: missing \"table\" argument"));
        }

        let builder = LinkMessageBuilder::<LinkVrf>::new(&self.name);
        let mut remaining_iter = remaining.into_iter();
        let builder = apply_vrf_args(builder, &mut remaining_iter)?;
        Ok(builder)
    }
}

impl std::fmt::Display for CliLinkInfoDataVrf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "table {}", self.table)
    }
}

#[derive(Serialize)]
pub(crate) struct CliLinkInfoDataVrfPort {
    table: u32,
}

impl From<&[InfoVrf]> for CliLinkInfoDataVrfPort {
    fn from(info: &[InfoVrf]) -> Self {
        let mut table = 0;
        for nla in info {
            if let InfoVrf::TableId(id) = nla {
                table = *id;
            }
        }
        Self { table }
    }
}

impl std::fmt::Display for CliLinkInfoDataVrfPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "table {}", self.table)
    }
}

pub(crate) fn build_vrf_entries(
    args: &[String],
) -> Result<Vec<LinkInfo>, CliError> {
    let builder =
        LinkMessageBuilder::<LinkVrf>::new_with_info_kind(InfoKind::Vrf);
    let mut iter = args.iter().map(|s| s.as_str());
    let builder = apply_vrf_args(builder, &mut iter)?;
    Ok(extract_link_info(builder.build()))
}
