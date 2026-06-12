// SPDX-License-Identifier: MIT

use iproute_rs::CliError;
use rtnetlink::{LinkMessageBuilder, LinkVrf, packet_route::link::InfoVrf};
use serde::Serialize;

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

impl LinkBaseConf {
    pub(crate) fn apply_vrf(
        &self,
    ) -> Result<LinkMessageBuilder<LinkVrf>, CliError> {
        let mut iter = self.iface_specific.iter();
        let mut table_id: Option<u32> = None;

        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "table" => {
                    let Some(value) = iter.next() else {
                        return Err(CliError::from(
                            "vrf: \"table\" requires a value",
                        ));
                    };
                    table_id = Some(value.parse::<u32>().map_err(|_| {
                        CliError::from(format!(
                            "vrf: invalid table ID \"{value}\""
                        ))
                    })?);
                }
                "help" => {
                    return Err(CliError::from("Usage: ... vrf table TABLEID"));
                }
                other => {
                    return Err(CliError::from(format!(
                        "vrf: unknown option \"{other}\"?",
                    )));
                }
            }
        }

        let table_id = table_id
            .ok_or_else(|| CliError::from("vrf: missing \"table\" argument"))?;
        Ok(LinkVrf::new(&self.name, table_id))
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
