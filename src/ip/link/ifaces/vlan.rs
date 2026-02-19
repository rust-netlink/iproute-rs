// SPDX-License-Identifier: MIT

use rtnetlink::packet_route::link::{InfoVlan, VlanFlags};
use serde::Serialize;

#[derive(Serialize)]
pub(crate) struct CliLinkInfoDataVlan {
    protocol: String,
    id: u16,
    flags: Vec<String>,
}

impl From<&[InfoVlan]> for CliLinkInfoDataVlan {
    fn from(info: &[InfoVlan]) -> Self {
        let mut id = 0;
        let mut flags = Vec::new();
        let mut protocol = String::new();

        for nla in info {
            match nla {
                InfoVlan::Id(v) => id = *v,
                InfoVlan::Flags((flags_val, _)) => {
                    if flags_val.contains(VlanFlags::ReorderHdr) {
                        flags.push("REORDER_HDR".to_string());
                    }
                    if flags_val.contains(VlanFlags::Gvrp) {
                        flags.push("GVRP".to_string());
                    }
                    if flags_val.contains(VlanFlags::LooseBinding) {
                        flags.push("LOOSE_BINDING".to_string());
                    }
                    if flags_val.contains(VlanFlags::Mvrp) {
                        flags.push("MVRP".to_string());
                    }
                    if flags_val.contains(VlanFlags::BridgeBinding) {
                        flags.push("BRIDGE_BINDING".to_string());
                    }
                }
                InfoVlan::Protocol(v) => {
                    protocol = v.to_string().to_uppercase();
                }
                _ => (),
            }
        }

        Self {
            id,
            flags,
            protocol,
        }
    }
}

impl std::fmt::Display for CliLinkInfoDataVlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "protocol {} ", self.protocol)?;
        write!(f, "id {} ", self.id)?;
        if !self.flags.is_empty() {
            write!(f, "<{}>", self.flags.as_slice().join(","))?;
        }
        Ok(())
    }
}
