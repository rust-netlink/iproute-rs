// SPDX-License-Identifier: MIT

use iproute_rs::CliError;
use rtnetlink::{
    LinkMessageBuilder, LinkVeth,
    packet_route::link::{InfoVeth, LinkAttribute},
};
use serde::Serialize;

use crate::link::LinkBaseConf;

#[derive(Serialize)]
pub(crate) struct CliLinkInfoDataVeth {
    peer: String,
}

impl From<&InfoVeth> for CliLinkInfoDataVeth {
    fn from(info: &InfoVeth) -> Self {
        let mut peer = String::new();
        if let InfoVeth::Peer(msg) = info {
            for attr in &msg.attributes {
                if let LinkAttribute::IfName(name) = attr {
                    peer = name.clone();
                    break;
                }
            }
        }
        Self { peer }
    }
}

impl LinkBaseConf {
    pub(crate) fn apply_veth(
        &self,
    ) -> Result<LinkMessageBuilder<LinkVeth>, CliError> {
        let mut iter = self.iface_specific.iter();
        match iter.next() {
            Some(v) if v == "peer" => {}
            Some(other) => {
                return Err(CliError::from(format!(
                    "veth expects peer argument, got {other}"
                )));
            }
            None => {
                return Err(CliError::from("veth requires peer argument"));
            }
        }
        let Some(peer) = iter.next() else {
            return Err(CliError::from("veth peer requires a value"));
        };
        Ok(LinkVeth::new(&self.name, peer))
    }
}

impl std::fmt::Display for CliLinkInfoDataVeth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if !self.peer.is_empty() {
            write!(f, "peer {}", self.peer)?;
        }
        Ok(())
    }
}
