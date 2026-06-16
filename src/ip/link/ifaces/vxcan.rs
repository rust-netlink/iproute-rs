// SPDX-License-Identifier: MIT

use iproute_rs::CliError;
use rtnetlink::{LinkMessageBuilder, LinkVxcan};

use crate::link::LinkBaseConf;

impl LinkBaseConf {
    pub(crate) fn apply_vxcan(
        &self,
    ) -> Result<LinkMessageBuilder<LinkVxcan>, CliError> {
        let mut iter = self.iface_specific.iter();
        match iter.next() {
            Some(v) if v == "peer" => {}
            Some(other) => {
                return Err(CliError::from(format!(
                    "vxcan expects peer argument, got {other}"
                )));
            }
            None => {
                return Err(CliError::from("vxcan requires peer argument"));
            }
        }
        // iproute2 supports both "peer <name>" and "peer name <name>"
        let peer = match iter.next() {
            Some(v) if v == "name" => iter.next(),
            Some(v) => Some(v),
            None => None,
        };
        let Some(peer) = peer else {
            return Err(CliError::from("vxcan peer requires a value"));
        };
        Ok(LinkVxcan::new(&self.name, peer))
    }
}

pub(crate) struct IfaceVxcan;

impl IfaceVxcan {
    #[rustfmt::skip]
    pub(crate) fn print_help() -> &'static str {
        r"Usage: ip link <options> type vxcan [peer <options>]
To get <options> type 'ip link add help'
"
    }
}
