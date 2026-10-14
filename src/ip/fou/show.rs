// SPDX-License-Identifier: MIT

use iproute_rs::{CanDisplay, CanOutput};
use nl_fou::{FouAddressFamily, FouConfig, FouEncap};
use serde::Serialize;

use super::add::index_to_name;
use crate::CliError;

#[derive(Serialize, Default)]
pub(crate) struct CliFou {
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gue: Option<()>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ipproto: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    family: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    local: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dev: Option<String>,
    /// `-6` is only printed in the plain text output.
    #[serde(skip)]
    ipv6: bool,
}

impl std::fmt::Display for CliFou {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(port) = self.port {
            write!(f, "port {port}")?;
        }
        if self.gue.is_some() {
            write!(f, " gue")?;
        } else if let Some(ipproto) = self.ipproto {
            write!(f, " ipproto {ipproto}")?;
        }
        if self.ipv6 {
            write!(f, " -6")?;
        }
        if let Some(local) = &self.local {
            write!(f, " local {local}")?;
        }
        if let Some(peer) = &self.peer {
            write!(f, " peer {peer}")?;
        }
        if let Some(peer_port) = self.peer_port {
            write!(f, " peer_port {peer_port}")?;
        }
        if let Some(dev) = &self.dev {
            write!(f, " dev {dev}")?;
        }
        Ok(())
    }
}

impl CanDisplay for CliFou {
    fn gen_string(&self) -> String {
        self.to_string()
    }
}

impl CanOutput for CliFou {}

fn parse_config_to_cli_fou(config: FouConfig) -> CliFou {
    // iproute2 prints `gue` instead of `ipproto` for a GUE listener, even
    // when the kernel reports an ipproto attribute.
    let gue = config.encap == Some(FouEncap::Gue);
    CliFou {
        port: config.port,
        gue: gue.then_some(()),
        ipproto: if gue { None } else { config.ipproto },
        family: config.family.map(family_name),
        local: config.local.map(|addr| addr.to_string()),
        peer: config.peer.map(|addr| addr.to_string()),
        peer_port: config.peer_port,
        dev: config.ifindex.and_then(index_to_name),
        ipv6: config.family == Some(FouAddressFamily::Ipv6),
    }
}

fn family_name(family: FouAddressFamily) -> String {
    match family {
        FouAddressFamily::Ipv4 => "inet".to_string(),
        FouAddressFamily::Ipv6 => "inet6".to_string(),
        _ => "???".to_string(),
    }
}

pub(crate) async fn handle_show() -> Result<Vec<CliFou>, CliError> {
    let (connection, mut handle, _) = nl_fou::new_connection()?;
    tokio::spawn(connection);

    let listeners = handle.get_all().await?;
    Ok(listeners.into_iter().map(parse_config_to_cli_fou).collect())
}
