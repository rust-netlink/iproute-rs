// SPDX-License-Identifier: MIT

use iproute_rs::CliError;
use rtnetlink::{
    LinkMessageBuilder, LinkNetkit,
    packet_route::link::{InfoNetkit, NetkitMode, NetkitPolicy, NetkitScrub},
};
use serde::Serialize;

use crate::link::LinkBaseConf;

#[derive(Serialize)]
pub(crate) struct CliLinkInfoDataNetkit {
    mode: String,
    #[serde(rename = "type")]
    typ: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer_policy: Option<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    scrub: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    peer_scrub: String,
}

impl From<&[InfoNetkit]> for CliLinkInfoDataNetkit {
    fn from(info: &[InfoNetkit]) -> Self {
        let mut mode = String::new();
        let mut typ = String::new();
        let mut policy = None;
        let mut peer_policy = None;
        let mut scrub = String::new();
        let mut peer_scrub = String::new();
        for nla in info {
            match nla {
                InfoNetkit::Mode(m) => {
                    mode = match m {
                        NetkitMode::L2 => "l2".to_string(),
                        NetkitMode::L3 => "l3".to_string(),
                        _ => format!("{m:?}"),
                    };
                }
                InfoNetkit::Primary(v) => {
                    typ = if *v {
                        "primary".to_string()
                    } else {
                        "peer".to_string()
                    };
                }
                InfoNetkit::Policy(p) => {
                    policy = Some(match p {
                        NetkitPolicy::Pass => "forward".to_string(),
                        NetkitPolicy::Drop => "blackhole".to_string(),
                        _ => format!("{p:?}"),
                    });
                }
                InfoNetkit::PeerPolicy(p) => {
                    peer_policy = Some(match p {
                        NetkitPolicy::Pass => "forward".to_string(),
                        NetkitPolicy::Drop => "blackhole".to_string(),
                        _ => format!("{p:?}"),
                    });
                }
                InfoNetkit::Scrub(s) => {
                    scrub = match s {
                        NetkitScrub::None => "none".to_string(),
                        NetkitScrub::Default => "default".to_string(),
                        _ => format!("{s:?}"),
                    };
                }
                InfoNetkit::PeerScrub(s) => {
                    peer_scrub = match s {
                        NetkitScrub::None => "none".to_string(),
                        NetkitScrub::Default => "default".to_string(),
                        _ => format!("{s:?}"),
                    };
                }
                _ => (),
            }
        }

        Self {
            mode,
            typ,
            policy,
            peer_policy,
            scrub,
            peer_scrub,
        }
    }
}

impl LinkBaseConf {
    pub(crate) fn apply_netkit(
        &self,
    ) -> Result<LinkMessageBuilder<LinkNetkit>, CliError> {
        let mut mode = NetkitMode::L3;
        let mut policy = None;
        let mut peer_policy = None;
        let mut scrub = None;
        let mut peer_scrub = None;
        let mut peer_name = None;
        let mut seen_peer = false;

        let mut iter = self.iface_specific.iter().peekable();
        while let Some(key) = iter.next() {
            match key.as_str() {
                "mode" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "netkit mode requires a value",
                        ));
                    };
                    mode = match v.as_str() {
                        "l3" => NetkitMode::L3,
                        "l2" => NetkitMode::L2,
                        _ => {
                            return Err(CliError::from(format!(
                                "netkit mode must be l3 or l2, got {v}"
                            )));
                        }
                    };
                }
                "forward" | "blackhole" => {
                    let p = match key.as_str() {
                        "forward" => NetkitPolicy::Pass,
                        _ => NetkitPolicy::Drop,
                    };
                    if seen_peer {
                        peer_policy = Some(p);
                    } else {
                        policy = Some(p);
                    }
                }
                "peer" => {
                    seen_peer = true;
                }
                "name" if seen_peer => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "netkit peer name requires a value",
                        ));
                    };
                    peer_name = Some(v.clone());
                }
                "scrub" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "netkit scrub requires a value",
                        ));
                    };
                    let s = match v.as_str() {
                        "default" => NetkitScrub::Default,
                        "none" => NetkitScrub::None,
                        _ => {
                            return Err(CliError::from(format!(
                                "netkit scrub must be default or none, got {v}"
                            )));
                        }
                    };
                    if seen_peer {
                        peer_scrub = Some(s);
                    } else {
                        scrub = Some(s);
                    }
                }
                _ if seen_peer && peer_name.is_none() => {
                    peer_name = Some(key.clone());
                }
                _ => {
                    return Err(CliError::from(format!(
                        "Unknown netkit argument: {key}"
                    )));
                }
            }
        }

        let mut builder = LinkMessageBuilder::<LinkNetkit>::new_with_info_kind(
            rtnetlink::packet_route::link::InfoKind::Netkit,
        )
        .name(self.name.clone())
        .mode(mode);

        if let Some(ref name) = peer_name {
            builder = builder.peer(name);
        }

        if let Some(p) = policy {
            builder = builder.policy(p);
        }

        if let Some(p) = peer_policy {
            builder = builder.peer_policy(p);
        }

        if let Some(s) = scrub {
            builder = builder.scrub(s);
        }

        if let Some(s) = peer_scrub {
            builder = builder.peer_scrub(s);
        }

        Ok(builder)
    }
}

impl std::fmt::Display for CliLinkInfoDataNetkit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "mode {} type {}", self.mode, self.typ)?;
        if let Some(ref policy) = self.policy {
            write!(f, " policy {policy}")?;
        }
        if let Some(ref peer_policy) = self.peer_policy {
            write!(f, " peer policy {peer_policy}")?;
        }
        if !self.scrub.is_empty() {
            write!(f, " scrub {}", self.scrub)?;
        }
        if !self.peer_scrub.is_empty() {
            write!(f, " peer scrub {}", self.peer_scrub)?;
        }
        Ok(())
    }
}
