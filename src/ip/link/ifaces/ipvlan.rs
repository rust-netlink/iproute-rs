// SPDX-License-Identifier: MIT

use iproute_rs::CliError;
use rtnetlink::{
    LinkIpVlan, LinkIpVtap, LinkMessageBuilder,
    packet_route::link::{
        InfoIpVlan, InfoIpVtap, IpVlanFlags, IpVlanMode, IpVtapMode,
    },
};
use serde::Serialize;

use crate::link::LinkBaseConf;

fn is_false(v: &bool) -> bool {
    !*v
}

#[derive(Serialize, Default)]
pub(crate) struct CliLinkInfoDataIpVlan {
    mode: String,
    #[serde(skip_serializing_if = "is_false")]
    bridge: bool,
    #[serde(skip_serializing_if = "is_false")]
    private: bool,
    #[serde(skip_serializing_if = "is_false")]
    vepa: bool,
}

impl From<&[InfoIpVlan]> for CliLinkInfoDataIpVlan {
    fn from(info: &[InfoIpVlan]) -> Self {
        let mut mode = String::new();
        let mut bridge = false;
        let mut private = false;
        let mut vepa = false;

        for nla in info {
            match nla {
                InfoIpVlan::Mode(v) => mode = v.to_string(),
                InfoIpVlan::Flags(flags_val) => {
                    if flags_val.contains(IpVlanFlags::Private) {
                        private = true;
                    } else if flags_val.contains(IpVlanFlags::Vepa) {
                        vepa = true;
                    } else {
                        bridge = true;
                    }
                }
                _ => (),
            }
        }

        Self {
            mode,
            bridge,
            private,
            vepa,
        }
    }
}

#[derive(Serialize, Default)]
pub(crate) struct CliLinkInfoDataIpVtap {
    mode: String,
    #[serde(skip_serializing_if = "is_false")]
    bridge: bool,
    #[serde(skip_serializing_if = "is_false")]
    private: bool,
    #[serde(skip_serializing_if = "is_false")]
    vepa: bool,
}

impl From<&[InfoIpVtap]> for CliLinkInfoDataIpVtap {
    fn from(info: &[InfoIpVtap]) -> Self {
        let mut mode = String::new();
        let mut bridge = false;
        let mut private = false;
        let mut vepa = false;

        for nla in info {
            match nla {
                InfoIpVtap::Mode(v) => mode = v.to_string(),
                InfoIpVtap::Flags(flags_val) => {
                    if flags_val.contains(IpVlanFlags::Private) {
                        private = true;
                    } else if flags_val.contains(IpVlanFlags::Vepa) {
                        vepa = true;
                    } else {
                        bridge = true;
                    }
                }
                _ => (),
            }
        }

        Self {
            mode,
            bridge,
            private,
            vepa,
        }
    }
}

impl LinkBaseConf {
    pub(crate) async fn apply_ipvlan(
        &self,
        handle: &rtnetlink::Handle,
    ) -> Result<LinkMessageBuilder<LinkIpVlan>, CliError> {
        let link_name = self
            .link
            .as_deref()
            .ok_or_else(|| CliError::from("IPVLAN requires link device"))?;

        let link_ifindex = self.get_ifindex_by_name(handle, link_name).await?;

        let mut builder = LinkMessageBuilder::<LinkIpVlan>::new(&self.name)
            .link(link_ifindex);

        let mut iter = self.iface_specific.iter();
        while let Some(key) = iter.next() {
            match key.as_str() {
                "mode" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "IPVLAN mode requires a value",
                        ));
                    };
                    let mode = v.parse::<IpVlanMode>().map_err(|e| {
                        CliError::from(format!(
                            "Unknown IPVLAN mode: {v}, supported: l2, l3, \
                             l3s: {e}"
                        ))
                    })?;
                    builder = builder.mode(mode);
                }
                "flag" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "IPVLAN flag requires a value",
                        ));
                    };
                    let flag = match v.as_str() {
                        "bridge" => IpVlanFlags::empty(),
                        "private" => IpVlanFlags::Private,
                        "vepa" => IpVlanFlags::Vepa,
                        _ => {
                            return Err(CliError::from(format!(
                                "Unknown IPVLAN flag: {v}, supported: bridge, \
                                 private, vepa"
                            )));
                        }
                    };
                    builder = builder.flag(flag);
                }
                _ => {
                    return Err(CliError::from(format!(
                        "Unknown IPVLAN argument: {key}"
                    )));
                }
            }
        }

        Ok(builder)
    }

    pub(crate) async fn apply_ipvtap(
        &self,
        handle: &rtnetlink::Handle,
    ) -> Result<LinkMessageBuilder<LinkIpVtap>, CliError> {
        let link_name = self
            .link
            .as_deref()
            .ok_or_else(|| CliError::from("IPVTAP requires link device"))?;

        let link_ifindex = self.get_ifindex_by_name(handle, link_name).await?;

        let mut builder = LinkMessageBuilder::<LinkIpVtap>::new(&self.name)
            .link(link_ifindex);

        let mut iter = self.iface_specific.iter();
        while let Some(key) = iter.next() {
            match key.as_str() {
                "mode" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "IPVTAP mode requires a value",
                        ));
                    };
                    let mode = v.parse::<IpVtapMode>().map_err(|e| {
                        CliError::from(format!(
                            "Unknown IPVTAP mode: {v}, supported: l2, l3, \
                             l3s: {e}"
                        ))
                    })?;
                    builder = builder.mode(mode);
                }
                "flag" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "IPVTAP flag requires a value",
                        ));
                    };
                    let flag = match v.as_str() {
                        "bridge" => IpVlanFlags::empty(),
                        "private" => IpVlanFlags::Private,
                        "vepa" => IpVlanFlags::Vepa,
                        _ => {
                            return Err(CliError::from(format!(
                                "Unknown IPVTAP flag: {v}, supported: bridge, \
                                 private, vepa"
                            )));
                        }
                    };
                    builder = builder.flag(flag);
                }
                _ => {
                    return Err(CliError::from(format!(
                        "Unknown IPVTAP argument: {key}"
                    )));
                }
            }
        }

        Ok(builder)
    }
}

impl std::fmt::Display for CliLinkInfoDataIpVlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Leading space matches iproute2 ipvlan_print_opt format " mode %s "
        // The trailing space from `{data} ` in CliLinkInfo::fmt handles
        // separation from subsequent fields.
        write!(f, " mode {} ", self.mode)?;
        if self.private {
            write!(f, "private")?;
        } else if self.vepa {
            write!(f, "vepa")?;
        } else if self.bridge {
            write!(f, "bridge")?;
        }
        Ok(())
    }
}

impl std::fmt::Display for CliLinkInfoDataIpVtap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Leading space matches iproute2 ipvlan_print_opt format " mode %s "
        write!(f, " mode {} ", self.mode)?;
        if self.private {
            write!(f, "private")?;
        } else if self.vepa {
            write!(f, "vepa")?;
        } else if self.bridge {
            write!(f, "bridge")?;
        }
        Ok(())
    }
}
