// SPDX-License-Identifier: MIT

use iproute_rs::CliError;
use rtnetlink::{
    LinkMacVlan, LinkMacVtap, LinkMessageBuilder,
    packet_route::link::{
        InfoMacVlan, InfoMacVtap, MacVlanFlags, MacVlanMode, MacVtapMode,
    },
};
use serde::Serialize;

use crate::link::LinkBaseConf;

fn is_false(v: &bool) -> bool {
    !*v
}

#[derive(Serialize, Default)]
pub(crate) struct CliLinkInfoDataMacVlan {
    mode: String,
    #[serde(skip_serializing_if = "is_false")]
    nopromisc: bool,
    #[serde(skip_serializing_if = "is_false")]
    nodst: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    bcqueuelen: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    usedbcqueuelen: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bclim: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    macaddr_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    macaddr_data: Option<Vec<String>>,
}

impl From<&[InfoMacVlan]> for CliLinkInfoDataMacVlan {
    fn from(info: &[InfoMacVlan]) -> Self {
        let mut mode = String::new();
        let mut nopromisc = false;
        let mut nodst = false;
        let mut bcqueuelen = None;
        let mut usedbcqueuelen = None;
        let mut bclim = None;
        let mut macaddr_count = None;
        let mut macaddr_data = None;

        for nla in info {
            match nla {
                InfoMacVlan::Mode(v) => mode = v.to_string(),
                InfoMacVlan::Flags(flags_val) => {
                    if flags_val.contains(MacVlanFlags::NoPromisc) {
                        nopromisc = true;
                    }
                    if flags_val.contains(MacVlanFlags::NoDst) {
                        nodst = true;
                    }
                }
                InfoMacVlan::BcQueueLen(v) => bcqueuelen = Some(*v),
                InfoMacVlan::BcQueueLenUsed(v) => usedbcqueuelen = Some(*v),
                InfoMacVlan::BcCutoff(v) => bclim = Some(*v),
                InfoMacVlan::MacAddrCount(v) => macaddr_count = Some(*v),
                InfoMacVlan::MacAddrData(addrs) => {
                    let mut macs = Vec::new();
                    for addr in addrs {
                        if let InfoMacVlan::MacAddr(bytes) = addr {
                            macs.push(format!(
                                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                bytes[0],
                                bytes[1],
                                bytes[2],
                                bytes[3],
                                bytes[4],
                                bytes[5]
                            ));
                        }
                    }
                    if !macs.is_empty() {
                        macaddr_data = Some(macs);
                    }
                }
                _ => (),
            }
        }

        // Only include macaddr fields in source mode, matching iproute2
        // behavior
        if mode != "source" {
            macaddr_count = None;
            macaddr_data = None;
        }

        Self {
            mode,
            nopromisc,
            nodst,
            bcqueuelen,
            usedbcqueuelen,
            bclim,
            macaddr_count,
            macaddr_data,
        }
    }
}

#[derive(Serialize, Default)]
pub(crate) struct CliLinkInfoDataMacVtap {
    mode: String,
    #[serde(skip_serializing_if = "is_false")]
    nopromisc: bool,
    #[serde(skip_serializing_if = "is_false")]
    nodst: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    bcqueuelen: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    usedbcqueuelen: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bclim: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    macaddr_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    macaddr_data: Option<Vec<String>>,
}

impl From<&[InfoMacVtap]> for CliLinkInfoDataMacVtap {
    fn from(info: &[InfoMacVtap]) -> Self {
        let mut mode = String::new();
        let mut nopromisc = false;
        let mut nodst = false;
        let mut bcqueuelen = None;
        let mut usedbcqueuelen = None;
        let mut bclim = None;
        let mut macaddr_count = None;
        let mut macaddr_data = None;

        for nla in info {
            match nla {
                InfoMacVtap::Mode(v) => mode = v.to_string(),
                InfoMacVtap::Flags(flags_val) => {
                    if flags_val.contains(MacVlanFlags::NoPromisc) {
                        nopromisc = true;
                    }
                    if flags_val.contains(MacVlanFlags::NoDst) {
                        nodst = true;
                    }
                }
                InfoMacVtap::BcQueueLen(v) => bcqueuelen = Some(*v),
                InfoMacVtap::BcQueueLenUsed(v) => usedbcqueuelen = Some(*v),
                InfoMacVtap::BcCutoff(v) => bclim = Some(*v),
                InfoMacVtap::MacAddrCount(v) => macaddr_count = Some(*v),
                InfoMacVtap::MacAddrData(addrs) => {
                    let mut macs = Vec::new();
                    for addr in addrs {
                        if let InfoMacVtap::MacAddr(bytes) = addr {
                            macs.push(format!(
                                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                bytes[0],
                                bytes[1],
                                bytes[2],
                                bytes[3],
                                bytes[4],
                                bytes[5]
                            ));
                        }
                    }
                    if !macs.is_empty() {
                        macaddr_data = Some(macs);
                    }
                }
                _ => (),
            }
        }

        // Only include macaddr fields in source mode, matching iproute2
        // behavior
        if mode != "source" {
            macaddr_count = None;
            macaddr_data = None;
        }

        Self {
            mode,
            nopromisc,
            nodst,
            bcqueuelen,
            usedbcqueuelen,
            bclim,
            macaddr_count,
            macaddr_data,
        }
    }
}

impl LinkBaseConf {
    pub(crate) async fn apply_macvlan(
        &self,
        handle: &rtnetlink::Handle,
    ) -> Result<LinkMessageBuilder<LinkMacVlan>, CliError> {
        let link_name = self
            .link
            .as_deref()
            .ok_or_else(|| CliError::from("MACVLAN requires link device"))?;

        let link_ifindex = self.get_ifindex_by_name(handle, link_name).await?;

        let mut builder = LinkMessageBuilder::<LinkMacVlan>::new(&self.name)
            .link(link_ifindex);

        let mut iter = self.iface_specific.iter();
        while let Some(key) = iter.next() {
            match key.as_str() {
                "mode" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "MACVLAN mode requires a value",
                        ));
                    };
                    let mode = v.parse::<MacVlanMode>().map_err(|e| {
                        CliError::from(format!(
                            "Unknown MACVLAN mode: {v}, supported: private, \
                             vepa, bridge, passthru, source: {e}"
                        ))
                    })?;
                    builder = builder.mode(mode);
                }
                "flag" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "MACVLAN flag requires a value",
                        ));
                    };
                    let flag = match v.as_str() {
                        "nopromisc" => MacVlanFlags::NoPromisc,
                        "nodst" => MacVlanFlags::NoDst,
                        "null" => MacVlanFlags::empty(),
                        _ => {
                            return Err(CliError::from(format!(
                                "Unknown MACVLAN flag: {v}, supported: \
                                 nopromisc, nodst, null"
                            )));
                        }
                    };
                    builder =
                        builder.append_info_data(InfoMacVlan::Flags(flag));
                }
                "nopromisc" => {
                    builder = builder.append_info_data(InfoMacVlan::Flags(
                        MacVlanFlags::NoPromisc,
                    ));
                }
                "nodst" => {
                    builder = builder.append_info_data(InfoMacVlan::Flags(
                        MacVlanFlags::NoDst,
                    ));
                }
                "bcqueuelen" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "MACVLAN bcqueuelen requires a value",
                        ));
                    };
                    let val: u32 = v.parse().map_err(|_| {
                        CliError::from(format!(
                            "Invalid MACVLAN bcqueuelen: {v}"
                        ))
                    })?;
                    builder =
                        builder.append_info_data(InfoMacVlan::BcQueueLen(val));
                }
                "bclim" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "MACVLAN bclim requires a value",
                        ));
                    };
                    let val: i32 = v.parse().map_err(|_| {
                        CliError::from(format!("Invalid MACVLAN bclim: {v}"))
                    })?;
                    builder =
                        builder.append_info_data(InfoMacVlan::BcCutoff(val));
                }
                _ => {
                    return Err(CliError::from(format!(
                        "Unknown MACVLAN argument: {key}"
                    )));
                }
            }
        }

        Ok(builder)
    }

    pub(crate) async fn apply_macvtap(
        &self,
        handle: &rtnetlink::Handle,
    ) -> Result<LinkMessageBuilder<LinkMacVtap>, CliError> {
        let link_name = self
            .link
            .as_deref()
            .ok_or_else(|| CliError::from("MACVTAP requires link device"))?;

        let link_ifindex = self.get_ifindex_by_name(handle, link_name).await?;

        let mut builder = LinkMessageBuilder::<LinkMacVtap>::new(&self.name)
            .link(link_ifindex);

        let mut iter = self.iface_specific.iter();
        while let Some(key) = iter.next() {
            match key.as_str() {
                "mode" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "MACVTAP mode requires a value",
                        ));
                    };
                    let mode = v.parse::<MacVtapMode>().map_err(|e| {
                        CliError::from(format!(
                            "Unknown MACVTAP mode: {v}, supported: private, \
                             vepa, bridge, passthru, source: {e}"
                        ))
                    })?;
                    builder = builder.mode(mode);
                }
                "flag" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "MACVTAP flag requires a value",
                        ));
                    };
                    let flag = match v.as_str() {
                        "nopromisc" => MacVlanFlags::NoPromisc,
                        "nodst" => MacVlanFlags::NoDst,
                        "null" => MacVlanFlags::empty(),
                        _ => {
                            return Err(CliError::from(format!(
                                "Unknown MACVTAP flag: {v}, supported: \
                                 nopromisc, nodst, null"
                            )));
                        }
                    };
                    builder =
                        builder.append_info_data(InfoMacVtap::Flags(flag));
                }
                "nopromisc" => {
                    builder = builder.append_info_data(InfoMacVtap::Flags(
                        MacVlanFlags::NoPromisc,
                    ));
                }
                "nodst" => {
                    builder = builder.append_info_data(InfoMacVtap::Flags(
                        MacVlanFlags::NoDst,
                    ));
                }
                "bcqueuelen" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "MACVTAP bcqueuelen requires a value",
                        ));
                    };
                    let val: u32 = v.parse().map_err(|_| {
                        CliError::from(format!(
                            "Invalid MACVTAP bcqueuelen: {v}"
                        ))
                    })?;
                    builder =
                        builder.append_info_data(InfoMacVtap::BcQueueLen(val));
                }
                "bclim" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "MACVTAP bclim requires a value",
                        ));
                    };
                    let val: i32 = v.parse().map_err(|_| {
                        CliError::from(format!("Invalid MACVTAP bclim: {v}"))
                    })?;
                    builder =
                        builder.append_info_data(InfoMacVtap::BcCutoff(val));
                }
                _ => {
                    return Err(CliError::from(format!(
                        "Unknown MACVTAP argument: {key}"
                    )));
                }
            }
        }

        Ok(builder)
    }
}

impl std::fmt::Display for CliLinkInfoDataMacVlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "mode {}", self.mode)?;
        if self.nopromisc {
            write!(f, " nopromisc")?;
        }
        if self.nodst {
            write!(f, " nodst")?;
        }
        if let Some(v) = self.bcqueuelen {
            write!(f, " bcqueuelen {v}")?;
        }
        if let Some(v) = self.usedbcqueuelen {
            write!(f, " usedbcqueuelen {v}")?;
        }
        if let Some(v) = self.bclim {
            write!(f, " bclim {v}")?;
        }
        if self.mode == "source" {
            if let Some(v) = self.macaddr_count {
                write!(f, " remotes ({v})")?;
            }
            if let Some(addrs) = &self.macaddr_data {
                for addr in addrs {
                    write!(f, " {addr}")?;
                }
            }
        }
        Ok(())
    }
}

impl std::fmt::Display for CliLinkInfoDataMacVtap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "mode {}", self.mode)?;
        if self.nopromisc {
            write!(f, " nopromisc")?;
        }
        if self.nodst {
            write!(f, " nodst")?;
        }
        if let Some(v) = self.bcqueuelen {
            write!(f, " bcqueuelen {v}")?;
        }
        if let Some(v) = self.usedbcqueuelen {
            write!(f, " usedbcqueuelen {v}")?;
        }
        if let Some(v) = self.bclim {
            write!(f, " bclim {v}")?;
        }
        if self.mode == "source" {
            if let Some(v) = self.macaddr_count {
                write!(f, " remotes ({v})")?;
            }
            if let Some(addrs) = &self.macaddr_data {
                for addr in addrs {
                    write!(f, " {addr}")?;
                }
            }
        }
        Ok(())
    }
}

pub(crate) struct IfaceMacVlan;

impl IfaceMacVlan {
    #[rustfmt::skip]
    pub(crate) fn print_help() -> &'static str {
        r#"Usage: ... macvlan mode MODE [flag MODE_FLAG] MODE_OPTS [bcqueuelen BC_QUEUE_LEN] [bclim BCLIM]

MODE: private | vepa | bridge | passthru | source
MODE_FLAG: null | nopromisc | nodst
MODE_OPTS: for mode "source":
        macaddr { { add | del } <macaddr> | set [ <macaddr> [ <macaddr>  ... ] ] | flush }
BC_QUEUE_LEN: Length of the rx queue for broadcast/multicast: [0-4294967295]
BCLIM: Threshold for broadcast queueing: 32-bit integer
"#
    }
}

pub(crate) struct IfaceMacVtap;

impl IfaceMacVtap {
    #[rustfmt::skip]
    pub(crate) fn print_help() -> &'static str {
        r#"Usage: ... macvtap mode MODE [flag MODE_FLAG] MODE_OPTS [bcqueuelen BC_QUEUE_LEN] [bclim BCLIM]

MODE: private | vepa | bridge | passthru | source
MODE_FLAG: null | nopromisc | nodst
MODE_OPTS: for mode "source":
        macaddr { { add | del } <macaddr> | set [ <macaddr> [ <macaddr>  ... ] ] | flush }
BC_QUEUE_LEN: Length of the rx queue for broadcast/multicast: [0-4294967295]
BCLIM: Threshold for broadcast queueing: 32-bit integer
"#
    }
}
