// SPDX-License-Identifier: MIT

use iproute_rs::CliError;
use rtnetlink::{LinkMessageBuilder, LinkXfrm, packet_route::link::InfoXfrm};
use serde::{Serialize, Serializer};

use crate::link::LinkBaseConf;

pub(crate) struct CliLinkInfoDataXfrm {
    if_id: u32,
}

impl Serialize for CliLinkInfoDataXfrm {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("CliLinkInfoDataXfrm", 1)?;
        s.serialize_field("if_id", &format_args!("{:#x}", self.if_id))?;
        s.end()
    }
}

impl From<&[InfoXfrm]> for CliLinkInfoDataXfrm {
    fn from(info: &[InfoXfrm]) -> Self {
        let mut if_id = 0;
        for i in info {
            if let InfoXfrm::IfId(v) = i {
                if_id = *v;
            }
        }
        Self { if_id }
    }
}

impl std::fmt::Display for CliLinkInfoDataXfrm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "if_id {:#x}", self.if_id)
    }
}

impl LinkBaseConf {
    pub(crate) async fn apply_xfrm(
        &self,
        handle: &rtnetlink::Handle,
    ) -> Result<LinkMessageBuilder<LinkXfrm>, CliError> {
        let mut iter = self.iface_specific.iter();
        let mut dev: Option<u32> = None;
        let mut if_id: Option<u32> = None;

        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "dev" => {
                    let Some(dev_name) = iter.next() else {
                        return Err(CliError::from(
                            "xfrm dev requires a value",
                        ));
                    };
                    dev =
                        Some(self.get_ifindex_by_name(handle, dev_name).await?);
                }
                "if_id" => {
                    let Some(val) = iter.next() else {
                        return Err(CliError::from(
                            "xfrm if_id requires a value",
                        ));
                    };
                    if_id = Some(parse_if_id(val)?);
                }
                other => {
                    return Err(CliError::from(format!(
                        "xfrm: unknown argument {other}"
                    )));
                }
            }
        }

        let Some(if_id) = if_id else {
            return Err(CliError::from("xfrm requires if_id argument"));
        };

        Ok(LinkXfrm::new(&self.name, dev.unwrap_or(0), if_id))
    }
}

fn parse_if_id(val: &str) -> Result<u32, CliError> {
    let v = val
        .strip_prefix("0x")
        .or_else(|| val.strip_prefix("0X"))
        .map_or_else(|| val.parse::<u32>(), |hex| u32::from_str_radix(hex, 16));
    v.map_err(|_| CliError::from(format!("invalid if_id value: {val}")))
}

pub(crate) struct IfaceXfrm;

impl IfaceXfrm {
    #[rustfmt::skip]
    pub(crate) fn print_help() -> &'static str {
        r"Usage: ... xfrm dev [ PHYS_DEV ] [ if_id IF-ID ]
                [ external ]

Where: IF-ID := { 0x1..0xffffffff }
"
    }
}
