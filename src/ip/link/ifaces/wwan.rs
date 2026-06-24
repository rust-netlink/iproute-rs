// SPDX-License-Identifier: MIT

use iproute_rs::CliError;
use rtnetlink::{
    LinkWwan, LinkMessageBuilder,
    packet_route::link::{InfoKind, InfoWwan, LinkInfo},
};
use serde::Serialize;

use super::parse::{extract_link_info, parse_u32};
use crate::link::LinkBaseConf;

#[derive(Serialize)]
pub(crate) struct CliLinkInfoDataWwan {
    linkid: u32,
}

impl From<&[InfoWwan]> for CliLinkInfoDataWwan {
    fn from(info: &[InfoWwan]) -> Self {
        let mut linkid = 0;
        for nla in info {
            match nla {
                InfoWwan::LinkId(v) => {
                    linkid = *v;
                }
                _ => {}
            }
        }
        Self { linkid }
    }
}

impl std::fmt::Display for CliLinkInfoDataWwan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "linkid {}", self.linkid)
    }
}

fn apply_wwan_args<'a>(
    mut builder: LinkMessageBuilder<LinkWwan>,
    iter: &mut impl Iterator<Item = &'a str>,
) -> Result<LinkMessageBuilder<LinkWwan>, CliError> {
    let mut linkid_set = false;
    while let Some(key) = iter.next() {
        let Some(v) = iter.next() else {
            return Err(CliError::from(format!("\"{key}\" requires a value")));
        };
        match key {
            "linkid" => {
                builder = builder.linkid(parse_u32(v, "linkid")?);
                linkid_set = true;
            }
            _ => {
                return Err(CliError::from(format!(
                    "wwan: unknown option \"{key}\"",
                )));
            }
        }
    }
    if !linkid_set {
        return Err(CliError::from(
            "wwan: missing required \"linkid\" argument",
        ));
    }
    Ok(builder)
}

impl LinkBaseConf {
    pub(crate) async fn apply_wwan(
        &self,
        _handle: &rtnetlink::Handle,
    ) -> Result<LinkMessageBuilder<LinkWwan>, CliError> {
        let mut remaining: Vec<&str> = Vec::new();
        let mut iter = self.iface_specific.iter();
        while let Some(key) = iter.next() {
            remaining.push(key);
            if let Some(v) = iter.next() {
                remaining.push(v);
            }
        }

        let builder = LinkMessageBuilder::<LinkWwan>::new(&self.name);
        let mut remaining_iter = remaining.into_iter();
        apply_wwan_args(builder, &mut remaining_iter)
    }
}

pub(crate) struct IfaceWwan;

impl IfaceWwan {
    pub(crate) fn build_entries(
        args: &[String],
    ) -> Result<Vec<LinkInfo>, CliError> {
        let builder =
            LinkMessageBuilder::<LinkWwan>::new_with_info_kind(InfoKind::Wwan);
        let mut iter = args.iter().map(|s| s.as_str());
        let builder = apply_wwan_args(builder, &mut iter)?;
        Ok(extract_link_info(builder.build()))
    }

    #[rustfmt::skip]
    pub(crate) fn print_help() -> &'static str {
        "Usage: ... wwan linkid LINKID\n\nWhere: LINKID := 0-4294967295\n"
    }
}

#[cfg(test)]
mod tests {
    use rtnetlink::packet_route::link::{InfoData, InfoWwan, LinkInfo};

    use super::*;

    #[test]
    fn test_build_entries_with_linkid() {
        let infos =
            IfaceWwan::build_entries(&["linkid".into(), "42".into()]).unwrap();
        assert!(infos.contains(&LinkInfo::Kind(InfoKind::Wwan)));
        assert!(infos.contains(&LinkInfo::Data(InfoData::Wwan(vec![
            InfoWwan::LinkId(42),
        ]))));
    }

    #[test]
    fn test_build_entries_missing_linkid() {
        let err = IfaceWwan::build_entries(&[]).unwrap_err();
        assert!(err.msg.contains("linkid"), "{}", err.msg);
    }

    #[test]
    fn test_build_entries_missing_value() {
        let err = IfaceWwan::build_entries(&["linkid".into()]).unwrap_err();
        assert!(err.msg.contains("requires a value"), "{}", err.msg);
    }

    #[test]
    fn test_wwan_info_from_linkid() {
        let infos = vec![InfoWwan::LinkId(42)];
        let data = CliLinkInfoDataWwan::from(infos.as_slice());
        assert_eq!(data.linkid, 42);
    }

    #[test]
    fn test_wwan_display() {
        let infos = vec![InfoWwan::LinkId(100)];
        let data = CliLinkInfoDataWwan::from(infos.as_slice());
        let display = format!("{data}");
        assert_eq!(display, "linkid 100");
    }
}
