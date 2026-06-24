// SPDX-License-Identifier: MIT

use iproute_rs::CliError;
use rtnetlink::{
    LinkGtp, LinkMessageBuilder,
    packet_route::link::{GtpRole, InfoGtp, InfoKind, LinkInfo},
};
use serde::Serialize;

use super::parse::{extract_link_info, parse_u8, parse_u32};
use crate::link::LinkBaseConf;

#[derive(Serialize)]
pub(crate) struct CliLinkInfoDataGtp {
    role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    hsize: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    restart_count: Option<u8>,
}

impl From<&[InfoGtp]> for CliLinkInfoDataGtp {
    fn from(info: &[InfoGtp]) -> Self {
        let mut role = GtpRole::default();
        let mut hsize = None;
        let mut restart_count = None;
        for nla in info {
            match nla {
                InfoGtp::Role(r) => {
                    role = *r;
                }
                InfoGtp::PdpHashsize(v) => {
                    hsize = Some(*v);
                }
                InfoGtp::RestartCount(v) => {
                    restart_count = Some(*v);
                }
                _ => {}
            }
        }
        Self {
            role: role.to_string(),
            hsize,
            restart_count,
        }
    }
}

impl std::fmt::Display for CliLinkInfoDataGtp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "role {}", self.role)?;
        if let Some(hsize) = self.hsize {
            write!(f, " hsize {hsize}")?;
        }
        if let Some(restart_count) = self.restart_count {
            write!(f, " restart_count {restart_count}")?;
        }
        Ok(())
    }
}

fn apply_gtp_args<'a>(
    mut builder: LinkMessageBuilder<LinkGtp>,
    iter: &mut impl Iterator<Item = &'a str>,
) -> Result<LinkMessageBuilder<LinkGtp>, CliError> {
    let mut role_set = false;
    while let Some(key) = iter.next() {
        let Some(v) = iter.next() else {
            return Err(CliError::from(format!("\"{key}\" requires a value")));
        };
        match key {
            "role" => match v {
                "sgsn" => {
                    builder = builder.role(GtpRole::Sgsn);
                    role_set = true;
                }
                "ggsn" => {
                    builder = builder.role(GtpRole::Ggsn);
                    role_set = true;
                }
                _ => {
                    return Err(CliError::from(format!(
                        "gtp: invalid role \"{v}\", must be \"sgsn\" or \
                         \"ggsn\""
                    )));
                }
            },
            "hsize" => {
                builder = builder.pdp_hashsize(parse_u32(v, "hsize")?);
            }
            "restart_count" => {
                builder = builder.restart_count(parse_u8(v, "restart_count")?);
            }
            _ => {
                return Err(CliError::from(format!(
                    "gtp: unknown option \"{key}\"",
                )));
            }
        }
    }
    if !role_set {
        return Err(CliError::from("gtp: missing required \"role\" argument"));
    }
    Ok(builder)
}

impl LinkBaseConf {
    pub(crate) fn apply_gtp(
        &self,
        _handle: &rtnetlink::Handle,
    ) -> Result<LinkMessageBuilder<LinkGtp>, CliError> {
        let mut remaining: Vec<&str> = Vec::new();
        let mut iter = self.iface_specific.iter();
        while let Some(key) = iter.next() {
            remaining.push(key);
            if let Some(v) = iter.next() {
                remaining.push(v);
            }
        }

        let builder = LinkMessageBuilder::<LinkGtp>::new(&self.name);
        let mut remaining_iter = remaining.into_iter();
        apply_gtp_args(builder, &mut remaining_iter)
    }
}

pub(crate) struct IfaceGtp;

impl IfaceGtp {
    pub(crate) fn build_entries(
        args: &[String],
    ) -> Result<Vec<LinkInfo>, CliError> {
        let builder =
            LinkMessageBuilder::<LinkGtp>::new_with_info_kind(InfoKind::Gtp);
        let mut iter = args.iter().map(|s| s.as_str());
        let builder = apply_gtp_args(builder, &mut iter)?;
        Ok(extract_link_info(builder.build()))
    }

    #[rustfmt::skip]
    pub(crate) fn print_help() -> &'static str {
        "Usage: ... gtp role ROLE\n\t\t[ hsize HSIZE ]\n\t\t[ restart_count RESTART_COUNT ]\n\nWhere:\tROLE\t\t:= { sgsn | ggsn }\n\tHSIZE\t\t:= 1-131071\n\tRESTART_COUNT\t:= 0-255\n"
    }
}

#[cfg(test)]
mod tests {
    use rtnetlink::packet_route::link::{GtpRole, InfoData, InfoGtp, LinkInfo};

    use super::*;

    #[test]
    fn test_build_entries_with_role_only() {
        let infos =
            IfaceGtp::build_entries(&["role".into(), "sgsn".into()]).unwrap();
        assert!(infos.contains(&LinkInfo::Kind(InfoKind::Gtp)));
        assert!(infos.contains(&LinkInfo::Data(InfoData::Gtp(vec![
            InfoGtp::Role(GtpRole::Sgsn),
        ]))));
    }

    #[test]
    fn test_build_entries_with_all_params() {
        let infos = IfaceGtp::build_entries(&[
            "role".into(),
            "ggsn".into(),
            "hsize".into(),
            "2048".into(),
            "restart_count".into(),
            "10".into(),
        ])
        .unwrap();
        assert!(infos.contains(&LinkInfo::Kind(InfoKind::Gtp)));
        assert!(infos.contains(&LinkInfo::Data(InfoData::Gtp(vec![
            InfoGtp::Role(GtpRole::Ggsn),
            InfoGtp::PdpHashsize(2048),
            InfoGtp::RestartCount(10),
        ]))));
    }

    #[test]
    fn test_build_entries_missing_role() {
        let err = IfaceGtp::build_entries(&[]).unwrap_err();
        assert!(err.msg.contains("role"), "{}", err.msg);
    }

    #[test]
    fn test_build_entries_invalid_role() {
        let err = IfaceGtp::build_entries(&["role".into(), "invalid".into()])
            .unwrap_err();
        assert!(err.msg.contains("invalid role"), "{}", err.msg);
    }

    #[test]
    fn test_build_entries_missing_value() {
        let err = IfaceGtp::build_entries(&["role".into()]).unwrap_err();
        assert!(err.msg.contains("requires a value"), "{}", err.msg);
    }

    #[test]
    fn test_gtp_info_from_sgsn() {
        let infos = vec![InfoGtp::Role(GtpRole::Sgsn)];
        let data = CliLinkInfoDataGtp::from(infos.as_slice());
        assert_eq!(data.role, "sgsn");
        assert!(data.hsize.is_none());
        assert!(data.restart_count.is_none());
    }

    #[test]
    fn test_gtp_info_from_ggsn_full() {
        let infos = vec![
            InfoGtp::Role(GtpRole::Ggsn),
            InfoGtp::PdpHashsize(2048),
            InfoGtp::RestartCount(5),
        ];
        let data = CliLinkInfoDataGtp::from(infos.as_slice());
        assert_eq!(data.role, "ggsn");
        assert_eq!(data.hsize, Some(2048));
        assert_eq!(data.restart_count, Some(5));
    }

    #[test]
    fn test_gtp_display_sgsn() {
        let infos = vec![InfoGtp::Role(GtpRole::Sgsn)];
        let data = CliLinkInfoDataGtp::from(infos.as_slice());
        let display = format!("{data}");
        assert_eq!(display, "role sgsn");
    }

    #[test]
    fn test_gtp_display_full() {
        let infos = vec![
            InfoGtp::Role(GtpRole::Ggsn),
            InfoGtp::PdpHashsize(1024),
            InfoGtp::RestartCount(0),
        ];
        let data = CliLinkInfoDataGtp::from(infos.as_slice());
        let display = format!("{data}");
        assert_eq!(display, "role ggsn hsize 1024 restart_count 0");
    }
}
