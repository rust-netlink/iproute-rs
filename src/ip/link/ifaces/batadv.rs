// SPDX-License-Identifier: MIT

use iproute_rs::CliError;
use rtnetlink::{
    LinkBatAdv, LinkMessageBuilder,
    packet_route::link::{InfoKind, LinkInfo},
};

use super::parse::extract_link_info;
use crate::link::LinkBaseConf;

fn apply_batadv_args(
    mut builder: LinkMessageBuilder<LinkBatAdv>,
    iter: &mut impl Iterator<Item = impl AsRef<str>>,
) -> Result<LinkMessageBuilder<LinkBatAdv>, CliError> {
    while let Some(key) = iter.next() {
        match key.as_ref() {
            "ra" => {
                let Some(v) = iter.next() else {
                    return Err(CliError::from("\"ra\" requires a value"));
                };
                builder = builder.algo_name(v.as_ref().to_string());
            }
            _ => {
                return Err(CliError::from(format!(
                    "batadv: unknown option \"{}\"",
                    key.as_ref(),
                )));
            }
        }
    }
    Ok(builder)
}

impl LinkBaseConf {
    pub(crate) fn apply_batadv(
        &self,
    ) -> Result<LinkMessageBuilder<LinkBatAdv>, CliError> {
        let builder = LinkMessageBuilder::<LinkBatAdv>::new(&self.name);
        let mut iter = self.iface_specific.iter();
        apply_batadv_args(builder, &mut iter)
    }
}

pub(crate) struct IfaceBatAdv;

impl IfaceBatAdv {
    pub(crate) fn build_entries(
        args: &[String],
    ) -> Result<Vec<LinkInfo>, CliError> {
        let builder = LinkMessageBuilder::<LinkBatAdv>::new_with_info_kind(
            InfoKind::BatAdv,
        );
        let mut iter = args.iter();
        let builder = apply_batadv_args(builder, &mut iter)?;
        Ok(extract_link_info(builder.build()))
    }

    pub(crate) fn print_help() -> &'static str {
        "Usage: ... batadv [ ra ROUTING_ALG ]\n\nWhere: ROUTING_ALG := { \
         BATMAN_IV | BATMAN_V }\n"
    }
}

#[cfg(test)]
mod tests {
    use rtnetlink::packet_route::link::{InfoBatAdv, InfoData};

    use super::*;

    #[test]
    fn test_build_entries_with_ra() {
        let infos =
            IfaceBatAdv::build_entries(&["ra".into(), "BATMAN_IV".into()])
                .unwrap();
        assert!(infos.contains(&LinkInfo::Kind(InfoKind::BatAdv)));
        assert!(infos.contains(&LinkInfo::Data(InfoData::BatAdv(vec![
            InfoBatAdv::AlgoName("BATMAN_IV".to_string()),
        ]))));
    }

    #[test]
    fn test_build_entries_empty() {
        let infos = IfaceBatAdv::build_entries(&[]).unwrap();
        assert!(infos.contains(&LinkInfo::Kind(InfoKind::BatAdv)));
    }

    #[test]
    fn test_build_entries_missing_value() {
        let err = IfaceBatAdv::build_entries(&["ra".into()]).unwrap_err();
        assert!(err.msg.contains("requires a value"), "{}", err.msg);
    }

    #[test]
    fn test_build_entries_unknown_option() {
        let err = IfaceBatAdv::build_entries(&["foo".into(), "bar".into()])
            .unwrap_err();
        assert!(err.msg.contains("unknown option"), "{}", err.msg);
    }
}
