// SPDX-License-Identifier: MIT

use iproute_rs::CliError;
use rtnetlink::packet_route::link::{
    InfoPortData, InfoPortKind, InfoTeamPort, LinkInfo,
};
use serde::Serialize;

#[derive(Serialize)]
pub(crate) struct CliLinkInfoDataTeamPort;

impl From<&[InfoTeamPort]> for CliLinkInfoDataTeamPort {
    fn from(_info: &[InfoTeamPort]) -> Self {
        Self
    }
}

impl std::fmt::Display for CliLinkInfoDataTeamPort {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Ok(())
    }
}

pub(crate) struct IfaceTeam;

impl IfaceTeam {
    #[rustfmt::skip]
    pub(crate) fn print_help() -> &'static str {
        r"Usage: ... team
"
    }
}

pub(crate) struct IfaceTeamPort;

impl IfaceTeamPort {
    pub(crate) fn build_entries(
        args: &[String],
    ) -> Result<Vec<LinkInfo>, CliError> {
        if !args.is_empty() {
            return Err(CliError::from(
                "team_slave does not accept any arguments",
            ));
        }
        Ok(vec![
            LinkInfo::PortKind(InfoPortKind::Team),
            LinkInfo::PortData(InfoPortData::TeamPort(Vec::new())),
        ])
    }

    pub(crate) fn print_help() -> &'static str {
        "Usage: ... team_slave\n"
    }
}
