// SPDX-License-Identifier: MIT

use rtnetlink::packet_route::AddressFamily;

use super::{
    add::{handle_add, handle_delete},
    show::{CliFou, handle_show},
};
use crate::CliError;

/// iproute2 `usage()` prints this message to stderr and exits with 255.
pub(crate) const USAGE: &str = concat!(
    "Usage: ip fou add port PORT { ipproto PROTO  | gue }\n",
    "\t\t   [ local IFADDR ] [ peer IFADDR ]\n",
    "\t\t   [ peer_port PORT ] [ dev IFNAME ]\n",
    "       ip fou del port PORT [ local IFADDR ]\n",
    "\t\t   [ peer IFADDR ] [ peer_port PORT ]\n",
    "\t\t   [ dev IFNAME ]\n",
    "       ip fou show\n",
    "\n",
    "Where: PROTO { ipproto-name | 1..255 }\n",
    "       PORT { 1..65535 }\n",
    "       IFADDR { addr }",
);

pub(crate) struct FouCommand;

impl FouCommand {
    pub(crate) const CMD: &'static str = "fou";

    pub(crate) fn gen_command() -> clap::Command {
        clap::Command::new(Self::CMD)
            .about("FOU (foo over UDP) configuration")
            .subcommand_required(false)
            .allow_external_subcommands(true)
            .disable_help_subcommand(true)
            .subcommand(
                clap::Command::new("add")
                    .about("add a FOU listener")
                    .alias("a")
                    .alias("ad")
                    .arg(
                        clap::Arg::new("options")
                            .action(clap::ArgAction::Append)
                            .trailing_var_arg(true),
                    ),
            )
            .subcommand(
                clap::Command::new("delete")
                    .about("delete a FOU listener")
                    .alias("d")
                    .alias("de")
                    .alias("del")
                    .alias("dele")
                    .alias("delet")
                    .arg(
                        clap::Arg::new("options")
                            .action(clap::ArgAction::Append)
                            .trailing_var_arg(true),
                    ),
            )
            .subcommand(
                clap::Command::new("show")
                    .about("list FOU listeners")
                    .alias("s")
                    .alias("sh")
                    .alias("sho")
                    .arg(
                        clap::Arg::new("options")
                            .action(clap::ArgAction::Append)
                            .trailing_var_arg(true),
                    ),
            )
            .subcommand(
                clap::Command::new("help")
                    .about("print this help message")
                    .alias("h")
                    .alias("he")
                    .alias("hel")
                    .arg(
                        clap::Arg::new("options")
                            .action(clap::ArgAction::Append)
                            .trailing_var_arg(true),
                    ),
            )
    }

    pub(crate) async fn handle(
        matches: &clap::ArgMatches,
        preferred_family: Option<AddressFamily>,
    ) -> Result<Vec<CliFou>, CliError> {
        if let Some(matches) = matches.subcommand_matches("add") {
            let opts = collect_options(matches);
            handle_add(&opts, preferred_family).await?;
            Ok(vec![])
        } else if let Some(matches) = matches.subcommand_matches("delete") {
            let opts = collect_options(matches);
            handle_delete(&opts, preferred_family).await?;
            Ok(vec![])
        } else if let Some(matches) = matches.subcommand_matches("show") {
            if !collect_options(matches).is_empty() {
                return Err(CliError::from(
                    "\"ip fou show\" does not take any arguments.",
                ));
            }
            handle_show().await
        } else if matches.subcommand_matches("help").is_some() {
            // `ip fou help` prints the usage message.
            Err(CliError {
                code: 255,
                msg: USAGE.to_string(),
            })
        } else if let Some((name, _)) = matches.subcommand() {
            // iproute2 `do_ipfou()` rejects unknown commands after the
            // generic netlink family was resolved and exits with 255.
            Err(CliError {
                code: 255,
                msg: format!(
                    "Command \"{name}\" is unknown, try \"ip fou help\"."
                ),
            })
        } else {
            // `ip fou` without arguments prints the usage message.
            Err(CliError {
                code: 255,
                msg: USAGE.to_string(),
            })
        }
    }
}

fn collect_options(matches: &clap::ArgMatches) -> Vec<String> {
    matches
        .get_many::<String>("options")
        .unwrap_or_default()
        .map(|o| o.to_string())
        .collect()
}
