// SPDX-License-Identifier: MIT

use iproute_rs::CliError;

use super::{
    add::{handle_add, handle_delete},
    show::{CliL2tp, handle_show},
};

/// iproute2 `usage()` prints this message to stderr and exits with 255.
pub(crate) const USAGE: &str = concat!(
    "Usage: ip l2tp add tunnel\n",
    "          remote ADDR local ADDR\n",
    "          tunnel_id ID peer_tunnel_id ID\n",
    "          [ encap { ip | udp } ]\n",
    "          [ udp_sport PORT ] [ udp_dport PORT ]\n",
    "          [ udp_csum { on | off } ]\n",
    "          [ udp6_csum_tx { on | off } ]\n",
    "          [ udp6_csum_rx { on | off } ]\n",
    "Usage: ip l2tp add session [ name NAME ]\n",
    "          tunnel_id ID\n",
    "          session_id ID peer_session_id ID\n",
    "          [ cookie HEXSTR ] [ peer_cookie HEXSTR ]\n",
    "          [ seq { none | send | recv | both } ]\n",
    "          [ l2spec_type L2SPEC ]\n",
    "       ip l2tp del tunnel tunnel_id ID\n",
    "       ip l2tp del session tunnel_id ID session_id ID\n",
    "       ip l2tp show tunnel [ tunnel_id ID ]\n",
    "       ip l2tp show session [ tunnel_id ID ] [ session_id ID ]\n",
    "\n",
    "Where: NAME   := STRING\n",
    "       ADDR   := { IP_ADDRESS | any }\n",
    "       PORT   := { 0..65535 }\n",
    "       ID     := { 1..4294967295 }\n",
    "       HEXSTR := { 8 or 16 hex digits (4 / 8 bytes) }\n",
    "       L2SPEC := { none | default }",
);

pub(crate) struct L2tpCommand;

impl L2tpCommand {
    pub(crate) const CMD: &'static str = "l2tp";

    pub(crate) fn gen_command() -> clap::Command {
        clap::Command::new(Self::CMD)
            .about("L2TP configuration")
            .subcommand_required(false)
            .allow_external_subcommands(true)
            .disable_help_subcommand(true)
            .subcommand(
                clap::Command::new("add")
                    .about("add a tunnel or a session")
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
                    .about("delete a tunnel or a session")
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
                    .about("list tunnels or sessions")
                    .alias("s")
                    .alias("sh")
                    .alias("sho")
                    .alias("l")
                    .alias("ls")
                    .alias("lst")
                    .alias("li")
                    .alias("lis")
                    .alias("list")
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
    ) -> Result<Vec<CliL2tp>, CliError> {
        if let Some(matches) = matches.subcommand_matches("add") {
            handle_add(&collect_options(matches)).await?;
            Ok(vec![])
        } else if let Some(matches) = matches.subcommand_matches("delete") {
            handle_delete(&collect_options(matches)).await?;
            Ok(vec![])
        } else if let Some(matches) = matches.subcommand_matches("show") {
            handle_show(&collect_options(matches), matches.get_flag("ONELINE"))
                .await
        } else if matches.subcommand_matches("help").is_some() {
            // `ip l2tp help` prints the usage message.
            Err(usage_error())
        } else if let Some((name, _)) = matches.subcommand() {
            // iproute2 rejects unknown commands before the generic netlink
            // family is resolved and exits with 255.
            Err(CliError {
                code: 255,
                msg: format!(
                    "Command \"{name}\" is unknown, try \"ip l2tp help\"."
                ),
            })
        } else {
            // `ip l2tp` without arguments prints the usage message.
            Err(usage_error())
        }
    }
}

fn usage_error() -> CliError {
    CliError {
        code: 255,
        msg: USAGE.to_string(),
    }
}

fn collect_options(matches: &clap::ArgMatches) -> Vec<String> {
    matches
        .get_many::<String>("options")
        .unwrap_or_default()
        .map(|o| o.to_string())
        .collect()
}
