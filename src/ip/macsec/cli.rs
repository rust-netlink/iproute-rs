// SPDX-License-Identifier: MIT

use iproute_rs::CliError;

use super::{
    add::{handle_modify, handle_offload},
    show::{CliMacsec, handle_show},
};

pub(crate) const USAGE: &str = concat!(
    "Usage: ip macsec add DEV tx sa { 0..3 } [ OPTS ] key ID KEY\n",
    "       ip macsec set DEV tx sa { 0..3 } [ OPTS ]\n",
    "       ip macsec del DEV tx sa { 0..3 }\n",
    "       ip macsec add DEV rx SCI [ on | off ]\n",
    "       ip macsec set DEV rx SCI [ on | off ]\n",
    "       ip macsec del DEV rx SCI\n",
    "       ip macsec add DEV rx SCI sa { 0..3 } [ OPTS ] key ID KEY\n",
    "       ip macsec set DEV rx SCI sa { 0..3 } [ OPTS ]\n",
    "       ip macsec del DEV rx SCI sa { 0..3 }\n",
    "       ip macsec show\n",
    "       ip macsec show DEV\n",
    "       ip macsec offload DEV [ off | phy | mac ]\n",
    "where  OPTS := [ pn <u32> | xpn <u64> ] [ salt SALT ] [ ssci <u32> ] [ \
     on | off ]\n",
    "       ID   := 128-bit hex string\n",
    "       KEY  := 128-bit or 256-bit hex string\n",
    "       SCI  := { sci <u64> | port { 1..2^16-1 } address <lladdr> }\n",
    "       SALT := 96-bit hex string",
);

pub(crate) struct MacsecCommand;

impl MacsecCommand {
    pub(crate) const CMD: &'static str = "macsec";

    pub(crate) fn gen_command() -> clap::Command {
        clap::Command::new(Self::CMD)
            .about("MACsec configuration")
            .subcommand_required(false)
            .allow_external_subcommands(true)
            .disable_help_subcommand(true)
            .subcommand(
                clap::Command::new("add")
                    .about("add a MACsec security association")
                    .alias("a")
                    .alias("ad")
                    .arg(
                        clap::Arg::new("options")
                            .action(clap::ArgAction::Append)
                            .trailing_var_arg(true),
                    ),
            )
            .subcommand(
                clap::Command::new("set")
                    .about("update a MACsec security association")
                    .alias("se")
                    .arg(
                        clap::Arg::new("options")
                            .action(clap::ArgAction::Append)
                            .trailing_var_arg(true),
                    ),
            )
            .subcommand(
                clap::Command::new("delete")
                    .about("delete a MACsec security association")
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
                    .about("list MACsec security associations")
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
                clap::Command::new("offload")
                    .about("set the MACsec offload mode")
                    .alias("o")
                    .alias("of")
                    .alias("off")
                    .alias("offl")
                    .alias("offlo")
                    .alias("offloa")
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
    ) -> Result<Vec<CliMacsec>, CliError> {
        if let Some(matches) = matches.subcommand_matches("add") {
            handle_modify(MacsecModify::Add, &collect_options(matches)).await?;
            Ok(vec![])
        } else if let Some(matches) = matches.subcommand_matches("set") {
            handle_modify(MacsecModify::Set, &collect_options(matches)).await?;
            Ok(vec![])
        } else if let Some(matches) = matches.subcommand_matches("delete") {
            handle_modify(MacsecModify::Delete, &collect_options(matches))
                .await?;
            Ok(vec![])
        } else if let Some(matches) = matches.subcommand_matches("show") {
            handle_show(
                &collect_options(matches),
                matches.get_count("STATISTICS") > 0,
                matches.get_flag("ONELINE"),
            )
            .await
        } else if let Some(matches) = matches.subcommand_matches("offload") {
            handle_offload(&collect_options(matches)).await?;
            Ok(vec![])
        } else if matches.subcommand_matches("help").is_some() {
            Err(usage_error())
        } else if let Some((name, _)) = matches.subcommand() {
            Err(CliError {
                code: 255,
                msg: format!(
                    "Command \"{name}\" is unknown, try \"ip macsec help\"."
                ),
            })
        } else {
            Err(usage_error())
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum MacsecModify {
    Add,
    Set,
    Delete,
}

pub(crate) fn usage_error() -> CliError {
    CliError {
        code: 255,
        msg: USAGE.to_string(),
    }
}

pub(crate) fn invarg(value: &str, msg: &str) -> CliError {
    CliError {
        code: 255,
        msg: format!("Error: argument \"{value}\" is wrong: {msg}"),
    }
}

pub(crate) fn missing_argument() -> CliError {
    CliError {
        code: 255,
        msg: "Command line is not complete. Try option \"help\"".to_string(),
    }
}

fn collect_options(matches: &clap::ArgMatches) -> Vec<String> {
    matches
        .get_many::<String>("options")
        .unwrap_or_default()
        .map(|o| o.to_string())
        .collect()
}
