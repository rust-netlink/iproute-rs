// SPDX-License-Identifier: MIT

use iproute_rs::CliError;

use super::{
    add::LinkAddCommand,
    delete::LinkDeleteCommand,
    set::LinkSetCommand,
    show::{CliLinkInfo, handle_show},
};

pub(crate) struct LinkCommand;

impl LinkCommand {
    pub(crate) const CMD: &'static str = "link";

    pub(crate) fn gen_command() -> clap::Command {
        clap::Command::new(Self::CMD)
            .about("network device configuration")
            .alias("lin")
            .alias("li")
            .alias("l")
            .subcommand_required(false)
            .subcommand(
                clap::Command::new("show")
                    .about("show links")
                    .alias("list")
                    .alias("lst")
                    .alias("ls")
                    .alias("li")
                    .alias("l")
                    .arg(
                        clap::Arg::new("options")
                            .action(clap::ArgAction::Append)
                            .trailing_var_arg(true),
                    ),
            )
            .subcommand(LinkAddCommand::gen_command())
            .subcommand(LinkDeleteCommand::gen_command())
            .subcommand(LinkSetCommand::gen_command())
    }

    pub(crate) async fn handle(
        matches: &clap::ArgMatches,
    ) -> Result<Vec<CliLinkInfo>, CliError> {
        if let Some(matches) = matches.subcommand_matches(LinkAddCommand::CMD) {
            LinkAddCommand::handle(matches).await?;
            Ok(vec![])
        } else if let Some(matches) =
            matches.subcommand_matches(LinkDeleteCommand::CMD)
        {
            LinkDeleteCommand::handle(matches).await?;
            Ok(vec![])
        } else if let Some(matches) =
            matches.subcommand_matches(LinkSetCommand::CMD)
        {
            LinkSetCommand::handle(matches).await?;
            Ok(vec![])
        } else if let Some(matches) = matches.subcommand_matches("show") {
            let opts: Vec<&str> = matches
                .get_many::<String>("options")
                .unwrap_or_default()
                .map(String::as_str)
                .collect();
            handle_show(&opts, matches.get_flag("DETAILS")).await
        } else {
            handle_show(&[], matches.get_flag("DETAILS")).await
        }
    }
}
