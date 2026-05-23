// SPDX-License-Identifier: MIT

use iproute_rs::CliError;

use super::show::{CliNeighbourInfo, handle_show};

pub(crate) struct NeighbourCommand;

impl NeighbourCommand {
    pub(crate) const CMD: &'static str = "neighbour";

    pub(crate) fn gen_command() -> clap::Command {
        clap::Command::new(Self::CMD)
            .about("arp/ndp table management")
            .alias("neigh")
            .alias("neig")
            .alias("nei")
            .alias("ne")
            .alias("n")
            .subcommand_required(false)
            .subcommand(
                clap::Command::new("show")
                    .about("list neighbour entries")
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
    }

    pub(crate) async fn handle(
        matches: &clap::ArgMatches,
    ) -> Result<Vec<CliNeighbourInfo>, CliError> {
        if let Some(matches) = matches.subcommand_matches("show") {
            let opts = matches
                .get_many::<String>("options")
                .unwrap_or_default()
                .map(String::as_str);
            handle_show(opts, matches.get_flag("STATISTICS")).await
        } else {
            handle_show([].into_iter(), matches.get_flag("STATISTICS")).await
        }
    }
}
