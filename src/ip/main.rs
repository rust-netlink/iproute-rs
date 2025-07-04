// SPDX-License-Identifier: MIT

mod link;

use iproute_rs::{print_result_and_exit, CliError, OutputFormat};

use self::link::LinkCommand;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), CliError> {
    let mut app = clap::Command::new("iproute-rs")
        .version(clap::crate_version!())
        .author("Gris Ge <fge@redhat.com>")
        .about("Command line of rust-netlink")
        .arg(
            clap::Arg::new("VERSION")
                .long("Version")
                .help("Print Version")
                .action(clap::ArgAction::SetTrue)
                .global(true),
        )
        .arg(
            clap::Arg::new("JSON")
                .short('j')
                .help("JSON output")
                .action(clap::ArgAction::SetTrue)
                .global(true),
        )
        .arg(
            clap::Arg::new("YAML")
                .short('y')
                .help("YAML output")
                .action(clap::ArgAction::SetTrue)
                .global(true),
        )
        .subcommand_required(true)
        .subcommand(LinkCommand::gen_command());

    let matches = app.get_matches_mut();

    let fmt = if matches.get_flag("JSON") {
        OutputFormat::Json
    } else if matches.get_flag("YAML") {
        OutputFormat::Yaml
    } else {
        OutputFormat::default()
    };

    if matches.get_flag("VERSION") {
        print_result_and_exit(Ok(format!("{}", app.render_version())));
    } else if let Some(matches) = matches.subcommand_matches(LinkCommand::CMD) {
        print_result_and_exit(LinkCommand::handle(matches, fmt).await);
    }

    Ok(())
}
