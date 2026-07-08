// SPDX-License-Identifier: MIT

mod address;
mod link;
mod neighbour;

#[cfg(test)]
mod tests;

use std::io::IsTerminal;

use iproute_rs::{CliColor, CliError, OutputFormat, print_result_and_exit};
use rtnetlink::packet_route::AddressFamily;

use self::{address::AddressCommand, link::LinkCommand};
use crate::neighbour::NeighbourCommand;

pub(crate) fn resolve_preferred_family(
    matches: &clap::ArgMatches,
) -> Option<AddressFamily> {
    if matches.get_flag("FAMILY4") {
        return Some(AddressFamily::Inet);
    }
    if matches.get_flag("FAMILY6") {
        return Some(AddressFamily::Inet6);
    }
    if matches.get_flag("FAMILYM") {
        return Some(AddressFamily::Bridge);
    }
    if matches.get_flag("FAMILY0") {
        return Some(AddressFamily::Unspec);
    }
    if let Some(family) = matches.get_one::<String>("FAMILY") {
        return match family.as_str() {
            "inet" => Some(AddressFamily::Inet),
            "inet6" => Some(AddressFamily::Inet6),
            "bridge" => Some(AddressFamily::Bridge),
            "link" | "mpls" => Some(AddressFamily::Unspec),
            _ => None,
        };
    }
    None
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), CliError> {
    let mut app = clap::Command::new("iproute-rs")
        .version(clap::crate_version!())
        .author(clap::crate_authors!())
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
            clap::Arg::new("COLOR")
                .short('c')
                .help("Colorful output")
                .action(clap::ArgAction::Set)
                .value_parser(["always", "auto", "never"])
                .default_value("auto")
                .global(true),
        )
        .arg(
            clap::Arg::new("YAML")
                .short('y')
                .help("YAML output")
                .action(clap::ArgAction::SetTrue)
                .global(true),
        )
        .arg(
            clap::Arg::new("DETAILS")
                .short('d')
                .help("Interface details")
                .action(clap::ArgAction::SetTrue)
                .global(true),
        )
        .arg(
            clap::Arg::new("STATISTICS")
                .short('s')
                .long("stats")
                .help("Show statistics")
                .action(clap::ArgAction::SetTrue)
                .global(true),
        )
        .arg(
            clap::Arg::new("FAMILY4")
                .short('4')
                .help("IPv4 only")
                .action(clap::ArgAction::SetTrue)
                .global(true),
        )
        .arg(
            clap::Arg::new("FAMILY6")
                .short('6')
                .help("IPv6 only")
                .action(clap::ArgAction::SetTrue)
                .global(true),
        )
        .arg(
            clap::Arg::new("FAMILYM")
                .short('B')
                .help("Bridge only")
                .action(clap::ArgAction::SetTrue)
                .global(true),
        )
        .arg(
            clap::Arg::new("FAMILY0")
                .short('0')
                .help("Link layer only")
                .action(clap::ArgAction::SetTrue)
                .global(true),
        )
        .arg(
            clap::Arg::new("FAMILY")
                .short('f')
                .long("family")
                .help("Address family")
                .value_parser(["inet", "inet6", "bridge", "mpls", "link"])
                .global(true),
        )
        .arg(
            clap::Arg::new("ONELINE")
                .short('o')
                .long("oneline")
                .help("Output each record on a single line")
                .action(clap::ArgAction::SetTrue)
                .global(true),
        )
        .arg(
            clap::Arg::new("BRIEF")
                .long("brief")
                .visible_alias("br")
                .help("Brief output")
                .action(clap::ArgAction::SetTrue)
                .global(true),
        )
        .arg(
            clap::Arg::new("RESOLVE")
                .short('r')
                .long("resolve")
                .help("Resolve hostnames")
                .action(clap::ArgAction::SetTrue)
                .global(true),
        )
        .arg(
            clap::Arg::new("LOOPS")
                .short('l')
                .long("loops")
                .help("Maximum number of flush attempts")
                .value_parser(clap::value_parser!(u32))
                .global(true),
        )
        .arg(
            clap::Arg::new("NETNS")
                .short('n')
                .long("netns")
                .help("Network namespace to use")
                .global(true),
        )
        .arg(
            clap::Arg::new("PRETTY")
                .long("pretty")
                .help("Pretty print JSON")
                .action(clap::ArgAction::SetTrue)
                .global(true),
        )
        .arg(
            clap::Arg::new("HUMAN")
                .long("human")
                .help("Human readable output")
                .action(clap::ArgAction::SetTrue)
                .global(true),
        )
        .arg(
            clap::Arg::new("NUMERIC")
                .long("Numeric")
                .help("Print numeric values")
                .action(clap::ArgAction::SetTrue)
                .global(true),
        )
        .arg(
            clap::Arg::new("ALL")
                .short('a')
                .long("all")
                .help("Apply to all network namespaces")
                .action(clap::ArgAction::SetTrue)
                .global(true),
        )
        .subcommand_required(true)
        .subcommand(LinkCommand::gen_command())
        .subcommand(AddressCommand::gen_command())
        .subcommand(NeighbourCommand::gen_command());

    let matches = app.get_matches_mut();

    let fmt = if matches.get_flag("JSON") {
        OutputFormat::Json
    } else if matches.get_flag("YAML") {
        OutputFormat::Yaml
    } else {
        OutputFormat::default()
    };

    if let Some(color_str) = matches.get_one::<String>("COLOR")
        && (color_str == "always"
            || (color_str == "auto" && std::io::stdout().is_terminal()))
    {
        CliColor::enable();
    }

    if matches.get_flag("VERSION") {
        print_result_and_exit(Ok(app.render_version().to_string()), fmt);
    } else if let Some(matches) = matches.subcommand_matches(LinkCommand::CMD) {
        print_result_and_exit(LinkCommand::handle(matches).await, fmt);
    } else if let Some(matches) =
        matches.subcommand_matches(AddressCommand::CMD)
    {
        let preferred_family = resolve_preferred_family(matches);
        print_result_and_exit(
            AddressCommand::handle(matches, preferred_family).await,
            fmt,
        );
    } else if let Some(matches) =
        matches.subcommand_matches(NeighbourCommand::CMD)
    {
        print_result_and_exit(NeighbourCommand::handle(matches).await, fmt);
    } else {
        app.print_help()?;
        println!();
    }

    Ok(())
}
