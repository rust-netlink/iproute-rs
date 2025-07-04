// SPDX-License-Identifier: MIT

use iproute_rs::{CliError, OutputFormat};
use serde::Serialize;

#[derive(Serialize, Default)]
struct IfaceBrief {
    ifindex: u32,
    ifname: String,
    flags: Vec<String>,
    mtu: u32,
}

pub(crate) async fn handle_show(
    matches: &clap::ArgMatches,
    fmt: OutputFormat,
) -> Result<String, CliError> {
    todo!()
}
