// SPDX-License-Identifier: MIT

mod add;
mod cli;
mod detail;
mod flags;
mod ifaces;
mod link_info;
mod show;

#[cfg(test)]
mod tests;

pub(crate) use self::{
    add::LinkBaseConf,
    cli::LinkCommand,
    show::{CliLinkInfo, handle_show},
};
