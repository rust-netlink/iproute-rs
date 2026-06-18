// SPDX-License-Identifier: MIT

mod add;
mod afstats;
mod cli;
mod delete;
mod detail;
mod flags;
mod ifaces;
mod link_info;
mod property;
mod set;
mod show;
mod xdp;
mod xstats;

#[cfg(test)]
mod tests;

pub(crate) use self::{
    add::LinkBaseConf,
    cli::LinkCommand,
    show::{CliLinkInfo, handle_show},
};
