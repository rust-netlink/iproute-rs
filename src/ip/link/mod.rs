// SPDX-License-Identifier: MIT

mod cli;
mod detail;
mod flags;
mod ifaces;
mod link_info;
mod show;

#[cfg(test)]
mod tests;

pub(crate) use self::cli::LinkCommand;
