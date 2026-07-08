// SPDX-License-Identifier: MIT

mod add;
mod cli;
mod save;
mod show;

#[cfg(test)]
mod tests;

pub(crate) use self::{cli::AddressCommand, show::CliAddressInfo};
