// SPDX-License-Identifier: MIT

mod cli;
mod show;

#[cfg(test)]
mod tests;

pub(crate) use self::{cli::AddressCommand, show::CliAddressInfo};
