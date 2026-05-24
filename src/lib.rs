// SPDX-License-Identifier: MIT

mod color;
mod error;
mod mac;
mod result;

pub use self::{
    color::CliColor,
    error::CliError,
    mac::{mac_to_string, parse_mac_str},
    result::{CanDisplay, CanOutput, OutputFormat, print_result_and_exit},
};
