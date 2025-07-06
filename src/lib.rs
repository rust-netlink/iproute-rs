// SPDX-License-Identifier: MIT

mod color;
mod error;
mod mac;
mod result;

pub use self::color::CliColor;
pub use self::error::CliError;
pub use self::mac::mac_to_string;
pub use self::result::{
    print_result_and_exit, CanDisplay, CanOutput, OutputFormat,
};
