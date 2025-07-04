// SPDX-License-Identifier: Apache-2.0

use std::io::Write;

use crate::error::CliError;

pub fn print_result_and_exit(result: Result<String, CliError>) {
    match result {
        Ok(s) => {
            let mut stdout = std::io::stdout();
            writeln!(stdout, "{s}").ok();
            std::process::exit(0);
        }
        Err(e) => {
            let mut stderr = std::io::stderr();
            writeln!(stderr, "{e}").ok();
            std::process::exit(e.code);
        }
    }
}

#[derive(Copy, Clone, Default, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum OutputFormat {
    #[default]
    Cli,
    Yaml,
    Json,
}
