// SPDX-License-Identifier: MIT

const DEFAULT_ERROR_CODE: i32 = 1;

#[derive(Debug, Default)]
pub struct CliError {
    pub code: i32,
    pub msg: String,
}

impl From<&str> for CliError {
    fn from(msg: &str) -> Self {
        Self {
            code: DEFAULT_ERROR_CODE,
            msg: msg.into(),
        }
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "error {}: {}", self.code, self.msg)
    }
}

impl std::error::Error for CliError {}
