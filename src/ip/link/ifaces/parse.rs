// SPDX-License-Identifier: MIT

use std::str::FromStr;

use iproute_rs::CliError;

pub(crate) fn parse_on_off_01(s: &str) -> Result<bool, CliError> {
    match s {
        "on" | "1" => Ok(true),
        "off" | "0" => Ok(false),
        _ => Err(CliError::from(format!("expected on/off or 0/1, got {s}"))),
    }
}

pub(crate) fn parse_u32(s: &str, name: &str) -> Result<u32, CliError> {
    s.parse::<u32>()
        .map_err(|_| CliError::from(format!("Invalid {name} value: {s}")))
}

pub(crate) fn parse_u64(s: &str, name: &str) -> Result<u64, CliError> {
    s.parse::<u64>()
        .map_err(|_| CliError::from(format!("Invalid {name} value: {s}")))
}

pub(crate) fn parse_u16(s: &str, name: &str) -> Result<u16, CliError> {
    s.parse::<u16>()
        .map_err(|_| CliError::from(format!("Invalid {name} value: {s}")))
}

pub(crate) fn parse_u8(s: &str, name: &str) -> Result<u8, CliError> {
    s.parse::<u8>()
        .map_err(|_| CliError::from(format!("Invalid {name} value: {s}")))
}

pub(crate) fn parse_from_str<T: FromStr>(
    s: &str,
    name: &str,
) -> Result<T, CliError>
where
    T::Err: std::fmt::Display,
{
    s.parse::<T>()
        .map_err(|e| CliError::from(format!("Invalid {name} value: {e}")))
}
