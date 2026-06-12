// SPDX-License-Identifier: MIT

use std::fmt::Write;

use crate::CliError;

pub fn mac_to_string(data: &[u8]) -> String {
    if data.len() == 4 {
        let mut arr = [0u8; 4];
        arr.copy_from_slice(data);
        return std::net::Ipv4Addr::from(arr).to_string();
    }
    if data.len() == 16 {
        let mut arr = [0u8; 16];
        arr.copy_from_slice(data);
        return std::net::Ipv6Addr::from(arr).to_string();
    }
    let mut rt = String::new();
    for (i, m) in data.iter().enumerate() {
        write!(rt, "{m:02x}").ok();
        if i != data.len() - 1 {
            rt.push(':');
        }
    }
    rt
}

pub fn parse_mac_str(s: &str) -> Result<Vec<u8>, CliError> {
    let mut bytes = Vec::new();
    for byte in s.split(':') {
        let v = u8::from_str_radix(byte, 16)
            .map_err(|_| CliError::from(format!("invalid MAC address: {s}")))?;
        bytes.push(v);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mac_str_ok() {
        assert_eq!(
            parse_mac_str("52:54:00:b0:52:d1").unwrap(),
            vec![0x52, 0x54, 0x00, 0xb0, 0x52, 0xd1]
        );
    }

    #[test]
    fn test_parse_mac_str_invalid() {
        assert!(parse_mac_str("zz:00:00:00:00:00").is_err());
    }

    #[test]
    fn test_parse_mac_str_empty() {
        assert!(parse_mac_str("").is_err());
    }

    #[test]
    fn test_mac_to_string_ethernet() {
        assert_eq!(
            mac_to_string(&[0x52u8, 0x54, 0x00, 0xb0, 0x52, 0xd1]),
            "52:54:00:b0:52:d1"
        );
    }

    #[test]
    fn test_mac_to_string_inifiband() {
        assert_eq!(
            mac_to_string(&[
                0x20u8, 0x00, 0x55, 0x04, 0x01, 0xFE, 0x80, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x02, 0xC9, 0x02, 0x00, 0x23, 0x13,
                0x92,
            ]),
            "20:00:55:04:01:fe:80:00:00:00:00:00:00:00:02:c9:02:00:23:13:92",
        );
    }
}
