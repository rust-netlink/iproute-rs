// SPDX-License-Identifier: MIT

use std::fmt::Write;

pub fn mac_to_string(data: &[u8]) -> String {
    let mut rt = String::new();
    for (i, m) in data.iter().enumerate().take(data.len()) {
        write!(rt, "{m:02x}").ok();
        if i != data.len() - 1 {
            rt.push(':');
        }
    }
    rt
}

#[cfg(test)]
mod tests {
    use super::mac_to_string;

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
