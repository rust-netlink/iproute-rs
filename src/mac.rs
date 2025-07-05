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
