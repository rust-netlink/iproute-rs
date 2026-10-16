// SPDX-License-Identifier: MIT

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use iproute_rs::CliError;
use nl_l2tp::L2tpEncapType;

use super::cli::USAGE;

/// `L2TP_L2SPECTYPE_DEFAULT` of the kernel.
const L2SPECTYPE_DEFAULT: u8 = 1;
/// Length of the default layer2 specific header.
const L2SPECTYPE_DEFAULT_LEN: u8 = 4;

/// The options `ip l2tp` accepts, the equivalent of `struct l2tp_parm` of
/// iproute2. Zero valued IDs and ports are treated as unset, as iproute2
/// does.
#[derive(Clone, Debug)]
pub(crate) struct Parm {
    pub tunnel_id: u32,
    pub peer_tunnel_id: u32,
    pub session_id: u32,
    pub peer_session_id: u32,
    pub encap: L2tpEncapType,
    pub local_udp_port: u16,
    pub peer_udp_port: u16,
    pub cookie: Option<Vec<u8>>,
    pub peer_cookie: Option<Vec<u8>>,
    /// `None` when the address is `default`, `all` or `any`.
    pub local: Option<IpAddr>,
    pub peer: Option<IpAddr>,
    pub udp6_csum_tx: bool,
    pub udp6_csum_rx: bool,
    pub udp_csum: bool,
    pub recv_seq: bool,
    pub send_seq: bool,
    pub tunnel: bool,
    pub session: bool,
    pub ifname: Option<String>,
    pub l2spec_type: u8,
    pub l2spec_len: u8,
}

impl Default for Parm {
    fn default() -> Self {
        Self {
            tunnel_id: 0,
            peer_tunnel_id: 0,
            session_id: 0,
            peer_session_id: 0,
            encap: L2tpEncapType::Udp,
            local_udp_port: 0,
            peer_udp_port: 0,
            cookie: None,
            peer_cookie: None,
            local: None,
            peer: None,
            udp6_csum_tx: true,
            udp6_csum_rx: true,
            udp_csum: false,
            recv_seq: false,
            send_seq: false,
            tunnel: false,
            session: false,
            ifname: None,
            l2spec_type: L2SPECTYPE_DEFAULT,
            l2spec_len: L2SPECTYPE_DEFAULT_LEN,
        }
    }
}

/// Parse the options of `ip l2tp add`, `ip l2tp delete` and `ip l2tp show`,
/// the equivalent of `parse_args()` of iproute2.
pub(crate) fn parse_options(opts: &[String]) -> Result<Parm, CliError> {
    if opts.is_empty() {
        return Err(usage_error());
    }

    let mut parm = Parm::default();
    let mut iter = opts.iter();

    while let Some(arg) = iter.next() {
        let arg = arg.as_str();
        // iproute2 compares the command words with `strcmp()`, only the
        // `help` keyword is matched as a prefix.
        if arg == "encap" {
            let value = next_value(&mut iter)?;
            parm.encap = match value {
                "ip" => L2tpEncapType::Ip,
                "udp" => L2tpEncapType::Udp,
                _ => {
                    return Err(CliError {
                        code: 255,
                        msg: format!(
                            "Unknown tunnel encapsulation \"{value}\""
                        ),
                    });
                }
            };
        } else if arg == "name" {
            let value = next_value(&mut iter)?;
            if !check_ifname(value) {
                return Err(invarg(value, "\"name\" not a valid ifname"));
            }
            parm.ifname = Some(value.to_string());
        } else if arg == "remote" {
            let value = next_value(&mut iter)?;
            parm.peer = parse_addr(value)?;
        } else if arg == "local" {
            let value = next_value(&mut iter)?;
            parm.local = parse_addr(value)?;
        } else if arg == "tunnel_id" || arg == "tid" {
            let value = next_value(&mut iter)?;
            parm.tunnel_id = parse_u32_base0(value)
                .ok_or_else(|| invarg(value, "invalid ID\n"))?;
        } else if arg == "peer_tunnel_id" || arg == "ptid" {
            let value = next_value(&mut iter)?;
            parm.peer_tunnel_id = parse_u32_base0(value)
                .ok_or_else(|| invarg(value, "invalid ID\n"))?;
        } else if arg == "session_id" || arg == "sid" {
            let value = next_value(&mut iter)?;
            parm.session_id = parse_u32_base0(value)
                .ok_or_else(|| invarg(value, "invalid ID\n"))?;
        } else if arg == "peer_session_id" || arg == "psid" {
            let value = next_value(&mut iter)?;
            parm.peer_session_id = parse_u32_base0(value)
                .ok_or_else(|| invarg(value, "invalid ID\n"))?;
        } else if arg == "udp_sport" {
            let value = next_value(&mut iter)?;
            parm.local_udp_port = parse_u16_base0(value)
                .ok_or_else(|| invarg(value, "invalid port\n"))?;
        } else if arg == "udp_dport" {
            let value = next_value(&mut iter)?;
            parm.peer_udp_port = parse_u16_base0(value)
                .ok_or_else(|| invarg(value, "invalid port\n"))?;
        } else if arg == "udp_csum" {
            let value = next_value(&mut iter)?;
            parm.udp_csum = parse_on_off(value).ok_or_else(|| {
                invarg(value, "invalid option for udp_csum\n")
            })?;
        } else if arg == "udp6_csum_rx" {
            let value = next_value(&mut iter)?;
            parm.udp6_csum_rx = parse_on_off(value).ok_or_else(|| {
                invarg(value, "invalid option for udp6_csum_rx\n")
            })?;
        } else if arg == "udp6_csum_tx" {
            let value = next_value(&mut iter)?;
            parm.udp6_csum_tx = parse_on_off(value).ok_or_else(|| {
                invarg(value, "invalid option for udp6_csum_tx\n")
            })?;
        } else if arg == "offset" {
            eprintln!("Ignoring option \"offset\"");
            next_value(&mut iter)?;
        } else if arg == "peer_offset" {
            eprintln!("Ignoring option \"peer_offset\"");
            next_value(&mut iter)?;
        } else if arg == "cookie" {
            let value = next_value(&mut iter)?;
            parm.cookie = Some(parse_cookie(value)?);
        } else if arg == "peer_cookie" {
            let value = next_value(&mut iter)?;
            parm.peer_cookie = Some(parse_cookie(value)?);
        } else if arg == "l2spec_type" {
            let value = next_value(&mut iter)?;
            if value.eq_ignore_ascii_case("default") {
                parm.l2spec_type = L2SPECTYPE_DEFAULT;
                parm.l2spec_len = L2SPECTYPE_DEFAULT_LEN;
            } else if value.eq_ignore_ascii_case("none") {
                parm.l2spec_type = 0;
                parm.l2spec_len = 0;
            } else {
                return Err(CliError {
                    code: 255,
                    msg: format!(
                        "Unknown layer2specific header type \"{value}\""
                    ),
                });
            }
        } else if arg == "seq" {
            let value = next_value(&mut iter)?;
            if value.eq_ignore_ascii_case("both") {
                parm.recv_seq = true;
                parm.send_seq = true;
            } else if value.eq_ignore_ascii_case("recv") {
                parm.recv_seq = true;
            } else if value.eq_ignore_ascii_case("send") {
                parm.send_seq = true;
            } else if value.eq_ignore_ascii_case("none") {
                parm.recv_seq = false;
                parm.send_seq = false;
            } else {
                return Err(CliError {
                    code: 255,
                    msg: format!("Unknown seq value \"{value}\""),
                });
            }
        } else if arg == "tunnel" {
            parm.tunnel = true;
        } else if arg == "session" {
            parm.session = true;
        } else if !arg.is_empty() && "help".starts_with(arg) {
            return Err(usage_error());
        } else {
            eprintln!("Unknown command: {arg}");
            return Err(usage_error());
        }
    }

    Ok(parm)
}

/// iproute2 `missarg()` exits with the code 255.
pub(crate) fn missarg(key: &str) -> CliError {
    CliError {
        code: 255,
        msg: format!("Error: argument \"{key}\" is required"),
    }
}

fn usage_error() -> CliError {
    CliError {
        code: 255,
        msg: USAGE.to_string(),
    }
}

fn next_value<'a>(
    iter: &mut std::slice::Iter<'a, String>,
) -> Result<&'a str, CliError> {
    iter.next().map(|s| s.as_str()).ok_or_else(|| CliError {
        code: 255,
        msg: "Command line is not complete. Try option \"help\"".to_string(),
    })
}

/// iproute2 `invarg()` exits with the code 255.
fn invarg(value: &str, msg: &str) -> CliError {
    CliError {
        code: 255,
        msg: format!("Error: argument \"{value}\" is wrong: {msg}"),
    }
}

/// iproute2 `check_ifname()`.
fn check_ifname(name: &str) -> bool {
    !name.is_empty()
        && name.len() < 16
        && name != "."
        && name != ".."
        && !name.chars().any(|c| c == '/' || c.is_whitespace())
}

/// iproute2 `get_u32(&val, arg, 0)`: `strtoul(..., 0)` accepts hexadecimal
/// and octal numbers, negative values overflow the `u32` range.
fn parse_u64_base0(s: &str) -> Option<u64> {
    if s.is_empty() || s.starts_with('-') {
        return None;
    }
    let (radix, digits) = if let Some(hex) =
        s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))
    {
        (16, hex)
    } else if s.len() > 1 && s.starts_with('0') {
        (8, &s[1..])
    } else {
        (10, s)
    };
    u64::from_str_radix(digits, radix).ok()
}

fn parse_u32_base0(s: &str) -> Option<u32> {
    parse_u64_base0(s).and_then(|value| u32::try_from(value).ok())
}

fn parse_u16_base0(s: &str) -> Option<u16> {
    parse_u64_base0(s).and_then(|value| u16::try_from(value).ok())
}

fn parse_on_off(s: &str) -> Option<bool> {
    match s {
        "on" => Some(true),
        "off" => Some(false),
        _ => None,
    }
}

/// iproute2 `hex2mem()`, the length is validated before.
fn parse_cookie(s: &str) -> Result<Vec<u8>, CliError> {
    if s.len() != 8 && s.len() != 16 {
        return Err(invarg(s, "cookie must be either 8 or 16 hex digits\n"));
    }
    let mut cookie = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16)
            .map_err(|_| invarg(s, "cookie must be a hex string\n"))?;
        cookie.push(byte);
    }
    Ok(cookie)
}

/// iproute2 `get_addr(..., AF_UNSPEC)`: `default`, `all` and `any` produce
/// an unspecified family, which the commands treat as a missing address.
fn parse_addr(s: &str) -> Result<Option<IpAddr>, CliError> {
    if s == "default" || s == "all" || s == "any" {
        return Ok(None);
    }
    if s.contains(':') {
        return s
            .parse::<Ipv6Addr>()
            .map(|addr| Some(IpAddr::V6(addr)))
            .map_err(|_| addr_error(s));
    }
    parse_ipv4_addr(s)
        .map(|addr| Some(IpAddr::V4(addr)))
        .ok_or_else(|| addr_error(s))
}

/// iproute2 `get_addr()` exits with the code 1 for an unparsable address.
fn addr_error(s: &str) -> CliError {
    CliError {
        code: 1,
        msg: format!(
            "Error: any valid address is expected rather than \"{s}\"."
        ),
    }
}

/// iproute2 `get_addr_ipv4()`: up to four dot separated parts parsed with
/// `strtoul(..., 0)`, the missing parts stay zero, so `127.1` becomes
/// `127.1.0.0`.
fn parse_ipv4_addr(s: &str) -> Option<Ipv4Addr> {
    let mut octets = [0u8; 4];
    for (count, part) in s.split('.').enumerate() {
        if count == 4 {
            return None;
        }
        octets[count] = u8::try_from(parse_u64_base0(part)?).ok()?;
    }
    Some(Ipv4Addr::from(octets))
}
