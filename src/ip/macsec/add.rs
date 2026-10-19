// SPDX-License-Identifier: MIT

use std::ffi::CString;

use iproute_rs::CliError;
use nl_macsec::{
    MACSEC_SALT_LEN, MacSecCipherId, MacSecOffload, MacsecConfig,
    MacsecRxScConfig, MacsecSaConfig, new_connection,
};

use super::cli::{MacsecModify, invarg, missing_argument, usage_error};

#[derive(Clone, Copy)]
struct Sci {
    value: u64,
}

#[derive(Default)]
struct SaDesc {
    an: u8,
    pn32: u32,
    pn64: u64,
    pn_set: bool,
    xpn: bool,
    key_id: Vec<u8>,
    key: Vec<u8>,
    active: Option<bool>,
    salt: Option<Vec<u8>>,
    ssci: Option<u32>,
}

pub(crate) async fn handle_modify(
    action: MacsecModify,
    opts: &[String],
) -> Result<(), CliError> {
    let mut iter = opts.iter();
    let link_name = iter.next().ok_or_else(usage_error)?;
    let ifindex = resolve_ifindex(link_name)?;
    let direction = iter.next().ok_or_else(usage_error)?;

    let args: Vec<String> = iter.cloned().collect();

    let (connection, mut handle, _) = new_connection()?;
    tokio::spawn(connection);
    let current = handle
        .get_all()
        .await?
        .into_iter()
        .find(|config| config.ifindex == ifindex);

    let config = match direction.as_str() {
        "tx" => build_tx(action, ifindex, current.as_ref(), &args)?,
        "rx" => build_rx(action, ifindex, current.as_ref(), &args)?,
        _ => return Err(usage_error()),
    };

    handle.apply(&config).await?;
    Ok(())
}

pub(crate) async fn handle_offload(opts: &[String]) -> Result<(), CliError> {
    let mut iter = opts.iter();
    let link_name = iter.next().ok_or_else(usage_error)?;
    let ifindex = resolve_ifindex(link_name)?;
    let value = iter.next().ok_or_else(usage_error)?;
    let offload = match value.as_str() {
        "off" => MacSecOffload::Off,
        "phy" => MacSecOffload::Phy,
        "mac" => MacSecOffload::Mac,
        _ => {
            eprintln!(
                "Error: argument of \"offload\" must be one of \"off\", \
                 \"phy\", \"mac\", not \"{value}\""
            );
            return Err(usage_error());
        }
    };

    let mut config = MacsecConfig::new(ifindex);
    config.secy.offload = Some(offload);
    apply_config(config).await
}

async fn apply_config(config: MacsecConfig) -> Result<(), CliError> {
    let (connection, mut handle, _) = new_connection()?;
    tokio::spawn(connection);
    handle.apply(&config).await?;
    Ok(())
}

fn build_tx(
    action: MacsecModify,
    ifindex: u32,
    current: Option<&MacsecConfig>,
    args: &[String],
) -> Result<MacsecConfig, CliError> {
    let (an, index) = parse_an(args)?;
    let mut config = MacsecConfig::new(ifindex);
    let mut sa_list = current
        .and_then(|config| config.tx_sa.clone())
        .unwrap_or_default();

    if action == MacsecModify::Delete {
        sa_list.retain(|sa| sa.an != an);
        config.tx_sa = Some(sa_list);
        return Ok(config);
    }

    let mut sa = SaDesc {
        an,
        ..Default::default()
    };
    parse_sa_args(args, index, &mut sa)?;
    check_sa_args(action, &sa)?;
    config.secy.cipher_suite = cipher_for_sa(&sa);
    let new_sa = sa_to_config(&sa);
    match sa_list.iter().position(|sa| sa.an == an) {
        Some(position) => sa_list[position] = new_sa,
        None => sa_list.push(new_sa),
    }
    config.tx_sa = Some(sa_list);
    Ok(config)
}

fn build_rx(
    action: MacsecModify,
    ifindex: u32,
    current: Option<&MacsecConfig>,
    args: &[String],
) -> Result<MacsecConfig, CliError> {
    let (sci, mut index) = parse_sci(args)?;
    let mut config = MacsecConfig::new(ifindex);
    let current_scs = current
        .and_then(|config| config.rx_sc.clone())
        .unwrap_or_default();

    if let Some(sa_an) = parse_optional_an(args, index) {
        index += 2;
        let mut sa_list = current_scs
            .iter()
            .find(|sc| sc.sci == sci.value)
            .and_then(|sc| sc.sa_list.clone())
            .unwrap_or_default();

        if action == MacsecModify::Delete {
            sa_list.retain(|sa| sa.an != sa_an);
            config.rx_sc = Some(rx_sc_list(&current_scs, sci.value, sa_list));
            return Ok(config);
        }

        let mut sa = SaDesc {
            an: sa_an,
            ..Default::default()
        };
        parse_sa_args(args, index, &mut sa)?;
        check_sa_args(action, &sa)?;
        config.secy.cipher_suite = cipher_for_sa(&sa);
        let new_sa = sa_to_config(&sa);
        match sa_list.iter().position(|sa| sa.an == sa_an) {
            Some(position) => sa_list[position] = new_sa,
            None => sa_list.push(new_sa),
        }
        config.rx_sc = Some(rx_sc_list(&current_scs, sci.value, sa_list));
        return Ok(config);
    }

    if action == MacsecModify::Delete {
        let sc_list = current_scs
            .iter()
            .filter(|sc| sc.sci != sci.value)
            .map(|sc| MacsecRxScConfig::new(sc.sci))
            .collect();
        config.rx_sc = Some(sc_list);
        return Ok(config);
    }

    let active = parse_rxsc_args(&args[index..])?;
    let mut sc_list: Vec<MacsecRxScConfig> = current_scs
        .iter()
        .filter(|sc| sc.sci != sci.value)
        .map(|sc| MacsecRxScConfig::new(sc.sci))
        .collect();
    let mut rx_sc = MacsecRxScConfig::new(sci.value);
    rx_sc.active = active;
    sc_list.push(rx_sc);
    config.rx_sc = Some(sc_list);
    Ok(config)
}

fn rx_sc_list(
    current: &[MacsecRxScConfig],
    sci: u64,
    sa_list: Vec<MacsecSaConfig>,
) -> Vec<MacsecRxScConfig> {
    let mut sc_list: Vec<MacsecRxScConfig> = current
        .iter()
        .filter(|sc| sc.sci != sci)
        .map(|sc| MacsecRxScConfig::new(sc.sci))
        .collect();
    let mut rx_sc = MacsecRxScConfig::new(sci);
    rx_sc.sa_list = Some(sa_list);
    sc_list.push(rx_sc);
    sc_list
}

fn cipher_for_sa(sa: &SaDesc) -> MacSecCipherId {
    if sa.xpn {
        MacSecCipherId::GcmAesXpn128
    } else {
        MacSecCipherId::GcmAes128
    }
}

fn sa_to_config(sa: &SaDesc) -> MacsecSaConfig {
    let mut config = MacsecSaConfig::new(sa.an);
    config.pn = if sa.pn_set {
        Some(if sa.xpn { sa.pn64 } else { u64::from(sa.pn32) })
    } else {
        None
    };
    config.ssci = sa.ssci;
    config.active = sa.active;
    config.key_id = sa.key_id.clone();
    if !sa.key.is_empty() {
        config.key = Some(sa.key.clone());
    }
    config.salt = sa.salt.as_deref().map(salt_array);
    config
}

fn salt_array(value: &[u8]) -> [u8; MACSEC_SALT_LEN] {
    let mut salt = [0u8; MACSEC_SALT_LEN];
    let len = value.len().min(MACSEC_SALT_LEN);
    salt[..len].copy_from_slice(&value[..len]);
    salt
}

fn check_sa_args(action: MacsecModify, sa: &SaDesc) -> Result<(), CliError> {
    match action {
        MacsecModify::Add => {
            if sa.key.is_empty() {
                return Err(CliError {
                    code: 1,
                    msg: "cannot create SA without key".to_string(),
                });
            }
            if !sa.pn_set {
                return Err(CliError {
                    code: 1,
                    msg: "must specify a packet number != 0".to_string(),
                });
            }
        }
        MacsecModify::Set => {
            if !sa.key.is_empty() {
                return Err(CliError {
                    code: 1,
                    msg: "cannot change key on SA".to_string(),
                });
            }
        }
        MacsecModify::Delete => {}
    }
    Ok(())
}

fn parse_an(args: &[String]) -> Result<(u8, usize), CliError> {
    if args.first().is_none_or(|arg| arg != "sa") {
        return Err(usage_error());
    }
    if args.len() < 2 {
        return Err(missing_argument());
    }
    let an = parse_u8_base0(&args[1])
        .filter(|an| *an <= 3)
        .ok_or_else(|| invarg(&args[1], "expected an { 0..3 }"))?;
    Ok((an, 2))
}

fn parse_optional_an(args: &[String], index: usize) -> Option<u8> {
    if args.get(index).is_some_and(|arg| arg == "sa")
        && let Some(an) = args.get(index + 1)
        && let Some(an) = parse_u8_base0(an).filter(|an| *an <= 3)
    {
        return Some(an);
    }
    None
}

fn parse_sci(args: &[String]) -> Result<(Sci, usize), CliError> {
    let mut sci = None;
    let mut port = None;
    let mut address = None;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "sci" => {
                let value = args.get(index + 1).ok_or_else(missing_argument)?;
                if port.is_some() {
                    return Err(invarg(value, "expected address"));
                }
                if address.is_some() {
                    return Err(invarg(value, "expected port"));
                }
                let value = parse_u64_base16(value)
                    .ok_or_else(|| invarg(value, "expected sci"))?;
                sci = Some(Sci { value });
                index += 2;
            }
            "port" => {
                let value = args.get(index + 1).ok_or_else(missing_argument)?;
                let value = parse_u16_base0(value)
                    .filter(|value| *value != 0)
                    .ok_or_else(|| invarg(value, "expected port != 0"))?;
                port = Some(value);
                index += 2;
            }
            "address" => {
                let value = args.get(index + 1).ok_or_else(missing_argument)?;
                address = Some(
                    parse_lladdr(value)
                        .ok_or_else(|| invarg(value, "expected lladdr"))?,
                );
                index += 2;
            }
            value => {
                return Err(invarg(value, "expected sci, port, or address"));
            }
        }

        if sci.is_some() || (port.is_some() && address.is_some()) {
            break;
        }
    }

    if let Some(sci) = sci {
        return Ok((sci, index));
    }
    if let (Some(port), Some(address)) = (port, address) {
        return Ok((
            Sci {
                value: make_sci(&address, port),
            },
            index,
        ));
    }

    Err(CliError {
        code: 255,
        msg: format!("expected sci\n{}", super::cli::USAGE),
    })
}

fn parse_rxsc_args(args: &[String]) -> Result<Option<bool>, CliError> {
    let mut active = None;
    for arg in args {
        let value = match arg.as_str() {
            "on" => true,
            "off" => false,
            _ => {
                eprintln!("macsec: unknown command \"{arg}\"?");
                return Err(usage_error());
            }
        };
        if active.is_some() {
            return Err(invarg(arg, "duplicate on/off"));
        }
        active = Some(value);
    }
    Ok(active)
}

fn parse_sa_args(
    args: &[String],
    mut index: usize,
    sa: &mut SaDesc,
) -> Result<usize, CliError> {
    while index < args.len() {
        let key = args[index].as_str();
        match key {
            "pn" => {
                let value = args.get(index + 1).ok_or_else(missing_argument)?;
                if sa.pn_set {
                    return Err(invarg(value, "duplicate pn"));
                }
                sa.pn32 = parse_u32_base0(value)
                    .filter(|value| *value != 0)
                    .ok_or_else(|| invarg(value, "expected pn != 0"))?;
                sa.pn_set = true;
                index += 2;
            }
            "xpn" => {
                let value = args.get(index + 1).ok_or_else(missing_argument)?;
                if sa.pn_set {
                    return Err(invarg(value, "duplicate xpn"));
                }
                sa.pn64 = parse_u64_base0(value)
                    .filter(|value| *value != 0)
                    .ok_or_else(|| invarg(value, "expected pn != 0"))?;
                sa.pn_set = true;
                sa.xpn = true;
                index += 2;
            }
            "salt" => {
                let value = args.get(index + 1).ok_or_else(missing_argument)?;
                if sa.salt.is_some() {
                    return Err(invarg(value, "duplicate salt"));
                }
                sa.salt = Some(
                    parse_hexstring(value, 12)
                        .ok_or_else(|| invarg(value, "expected salt"))?,
                );
                index += 2;
            }
            "ssci" => {
                let value = args.get(index + 1).ok_or_else(missing_argument)?;
                if sa.ssci.is_some() {
                    return Err(invarg(value, "duplicate ssci"));
                }
                sa.ssci = Some(
                    parse_u32_base16(value)
                        .ok_or_else(|| invarg(value, "expected ssci"))?,
                );
                index += 2;
            }
            "key" => {
                let id = args.get(index + 1).ok_or_else(missing_argument)?;
                let key = args.get(index + 2).ok_or_else(missing_argument)?;
                sa.key_id = parse_hexstring(id, 16)
                    .ok_or_else(|| invarg(id, "expected key id"))?;
                sa.key = parse_hexstring(key, 128)
                    .ok_or_else(|| invarg(key, "expected key"))?;
                index += 3;
            }
            "on" | "off" => {
                if sa.active.is_some() {
                    return Err(invarg(key, "duplicate on/off"));
                }
                sa.active = Some(key == "on");
                index += 1;
            }
            value => {
                eprintln!("macsec: unknown command \"{value}\"?");
                return Err(usage_error());
            }
        }
    }
    Ok(index)
}

fn make_sci(address: &[u8], port: u16) -> u64 {
    let mut bytes = [0u8; 8];
    let len = address.len().min(6);
    bytes[..len].copy_from_slice(&address[..len]);
    bytes[6..].copy_from_slice(&port.to_be_bytes());
    u64::from_be_bytes(bytes)
}

fn parse_lladdr(value: &str) -> Option<Vec<u8>> {
    if value.contains('.') {
        let address: std::net::Ipv4Addr = value.parse().ok()?;
        return Some(address.octets().to_vec());
    }
    let mut bytes = Vec::new();
    for part in value.split(':') {
        if bytes.len() == 6 {
            return None;
        }
        bytes.push(u8::from_str_radix(part, 16).ok()?);
    }
    if bytes.is_empty() { None } else { Some(bytes) }
}

fn parse_hexstring(value: &str, max_len: usize) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    let mut bytes = Vec::new();
    for chunk in value.as_bytes().chunks(2).take(max_len) {
        let text = std::str::from_utf8(chunk).ok()?;
        bytes.push(u8::from_str_radix(text, 16).ok()?);
    }
    Some(bytes)
}

fn parse_u64_base0(value: &str) -> Option<u64> {
    parse_u64_radix(value, None)
}

fn parse_u64_base16(value: &str) -> Option<u64> {
    parse_u64_radix(value, Some(16))
}

fn parse_u32_base0(value: &str) -> Option<u32> {
    parse_u64_base0(value).and_then(|value| u32::try_from(value).ok())
}

fn parse_u32_base16(value: &str) -> Option<u32> {
    parse_u64_base16(value).and_then(|value| u32::try_from(value).ok())
}

fn parse_u16_base0(value: &str) -> Option<u16> {
    parse_u64_base0(value).and_then(|value| u16::try_from(value).ok())
}

fn parse_u8_base0(value: &str) -> Option<u8> {
    parse_u64_base0(value).and_then(|value| u8::try_from(value).ok())
}

fn parse_u64_radix(value: &str, radix: Option<u32>) -> Option<u64> {
    if value.is_empty() {
        return None;
    }
    match radix {
        Some(radix) => {
            let value = value
                .strip_prefix("0x")
                .or_else(|| value.strip_prefix("0X"))
                .unwrap_or(value);
            u64::from_str_radix(value, radix).ok()
        }
        None => {
            let (radix, digits) = if let Some(hex) = value
                .strip_prefix("0x")
                .or_else(|| value.strip_prefix("0X"))
            {
                (16, hex)
            } else if value.len() > 1 && value.starts_with('0') {
                (8, &value[1..])
            } else {
                (10, value)
            };
            u64::from_str_radix(digits, radix).ok()
        }
    }
}

pub(crate) fn resolve_ifindex(name: &str) -> Result<u32, CliError> {
    let name = CString::new(name)
        .map_err(|_| CliError::from("macsec: invalid device name"))?;
    // SAFETY: `if_nametoindex()` only reads the provided C string.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        return Err(CliError {
            code: 1,
            msg: format!(
                "Device \"{}\" does not exist.",
                name.to_string_lossy()
            ),
        });
    }
    Ok(index)
}
