// SPDX-License-Identifier: MIT

use iproute_rs::CliError;
use rtnetlink::{
    LinkMacSec, LinkMessageBuilder,
    packet_route::link::{
        InfoMacSec, MacSecCipherId, MacSecOffload, MacSecValidate,
    },
};
use serde::Serialize;

use super::parse::{parse_on_off_01, parse_u8, parse_u32};
use crate::link::LinkBaseConf;

#[derive(Serialize, Default)]
pub(crate) struct CliLinkInfoDataMacSec {
    #[serde(skip_serializing_if = "Option::is_none")]
    sci: Option<String>,
    #[serde(skip_serializing_if = "is_false")]
    protect: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    cipher_suite: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    icv_len: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    encoding_sa: Option<u8>,
    #[serde(skip_serializing_if = "String::is_empty")]
    validation: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    offload: String,
    #[serde(skip_serializing_if = "is_false")]
    encrypt: bool,
    #[serde(skip_serializing_if = "is_false", rename = "inc_sci")]
    send_sci: bool,
    #[serde(skip_serializing_if = "is_false")]
    es: bool,
    #[serde(skip_serializing_if = "is_false")]
    scb: bool,
    #[serde(skip_serializing_if = "is_false", rename = "replay_protect")]
    replay: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    window: Option<u32>,
}

fn is_false(v: &bool) -> bool {
    !*v
}

fn cipher_id_to_name(cs: &MacSecCipherId) -> &'static str {
    match cs {
        #[allow(deprecated)]
        MacSecCipherId::DefaultGcmAes128 => "GCM-AES-128",
        MacSecCipherId::GcmAes128 => "GCM-AES-128",
        MacSecCipherId::GcmAes256 => "GCM-AES-256",
        MacSecCipherId::GcmAesXpn128 => "GCM-AES-XPN-128",
        MacSecCipherId::GcmAesXpn256 => "GCM-AES-XPN-256",
        _ => "(unknown)",
    }
}

fn validate_to_str(v: &MacSecValidate) -> &'static str {
    match v {
        MacSecValidate::Disabled => "disabled",
        MacSecValidate::Check => "check",
        MacSecValidate::Strict => "strict",
        _ => "(unknown)",
    }
}

fn offload_to_str(v: &MacSecOffload) -> &'static str {
    match v {
        MacSecOffload::Off => "off",
        MacSecOffload::Phy => "phy",
        MacSecOffload::Mac => "mac",
        _ => "(unknown)",
    }
}

impl From<&[InfoMacSec]> for CliLinkInfoDataMacSec {
    fn from(info: &[InfoMacSec]) -> Self {
        let mut sci = None;
        let mut protect = false;
        let mut cipher_suite = String::new();
        let mut icv_len = None;
        let mut encoding_sa = None;
        let mut validation = String::new();
        let mut offload = String::new();
        let mut encrypt = false;
        let mut send_sci = false;
        let mut es = false;
        let mut scb = false;
        let mut replay = false;
        let mut window = None;

        for nla in info {
            match nla {
                InfoMacSec::Sci(v) => {
                    sci = Some(format!("{:016x}", v.to_be()));
                }
                InfoMacSec::Port(_) => {}
                InfoMacSec::IcvLen(v) => icv_len = Some(*v),
                InfoMacSec::CipherSuite(v) => {
                    cipher_suite = cipher_id_to_name(v).to_string();
                }
                InfoMacSec::Window(v) => window = Some(*v),
                InfoMacSec::EncodingSa(v) => encoding_sa = Some(*v),
                InfoMacSec::Encrypt(v) => encrypt = *v != 0,
                InfoMacSec::Protect(v) => protect = *v != 0,
                InfoMacSec::IncSci(v) => send_sci = *v != 0,
                InfoMacSec::Es(v) => es = *v != 0,
                InfoMacSec::Scb(v) => scb = *v != 0,
                InfoMacSec::ReplayProtect(v) => replay = *v != 0,
                InfoMacSec::Validation(v) => {
                    validation = validate_to_str(v).to_string();
                }
                InfoMacSec::Offload(v) => {
                    offload = offload_to_str(v).to_string();
                }
                _ => {}
            }
        }

        Self {
            sci,
            protect,
            cipher_suite,
            icv_len,
            encoding_sa,
            validation,
            offload,
            encrypt,
            send_sci,
            es,
            scb,
            replay,
            window,
        }
    }
}

impl std::fmt::Display for CliLinkInfoDataMacSec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut sep = "";
        if let Some(v) = &self.sci {
            write!(f, "{sep}sci {v}")?;
            sep = " ";
        }
        write!(
            f,
            "{sep}protect {}",
            if self.protect { "on" } else { "off" }
        )?;
        sep = " ";
        if !self.cipher_suite.is_empty() {
            write!(f, "{sep}cipher {}", self.cipher_suite)?;
        }
        if let Some(v) = self.icv_len {
            write!(f, "{sep}icvlen {v}")?;
        }
        if let Some(v) = self.encoding_sa {
            write!(f, "{sep}encodingsa {v}")?;
        }
        if !self.validation.is_empty() {
            write!(f, "{sep}validate {}", self.validation)?;
        }
        if !self.offload.is_empty() {
            write!(f, "{sep}offload {}", self.offload)?;
        }
        write!(
            f,
            "{sep}encrypt {} send_sci {} end_station {} scb {} replay {}",
            if self.encrypt { "on" } else { "off" },
            if self.send_sci { "on" } else { "off" },
            if self.es { "on" } else { "off" },
            if self.scb { "on" } else { "off" },
            if self.replay { "on" } else { "off" },
        )?;
        if let Some(v) = self.window {
            write!(f, " window {v}")?;
        }
        Ok(())
    }
}

impl LinkBaseConf {
    pub(crate) async fn apply_macsec(
        &self,
        handle: &rtnetlink::Handle,
    ) -> Result<LinkMessageBuilder<LinkMacSec>, CliError> {
        let link_name = self
            .link
            .as_deref()
            .ok_or_else(|| CliError::from("MACSEC requires link device"))?;

        let link_ifindex = self.get_ifindex_by_name(handle, link_name).await?;

        let mut builder = LinkMessageBuilder::<LinkMacSec>::new(&self.name)
            .link(link_ifindex);

        let mut iter = self.iface_specific.iter();
        while let Some(key) = iter.next() {
            match key.as_str() {
                "sci" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "MACSEC sci requires a value",
                        ));
                    };
                    let val =
                        u64::from_str_radix(v.trim_start_matches("0x"), 16)
                            .map_err(|_| {
                                CliError::from(format!(
                                    "Invalid MACSEC sci: {v}"
                                ))
                            })?;
                    builder = builder.sci(val.to_be());
                }
                "port" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "MACSEC port requires a value",
                        ));
                    };
                    let val: u16 = v.parse().map_err(|_| {
                        CliError::from(format!("Invalid MACSEC port: {v}"))
                    })?;
                    builder = builder.port(val);
                }
                "cipher" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "MACSEC cipher requires a value",
                        ));
                    };
                    let val = match v.as_str() {
                        "default" => {
                            #[allow(deprecated)]
                            let v = MacSecCipherId::DefaultGcmAes128;
                            v
                        }
                        "gcm-aes-128" | "GCM-AES-128" => {
                            MacSecCipherId::GcmAes128
                        }
                        "gcm-aes-256" | "GCM-AES-256" => {
                            MacSecCipherId::GcmAes256
                        }
                        "gcm-aes-xpn-128" | "GCM-AES-XPN-128" => {
                            MacSecCipherId::GcmAesXpn128
                        }
                        "gcm-aes-xpn-256" | "GCM-AES-XPN-256" => {
                            MacSecCipherId::GcmAesXpn256
                        }
                        _ => {
                            return Err(CliError::from(format!(
                                "Unknown MACSEC cipher: {v}, supported: \
                                 default, gcm-aes-128, gcm-aes-256, \
                                 gcm-aes-xpn-128, gcm-aes-xpn-256"
                            )));
                        }
                    };
                    builder = builder.cipher_suite(val);
                }
                "icvlen" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "MACSEC icvlen requires a value",
                        ));
                    };
                    let val = parse_u8(v, "MACSEC icvlen")?;
                    builder = builder.icv_len(val);
                }
                "encrypt" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "MACSEC encrypt requires a value",
                        ));
                    };
                    let val = parse_on_off_01(v)?;
                    builder = builder.encrypt(val);
                }
                "send_sci" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "MACSEC send_sci requires a value",
                        ));
                    };
                    let val = parse_on_off_01(v)?;
                    builder = builder.inc_sci(val);
                }
                "end_station" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "MACSEC end_station requires a value",
                        ));
                    };
                    let val = parse_on_off_01(v)?;
                    builder = builder.es(val);
                }
                "scb" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "MACSEC scb requires a value",
                        ));
                    };
                    let val = parse_on_off_01(v)?;
                    builder = builder.scb(val);
                }
                "protect" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "MACSEC protect requires a value",
                        ));
                    };
                    let val = parse_on_off_01(v)?;
                    builder = builder.protect(val);
                }
                "replay" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "MACSEC replay requires a value",
                        ));
                    };
                    let val = parse_on_off_01(v)?;
                    builder = builder.replay_protect(val);
                    if val
                        && iter.len() > 0
                        && iter.clone().next() == Some(&"window".to_string())
                    {
                        iter.next();
                        let Some(w) = iter.next() else {
                            return Err(CliError::from(
                                "MACSEC window requires a value",
                            ));
                        };
                        let win = parse_u32(w, "MACSEC window")?;
                        builder = builder.window(win);
                    }
                }
                "window" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "MACSEC window requires a value",
                        ));
                    };
                    let val = parse_u32(v, "MACSEC window")?;
                    builder = builder.window(val);
                }
                "validate" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "MACSEC validate requires a value",
                        ));
                    };
                    let val = match v.as_str() {
                        "disabled" => MacSecValidate::Disabled,
                        "check" => MacSecValidate::Check,
                        "strict" => MacSecValidate::Strict,
                        _ => {
                            return Err(CliError::from(format!(
                                "Unknown MACSEC validate: {v}, supported: \
                                 disabled, check, strict"
                            )));
                        }
                    };
                    builder = builder.validation(val);
                }
                "encodingsa" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "MACSEC encodingsa requires a value",
                        ));
                    };
                    let val: u8 = v.parse().map_err(|_| {
                        CliError::from(format!(
                            "Invalid MACSEC encodingsa: {v}"
                        ))
                    })?;
                    if val > 3 {
                        return Err(CliError::from(format!(
                            "MACSEC encodingsa must be 0-3, got {v}"
                        )));
                    }
                    builder = builder.encoding_sa(val);
                }
                "offload" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "MACSEC offload requires a value",
                        ));
                    };
                    let val = match v.as_str() {
                        "off" => MacSecOffload::Off,
                        "phy" => MacSecOffload::Phy,
                        "mac" => MacSecOffload::Mac,
                        _ => {
                            return Err(CliError::from(format!(
                                "Unknown MACSEC offload: {v}, supported: off, \
                                 phy, mac"
                            )));
                        }
                    };
                    builder = builder.offload(val);
                }
                "address" => {
                    let Some(_v) = iter.next() else {
                        return Err(CliError::from(
                            "MACSEC address requires a value",
                        ));
                    };
                }
                _ => {
                    return Err(CliError::from(format!(
                        "Unknown MACSEC argument: {key}"
                    )));
                }
            }
        }

        Ok(builder)
    }
}

pub(crate) struct IfaceMacSec;

impl IfaceMacSec {
    #[rustfmt::skip]
    pub(crate) fn print_help() -> &'static str {
        r"Usage: ... macsec [ [ address <lladdr> ] port { 1..2^16-1 } | sci <u64> ]
                  [ cipher { default | gcm-aes-128 | gcm-aes-256 | gcm-aes-xpn-128 | gcm-aes-xpn-256 } ]
                  [ icvlen { 8..16 } ]
                  [ encrypt { on | off } ]
                  [ send_sci { on | off } ]
                  [ end_station { on | off } ]
                  [ scb { on | off } ]
                  [ protect { on | off } ]
                  [ replay { on | off} window { 0..2^32-1 } ]
                  [ validate { strict | check | disabled } ]
                  [ encodingsa { 0..3 } ]
                  [ offload { mac | phy | off } ]
"
    }
}
