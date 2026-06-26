// SPDX-License-Identifier: MIT

use iproute_rs::CliError;
use rtnetlink::{
    LinkCan, LinkMessageBuilder,
    packet_route::link::{
        CanBitTiming, CanCtrlModeFlags, InfoCan, InfoKind, LinkInfo,
    },
};
use serde::Serialize;

use super::parse::{extract_link_info, parse_on_off, parse_u16, parse_u32};
use crate::link::LinkBaseConf;

#[derive(Serialize, Default)]
pub(crate) struct CliLinkInfoDataCan {
    bitrate: Option<u32>,
    sample_point: Option<u32>,
    tq: Option<u32>,
    prop_seg: Option<u32>,
    phase_seg1: Option<u32>,
    phase_seg2: Option<u32>,
    sjw: Option<u32>,
    brp: Option<u32>,
    dbitrate: Option<u32>,
    dsample_point: Option<u32>,
    dtq: Option<u32>,
    dprop_seg: Option<u32>,
    dphase_seg1: Option<u32>,
    dphase_seg2: Option<u32>,
    dsjw: Option<u32>,
    dbrp: Option<u32>,
    restart_ms: Option<u32>,
    termination: Option<u16>,
    ctrl_flags: Option<u32>,
}

impl From<&[InfoCan]> for CliLinkInfoDataCan {
    fn from(info: &[InfoCan]) -> Self {
        let mut data = Self::default();
        for nla in info {
            match nla {
                InfoCan::BitTiming(v) => {
                    if v.bitrate != 0 {
                        data.bitrate = Some(v.bitrate);
                    }
                    if v.sample_point != 0 {
                        data.sample_point = Some(v.sample_point);
                    }
                    if v.tq != 0 {
                        data.tq = Some(v.tq);
                    }
                    if v.prop_seg != 0 {
                        data.prop_seg = Some(v.prop_seg);
                    }
                    if v.phase_seg1 != 0 {
                        data.phase_seg1 = Some(v.phase_seg1);
                    }
                    if v.phase_seg2 != 0 {
                        data.phase_seg2 = Some(v.phase_seg2);
                    }
                    if v.sjw != 0 {
                        data.sjw = Some(v.sjw);
                    }
                    if v.brp != 0 {
                        data.brp = Some(v.brp);
                    }
                }
                InfoCan::DataBitTiming(v) => {
                    if v.bitrate != 0 {
                        data.dbitrate = Some(v.bitrate);
                    }
                    if v.sample_point != 0 {
                        data.dsample_point = Some(v.sample_point);
                    }
                    if v.tq != 0 {
                        data.dtq = Some(v.tq);
                    }
                    if v.prop_seg != 0 {
                        data.dprop_seg = Some(v.prop_seg);
                    }
                    if v.phase_seg1 != 0 {
                        data.dphase_seg1 = Some(v.phase_seg1);
                    }
                    if v.phase_seg2 != 0 {
                        data.dphase_seg2 = Some(v.phase_seg2);
                    }
                    if v.sjw != 0 {
                        data.dsjw = Some(v.sjw);
                    }
                    if v.brp != 0 {
                        data.dbrp = Some(v.brp);
                    }
                }
                InfoCan::CtrlMode(v) => {
                    data.ctrl_flags = Some(v.flags.bits());
                }
                InfoCan::RestartMs(v) => {
                    data.restart_ms = Some(*v);
                }
                InfoCan::Termination(v) => {
                    data.termination = Some(*v);
                }
                _ => {}
            }
        }
        data
    }
}

impl std::fmt::Display for CliLinkInfoDataCan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(v) = self.bitrate {
            write!(f, "bitrate {v}")?;
        }
        if let Some(v) = self.sample_point {
            write!(f, " sample-point {}", v as f64 / 1000.0)?;
        }
        if let Some(v) = self.tq {
            write!(f, " tq {v}")?;
        }
        if let Some(v) = self.prop_seg {
            write!(f, " prop-seg {v}")?;
        }
        if let Some(v) = self.phase_seg1 {
            write!(f, " phase-seg1 {v}")?;
        }
        if let Some(v) = self.phase_seg2 {
            write!(f, " phase-seg2 {v}")?;
        }
        if let Some(v) = self.sjw {
            write!(f, " sjw {v}")?;
        }
        if let Some(v) = self.restart_ms {
            write!(f, " restart-ms {v}")?;
        }
        if let Some(v) = self.termination {
            write!(f, " termination {v}")?;
        }
        Ok(())
    }
}

fn apply_can_args<'a>(
    mut builder: LinkMessageBuilder<LinkCan>,
    iter: &mut impl Iterator<Item = &'a str>,
) -> Result<LinkMessageBuilder<LinkCan>, CliError> {
    let mut bt = CanBitTiming::default();
    let mut bt_set = false;
    let mut dbt = CanBitTiming::default();
    let mut dbt_set = false;
    let mut ctrl_mode_mask = CanCtrlModeFlags::empty();
    let mut ctrl_mode_flags = CanCtrlModeFlags::empty();

    while let Some(key) = iter.next() {
        match key {
            "bitrate" => {
                let v = parse_u32(next_arg(key, iter)?, "bitrate")?;
                bt.bitrate = v;
                bt_set = true;
            }
            "sample-point" => {
                let v = next_arg(key, iter)?;
                let sp = parse_sample_point(v)?;
                bt.sample_point = sp;
                bt_set = true;
            }
            "tq" => {
                bt.tq = parse_u32(next_arg(key, iter)?, "tq")?;
                bt_set = true;
            }
            "prop-seg" => {
                bt.prop_seg = parse_u32(next_arg(key, iter)?, "prop-seg")?;
                bt_set = true;
            }
            "phase-seg1" => {
                bt.phase_seg1 = parse_u32(next_arg(key, iter)?, "phase-seg1")?;
                bt_set = true;
            }
            "phase-seg2" => {
                bt.phase_seg2 = parse_u32(next_arg(key, iter)?, "phase-seg2")?;
                bt_set = true;
            }
            "sjw" => {
                bt.sjw = parse_u32(next_arg(key, iter)?, "sjw")?;
                bt_set = true;
            }
            "dbitrate" => {
                let v = parse_u32(next_arg(key, iter)?, "dbitrate")?;
                dbt.bitrate = v;
                dbt_set = true;
            }
            "dsample-point" => {
                let v = next_arg(key, iter)?;
                let sp = parse_sample_point(v)?;
                dbt.sample_point = sp;
                dbt_set = true;
            }
            "dtq" => {
                dbt.tq = parse_u32(next_arg(key, iter)?, "dtq")?;
                dbt_set = true;
            }
            "dprop-seg" => {
                dbt.prop_seg = parse_u32(next_arg(key, iter)?, "dprop-seg")?;
                dbt_set = true;
            }
            "dphase-seg1" => {
                dbt.phase_seg1 =
                    parse_u32(next_arg(key, iter)?, "dphase-seg1")?;
                dbt_set = true;
            }
            "dphase-seg2" => {
                dbt.phase_seg2 =
                    parse_u32(next_arg(key, iter)?, "dphase-seg2")?;
                dbt_set = true;
            }
            "dsjw" => {
                dbt.sjw = parse_u32(next_arg(key, iter)?, "dsjw")?;
                dbt_set = true;
            }
            "loopback" => {
                set_ctrlmode(
                    next_arg(key, iter)?,
                    &mut ctrl_mode_mask,
                    &mut ctrl_mode_flags,
                    CanCtrlModeFlags::Loopback,
                    "loopback",
                )?;
            }
            "listen-only" => {
                set_ctrlmode(
                    next_arg(key, iter)?,
                    &mut ctrl_mode_mask,
                    &mut ctrl_mode_flags,
                    CanCtrlModeFlags::ListenOnly,
                    "listen-only",
                )?;
            }
            "triple-sampling" => {
                set_ctrlmode(
                    next_arg(key, iter)?,
                    &mut ctrl_mode_mask,
                    &mut ctrl_mode_flags,
                    CanCtrlModeFlags::TripleSampling,
                    "triple-sampling",
                )?;
            }
            "one-shot" => {
                set_ctrlmode(
                    next_arg(key, iter)?,
                    &mut ctrl_mode_mask,
                    &mut ctrl_mode_flags,
                    CanCtrlModeFlags::OneShot,
                    "one-shot",
                )?;
            }
            "berr-reporting" => {
                set_ctrlmode(
                    next_arg(key, iter)?,
                    &mut ctrl_mode_mask,
                    &mut ctrl_mode_flags,
                    CanCtrlModeFlags::BerrReporting,
                    "berr-reporting",
                )?;
            }
            "fd" => {
                set_ctrlmode(
                    next_arg(key, iter)?,
                    &mut ctrl_mode_mask,
                    &mut ctrl_mode_flags,
                    CanCtrlModeFlags::Fd,
                    "fd",
                )?;
            }
            "fd-non-iso" => {
                set_ctrlmode(
                    next_arg(key, iter)?,
                    &mut ctrl_mode_mask,
                    &mut ctrl_mode_flags,
                    CanCtrlModeFlags::FdNonIso,
                    "fd-non-iso",
                )?;
            }
            "presume-ack" => {
                set_ctrlmode(
                    next_arg(key, iter)?,
                    &mut ctrl_mode_mask,
                    &mut ctrl_mode_flags,
                    CanCtrlModeFlags::PresumeAck,
                    "presume-ack",
                )?;
            }
            "cc-len8-dlc" => {
                set_ctrlmode(
                    next_arg(key, iter)?,
                    &mut ctrl_mode_mask,
                    &mut ctrl_mode_flags,
                    CanCtrlModeFlags::CcLen8Dlc,
                    "cc-len8-dlc",
                )?;
            }
            "tdc-mode" => {
                let v = next_arg(key, iter)?;
                match v {
                    "auto" => {
                        ctrl_mode_mask |= CanCtrlModeFlags::TdcAuto
                            | CanCtrlModeFlags::TdcManual;
                        ctrl_mode_flags |= CanCtrlModeFlags::TdcAuto;
                    }
                    "manual" => {
                        ctrl_mode_mask |= CanCtrlModeFlags::TdcAuto
                            | CanCtrlModeFlags::TdcManual;
                        ctrl_mode_flags |= CanCtrlModeFlags::TdcManual;
                    }
                    "off" => {
                        ctrl_mode_mask |= CanCtrlModeFlags::TdcAuto
                            | CanCtrlModeFlags::TdcManual;
                    }
                    _ => {
                        return Err(CliError::from(format!(
                            "\"tdc-mode\" must be either of \"auto\", \
                             \"manual\" or \"off\", got \"{v}\""
                        )));
                    }
                }
            }
            "restricted" => {
                set_ctrlmode(
                    next_arg(key, iter)?,
                    &mut ctrl_mode_mask,
                    &mut ctrl_mode_flags,
                    CanCtrlModeFlags::Restricted,
                    "restricted",
                )?;
            }
            "xl" => {
                set_ctrlmode(
                    next_arg(key, iter)?,
                    &mut ctrl_mode_mask,
                    &mut ctrl_mode_flags,
                    CanCtrlModeFlags::Xl,
                    "xl",
                )?;
            }
            "xtdc-mode" => {
                let v = next_arg(key, iter)?;
                match v {
                    "auto" => {
                        ctrl_mode_mask |= CanCtrlModeFlags::XlTdcAuto
                            | CanCtrlModeFlags::XlTdcManual;
                        ctrl_mode_flags |= CanCtrlModeFlags::XlTdcAuto;
                    }
                    "manual" => {
                        ctrl_mode_mask |= CanCtrlModeFlags::XlTdcAuto
                            | CanCtrlModeFlags::XlTdcManual;
                        ctrl_mode_flags |= CanCtrlModeFlags::XlTdcManual;
                    }
                    "off" => {
                        ctrl_mode_mask |= CanCtrlModeFlags::XlTdcAuto
                            | CanCtrlModeFlags::XlTdcManual;
                    }
                    _ => {
                        return Err(CliError::from(format!(
                            "\"xtdc-mode\" must be either of \"auto\", \
                             \"manual\" or \"off\", got \"{v}\""
                        )));
                    }
                }
            }
            "tms" => {
                set_ctrlmode(
                    next_arg(key, iter)?,
                    &mut ctrl_mode_mask,
                    &mut ctrl_mode_flags,
                    CanCtrlModeFlags::XlTms,
                    "tms",
                )?;
            }
            "restart-ms" => {
                let v = parse_u32(next_arg(key, iter)?, "restart-ms")?;
                builder = builder.restart_ms(v);
            }
            "restart" => {
                builder = builder.restart_ms(1);
            }
            "termination" => {
                let v = parse_u16(next_arg(key, iter)?, "termination")?;
                builder = builder.termination(v);
            }
            _ => {
                return Err(CliError::from(format!(
                    "can: unknown option \"{key}\""
                )));
            }
        }
    }

    if bt_set {
        builder = builder.bit_timing(bt);
    }
    if dbt_set {
        builder = builder.data_bit_timing(dbt);
    }
    if !ctrl_mode_mask.is_empty() {
        builder = builder.ctrl_mode(ctrl_mode_mask, ctrl_mode_flags);
    }

    Ok(builder)
}

fn next_arg<'a>(
    key: &str,
    iter: &mut impl Iterator<Item = &'a str>,
) -> Result<&'a str, CliError> {
    iter.next()
        .ok_or_else(|| CliError::from(format!("\"{key}\" requires a value")))
}

fn parse_sample_point(s: &str) -> Result<u32, CliError> {
    let sp: f64 = s.parse().map_err(|_| {
        CliError::from(format!("invalid \"sample-point\" value: {s}"))
    })?;
    if !(0.000..=0.999).contains(&sp) {
        return Err(CliError::from(format!(
            "invalid \"sample-point\" value: {s}, expected range 0.000..0.999"
        )));
    }
    Ok((sp * 1000.0) as u32)
}

fn set_ctrlmode(
    arg: &str,
    mask: &mut CanCtrlModeFlags,
    flags: &mut CanCtrlModeFlags,
    bit: CanCtrlModeFlags,
    _name: &str,
) -> Result<(), CliError> {
    let val = parse_on_off(arg)?;
    *mask |= bit;
    if val {
        *flags |= bit;
    }
    Ok(())
}

impl LinkBaseConf {
    pub(crate) fn apply_can(
        &self,
    ) -> Result<LinkMessageBuilder<LinkCan>, CliError> {
        let builder = LinkCan::new(&self.name);
        if !self.iface_specific.is_empty() {
            let mut iter = self.iface_specific.iter().map(|s| s.as_str());
            apply_can_args(builder, &mut iter)
        } else {
            Ok(builder)
        }
    }
}

pub(crate) struct IfaceCan;

impl IfaceCan {
    pub(crate) fn build_entries(
        args: &[String],
    ) -> Result<Vec<LinkInfo>, CliError> {
        let builder =
            LinkMessageBuilder::<LinkCan>::new_with_info_kind(InfoKind::Can);
        let mut iter = args.iter().map(|s| s.as_str());
        let builder = apply_can_args(builder, &mut iter)?;
        Ok(extract_link_info(builder.build()))
    }

    #[rustfmt::skip]
    pub(crate) fn print_help() -> &'static str {
        "Usage: ip link set DEVICE type can\n\
         \t[ bitrate BITRATE [ sample-point SAMPLE-POINT] ] |\n\
         \t[ tq TQ prop-seg PROP_SEG phase-seg1 PHASE-SEG1\n \
         \t  phase-seg2 PHASE-SEG2 [ sjw SJW ] ]\n\
         \n\
         \t[ dbitrate BITRATE [ dsample-point SAMPLE-POINT] ] |\n\
         \t[ dtq TQ dprop-seg PROP_SEG dphase-seg1 PHASE-SEG1\n \
         \t  dphase-seg2 PHASE-SEG2 [ dsjw SJW ] ]\n\
         \t[ tdcv TDCV tdco TDCO tdcf TDCF ]\n\
         \n\
         \t[ xbitrate BITRATE [ xsample-point SAMPLE-POINT] ] |\n\
         \t[ xtq TQ xprop-seg PROP_SEG xphase-seg1 PHASE-SEG1\n \
         \t  xphase-seg2 PHASE-SEG2 [ xsjw SJW ] ]\n\
         \t[ xtdcv TDCV xtdco TDCO xtdcf TDCF pwms PWMS pwml PWML pwmo PWMO]\n\
         \n\
         \t[ loopback { on | off } ]\n\
         \t[ listen-only { on | off } ]\n\
         \t[ triple-sampling { on | off } ]\n\
         \t[ one-shot { on | off } ]\n\
         \t[ berr-reporting { on | off } ]\n\
         \t[ fd { on | off } ]\n\
         \t[ fd-non-iso { on | off } ]\n\
         \t[ presume-ack { on | off } ]\n\
         \t[ cc-len8-dlc { on | off } ]\n\
         \t[ tdc-mode { auto | manual | off } ]\n\
         \t[ restricted { on | off } ]\n\
         \t[ xl { on | off } ]\n\
         \t[ xtdc-mode { auto | manual | off } ]\n\
         \t[ tms { on | off } ]\n\
         \n\
         \t[ restart-ms TIME-MS ]\n\
         \t[ restart ]\n\
         \n\
         \t[ termination { 0..65535 } ]\n\
         \n\
         \tWhere:\n\
         \t\tBITRATE\t\t:= { NUMBER in bps }\n\
         \t\tSAMPLE-POINT\t:= { 0.000..0.999 }\n\
         \t\tTQ\t\t:= { NUMBER in ns }\n\
         \t\tPROP-SEG\t:= { NUMBER in tq }\n\
         \t\tPHASE-SEG1\t:= { NUMBER in tq }\n\
         \t\tPHASE-SEG2\t:= { NUMBER in tq }\n\
         \t\tSJW\t\t:= { NUMBER in tq }\n\
         \t\tTDCV\t\t:= { NUMBER in mtq }\n\
         \t\tTDCO\t\t:= { NUMBER in mtq }\n\
         \t\tTDCF\t\t:= { NUMBER in mtq }\n\
         \t\tPWMS\t\t:= { NUMBER in mtq }\n\
         \t\tPWML\t\t:= { NUMBER in mtq }\n\
         \t\tPWMO\t\t:= { NUMBER in mtq }\n\
         \t\tRESTART-MS\t:= { 0 | NUMBER in ms }\n\
         \n\
         \tUnits:\n\
         \t\tbps\t:= bit per second\n\
         \t\tms\t:= millisecond\n\
         \t\tmtq\t:= minimum time quanta\n\
         \t\tns\t:= nanosecond\n\
         \t\ttq\t:= time quanta\n"
    }
}
