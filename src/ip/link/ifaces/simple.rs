// SPDX-License-Identifier: MIT

pub(crate) struct IfaceDummy;

impl IfaceDummy {
    #[rustfmt::skip]
    pub(crate) fn print_help() -> &'static str {
        r"Usage: ... dummy
"
    }
}

pub(crate) struct IfaceNlmon;

impl IfaceNlmon {
    #[rustfmt::skip]
    pub(crate) fn print_help() -> &'static str {
        r"Usage: ... nlmon
"
    }
}

pub(crate) struct IfaceVcan;

impl IfaceVcan {
    #[rustfmt::skip]
    pub(crate) fn print_help() -> &'static str {
        r"Usage: ... vcan
"
    }
}

pub(crate) struct IfaceNetdevsim;

impl IfaceNetdevsim {
    #[rustfmt::skip]
    pub(crate) fn print_help() -> &'static str {
        r"Usage: ... netdevsim
"
    }
}
