// SPDX-License-Identifier: MIT

use std::sync::OnceLock;

static IS_DARK_COLOR: OnceLock<bool> = OnceLock::new();
static IS_COLOR_ENABLED: OnceLock<bool> = OnceLock::new();

const COLOR_RED: &str = "\x1b[31m";
const COLOR_GREEN: &str = "\x1b[32m";
const COLOR_YELLOW: &str = "\x1b[33m";
const COLOR_BLUE: &str = "\x1b[34m";
const COLOR_MAGENTA: &str = "\x1b[35m";
const COLOR_CYAN: &str = "\x1b[36m";
const COLOR_CLEAR: &str = "\x1b[0m";

const COLOR_BOLD_RED: &str = "\x1b[1;31m";
const COLOR_BOLD_GREEN: &str = "\x1b[1;32m";
const COLOR_BOLD_YELLOW: &str = "\x1b[1;33m";
const COLOR_BOLD_BLUE: &str = "\x1b[1;34m";
const COLOR_BOLD_MAGENTA: &str = "\x1b[1;35m";
const COLOR_BOLD_CYAN: &str = "\x1b[1;36m";

#[derive(Clone, Copy, Debug)]
pub enum CliColor {
    IfaceName,
    Mac,
    Ipv4Addr,
    Ipv6Addr,
    StateUp,
    StateDown,
    Clear,
}

impl std::fmt::Display for CliColor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if CliColor::is_color_enabled() {
            if CliColor::is_dark_color() {
                match self {
                    Self::IfaceName => write!(f, "{COLOR_BOLD_CYAN}"),
                    Self::Mac => write!(f, "{COLOR_BOLD_YELLOW}"),
                    Self::Ipv4Addr => write!(f, "{COLOR_BOLD_MAGENTA}"),
                    Self::Ipv6Addr => write!(f, "{COLOR_BOLD_BLUE}"),
                    Self::StateUp => write!(f, "{COLOR_BOLD_GREEN}"),
                    Self::StateDown => write!(f, "{COLOR_BOLD_RED}"),
                    Self::Clear => write!(f, "{COLOR_CLEAR}"),
                }
            } else {
                match self {
                    Self::IfaceName => write!(f, "{COLOR_CYAN}"),
                    Self::Mac => write!(f, "{COLOR_YELLOW}"),
                    Self::Ipv4Addr => write!(f, "{COLOR_MAGENTA}"),
                    Self::Ipv6Addr => write!(f, "{COLOR_BLUE}"),
                    Self::StateUp => write!(f, "{COLOR_GREEN}"),
                    Self::StateDown => write!(f, "{COLOR_RED}"),
                    Self::Clear => write!(f, "{COLOR_CLEAR}"),
                }
            }
        } else {
            Ok(())
        }
    }
}

impl CliColor {
    pub fn enable() {
        IS_COLOR_ENABLED.get_or_init(|| true);
    }

    fn is_color_enabled() -> bool {
        *IS_COLOR_ENABLED.get_or_init(|| false)
    }

    // Check system variable `COLORFGBG` for background color
    fn is_dark_color() -> bool {
        *IS_DARK_COLOR.get_or_init(|| {
            if let Ok(var) = std::env::var("COLORFGBG") {
                if let Some(bg_int) =
                    var.split(";").last().and_then(|s| s.parse::<u8>().ok())
                {
                    bg_int <= 6 || bg_int == 8
                } else {
                    false
                }
            } else {
                false
            }
        })
    }
}

#[macro_export]
macro_rules! write_with_color {
    ($dst:expr, $color:expr, $($arg:tt)*) => {
        write!($dst, "{}", $color)
            .and_then(|_| write!($dst, $($arg)*))
            .and_then(|_| write!($dst, "{}", CliColor::Clear))
    }
}
