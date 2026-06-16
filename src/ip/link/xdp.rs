// SPDX-License-Identifier: MIT

use std::{fs, mem::size_of, slice};

use iproute_rs::CliError;
use rtnetlink::packet_route::link::LinkXdp;

const XDP_FLAGS_UPDATE_IF_NOEXIST: u32 = 1;
const XDP_FLAGS_SKB_MODE: u32 = 2;
const XDP_FLAGS_DRV_MODE: u32 = 4;
const XDP_FLAGS_HW_MODE: u32 = 8;

const BPF_PROG_LOAD: i32 = 5;
const BPF_OBJ_GET: i32 = 7;
const BPF_PROG_TYPE_XDP: u32 = 6;

#[repr(C)]
struct BpfInsn {
    code: u8,
    regs: u8,
    off: i16,
    imm: i32,
}

#[repr(C)]
struct BpfProgLoadAttr {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
}

#[repr(C)]
struct BpfObjGetAttr {
    pathname: u64,
    bpf_fd: u32,
    file_flags: u32,
}

fn bpf_syscall(cmd: i32, attr: *const u8, size: u32) -> Result<i32, CliError> {
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            cmd as libc::c_long,
            attr as libc::c_long,
            size as libc::c_long,
        )
    };
    if ret < 0 {
        Err(CliError::from(format!(
            "BPF syscall failed: {}",
            std::io::Error::last_os_error()
        )))
    } else {
        Ok(ret as i32)
    }
}

fn bpf_prog_load(
    prog_type: u32,
    insns: &[BpfInsn],
    license: &str,
    mut log_buf: Option<&mut [u8]>,
) -> Result<i32, CliError> {
    let license_bytes = license.as_bytes();
    let license_ptr = license_bytes.as_ptr();
    let insn_cnt = insns.len() as u32;
    let insns_ptr = insns.as_ptr();

    let (log_level, log_size, log_ptr) = match log_buf {
        Some(ref mut buf) => (1u32, buf.len() as u32, buf.as_mut_ptr()),
        None => (0u32, 0u32, std::ptr::null_mut()),
    };

    let attr = BpfProgLoadAttr {
        prog_type,
        insn_cnt,
        insns: insns_ptr as u64,
        license: license_ptr as u64,
        log_level,
        log_size,
        log_buf: log_ptr as u64,
        kern_version: 0,
        prog_flags: 0,
    };

    let fd = bpf_syscall(
        BPF_PROG_LOAD,
        &attr as *const BpfProgLoadAttr as *const u8,
        size_of::<BpfProgLoadAttr>() as u32,
    )?;

    Ok(fd)
}

fn bpf_obj_get(pathname: &str) -> Result<i32, CliError> {
    let resolved = pathname
        .strip_prefix("m:")
        .map(|stripped| format!("/sys/fs/bpf/{stripped}"));

    let final_path = resolved.as_deref().unwrap_or(pathname);

    let attr = BpfObjGetAttr {
        pathname: final_path.as_ptr() as u64,
        bpf_fd: 0,
        file_flags: 0,
    };

    let fd = bpf_syscall(
        BPF_OBJ_GET,
        &attr as *const BpfObjGetAttr as *const u8,
        size_of::<BpfObjGetAttr>() as u32,
    )?;

    Ok(fd)
}

#[repr(C)]
struct Elf64Ehdr {
    e_ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

#[repr(C)]
struct Elf64Shdr {
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
}

const EM_BPF: u16 = 247;
const ET_REL: u16 = 1;

fn find_elf_section<'a>(
    data: &'a [u8],
    target_name: &str,
) -> Result<&'a [u8], CliError> {
    if data.len() < size_of::<Elf64Ehdr>() || &data[..4] != b"\x7fELF" {
        return Err(CliError::from("Not a valid ELF file"));
    }
    if data[4] != 2 {
        return Err(CliError::from("Not a 64-bit ELF file"));
    }
    if data[5] != 1 {
        return Err(CliError::from("Only little-endian ELF is supported"));
    }

    let ehdr: &Elf64Ehdr = unsafe { &*(data.as_ptr() as *const Elf64Ehdr) };

    if ehdr.e_machine != EM_BPF {
        return Err(CliError::from(
            "Not a BPF ELF object file (expected e_machine = EM_BPF)",
        ));
    }
    if ehdr.e_type != ET_REL {
        return Err(CliError::from("Not a relocatable ELF object file"));
    }

    let shoff = ehdr.e_shoff as usize;
    let shnum = ehdr.e_shnum as usize;
    let shentsize = ehdr.e_shentsize as usize;
    let shstrndx = ehdr.e_shstrndx as usize;

    if shentsize != size_of::<Elf64Shdr>() {
        return Err(CliError::from("Unexpected section header entry size"));
    }

    if shoff + shnum * shentsize > data.len() {
        return Err(CliError::from("Truncated ELF file"));
    }

    let shdrs: &[Elf64Shdr] = unsafe {
        slice::from_raw_parts(
            data.as_ptr().add(shoff) as *const Elf64Shdr,
            shnum,
        )
    };

    if shstrndx >= shnum {
        return Err(CliError::from("Invalid section name string table index"));
    }

    let shstrtab_hdr = &shdrs[shstrndx];
    let shstrtab_off = shstrtab_hdr.sh_offset as usize;
    let shstrtab_size = shstrtab_hdr.sh_size as usize;
    if shstrtab_off + shstrtab_size > data.len() {
        return Err(CliError::from("Truncated string table"));
    }
    let shstrtab = &data[shstrtab_off..shstrtab_off + shstrtab_size];

    for (i, shdr) in shdrs.iter().enumerate() {
        if i == shstrndx {
            continue;
        }
        let name_off = shdr.sh_name as usize;
        let name_end = shstrtab[name_off..]
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| {
                CliError::from("Corrupt section name string table")
            })?;
        let name =
            std::str::from_utf8(&shstrtab[name_off..name_off + name_end])
                .map_err(|_| CliError::from("Invalid UTF-8 in section name"))?;

        if name == target_name {
            let sec_off = shdr.sh_offset as usize;
            let sec_size = shdr.sh_size as usize;
            if sec_off + sec_size > data.len() {
                return Err(CliError::from("Section extends beyond file"));
            }
            return Ok(&data[sec_off..sec_off + sec_size]);
        }
    }

    Err(CliError::from(format!(
        "Section '{target_name}' not found in BPF object file"
    )))
}

fn load_bpf_object(
    filename: &str,
    section: &str,
    verbose: bool,
) -> Result<i32, CliError> {
    let data = fs::read(filename).map_err(|e| {
        CliError::from(format!("Cannot read BPF object '{filename}': {e}"))
    })?;

    let prog_data = find_elf_section(&data, section)?;

    if prog_data.len() < size_of::<BpfInsn>() {
        return Err(CliError::from(format!(
            "Section '{section}' is too small to contain BPF instructions"
        )));
    }

    if prog_data.len() % size_of::<BpfInsn>() != 0 {
        return Err(CliError::from(format!(
            "Section '{section}' size is not a multiple of BPF instruction \
             size"
        )));
    }

    let insns: &[BpfInsn] = unsafe {
        slice::from_raw_parts(
            prog_data.as_ptr() as *const BpfInsn,
            prog_data.len() / size_of::<BpfInsn>(),
        )
    };

    let license_data = find_elf_section(&data, "license").ok();
    let license = license_data
        .and_then(|d| {
            let end = d.iter().position(|&b| b == 0).unwrap_or(d.len());
            std::str::from_utf8(&d[..end]).ok()
        })
        .unwrap_or("GPL");

    let mut log_buf = if verbose {
        Some(vec![0u8; 256 * 1024])
    } else {
        None
    };

    match bpf_prog_load(
        BPF_PROG_TYPE_XDP,
        insns,
        license,
        log_buf.as_deref_mut(),
    ) {
        Ok(fd) => Ok(fd),
        Err(e) => {
            if verbose && let Some(ref buf) = log_buf {
                let log_end =
                    buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
                let log_str =
                    std::str::from_utf8(&buf[..log_end]).unwrap_or("");
                if !log_str.is_empty() {
                    return Err(CliError::from(format!(
                        "BPF program load failed:\nVerifier log:\n{log_str}\n"
                    )));
                }
            }
            Err(e)
        }
    }
}

#[derive(Debug)]
pub(crate) enum XdpAction {
    Off,
    Object {
        file: String,
        section: String,
        verbose: bool,
    },
    Pinned {
        file: String,
    },
}

#[derive(Debug)]
pub(crate) struct XdpConfig {
    pub(crate) mode_flags: u32,
    pub(crate) action: XdpAction,
}

pub(crate) fn parse_xdp_args(
    iter: &mut std::iter::Peekable<std::slice::Iter<'_, String>>,
    mode_keyword: &str,
) -> Result<XdpConfig, CliError> {
    let mode_flags = match mode_keyword {
        "xdpgeneric" => XDP_FLAGS_SKB_MODE,
        "xdpdrv" => XDP_FLAGS_DRV_MODE,
        "xdpoffload" => XDP_FLAGS_HW_MODE,
        _ => 0,
    };

    let Some(next) = iter.peek() else {
        return Err(CliError::from(
            "Missing XDP action: expected 'off', 'object', or 'pinned'",
        ));
    };

    match next.as_str() {
        "off" | "none" => {
            iter.next();
            Ok(XdpConfig {
                mode_flags,
                action: XdpAction::Off,
            })
        }
        "object" | "obj" => {
            iter.next();
            let Some(file) = iter.next() else {
                return Err(CliError::from(
                    "\"object\" requires a filename argument",
                ));
            };
            let file = file.clone();
            let mut section = String::from("xdp");
            let mut verbose = false;

            loop {
                match iter.peek().map(|s| s.as_str()) {
                    Some("section") | Some("sec") => {
                        iter.next();
                        let Some(s) = iter.next() else {
                            return Err(CliError::from(
                                "\"section\" requires a name argument",
                            ));
                        };
                        section = s.clone();
                    }
                    Some("verbose") => {
                        iter.next();
                        verbose = true;
                    }
                    _ => break,
                }
            }

            Ok(XdpConfig {
                mode_flags,
                action: XdpAction::Object {
                    file,
                    section,
                    verbose,
                },
            })
        }
        "pinned" => {
            iter.next();
            let Some(file) = iter.next() else {
                return Err(CliError::from(
                    "\"pinned\" requires a filename argument",
                ));
            };
            Ok(XdpConfig {
                mode_flags,
                action: XdpAction::Pinned { file: file.clone() },
            })
        }
        _ => Err(CliError::from(format!(
            "Unknown XDP action '{}': expected 'off', 'object', or 'pinned'",
            next
        ))),
    }
}

pub(crate) fn build_xdp_attrs(
    config: &XdpConfig,
) -> Result<Vec<LinkXdp>, CliError> {
    let mut xdp = Vec::new();

    match &config.action {
        XdpAction::Off => {
            xdp.push(LinkXdp::Fd(-1));
            if config.mode_flags != 0 {
                xdp.push(LinkXdp::Flags(config.mode_flags));
            }
        }
        XdpAction::Object {
            file,
            section,
            verbose,
        } => {
            let fd = load_bpf_object(file, section, *verbose)?;
            xdp.push(LinkXdp::Fd(fd));
            let mut flags = config.mode_flags;
            flags |= XDP_FLAGS_UPDATE_IF_NOEXIST;
            xdp.push(LinkXdp::Flags(flags));
        }
        XdpAction::Pinned { file } => {
            let fd = bpf_obj_get(file)?;
            xdp.push(LinkXdp::Fd(fd));
            let mut flags = config.mode_flags;
            flags |= XDP_FLAGS_UPDATE_IF_NOEXIST;
            xdp.push(LinkXdp::Flags(flags));
        }
    }

    Ok(xdp)
}

#[cfg(test)]
mod tests {
    use std::sync::{LazyLock, Mutex};

    use super::*;

    /// Global lock ensuring BPF-related tests run sequentially.
    /// BPF operations (program load, obj get, etc.) share kernel state
    /// and can interfere when run in parallel.
    #[allow(dead_code)]
    static BPF_TEST_LOCK: LazyLock<Mutex<()>> =
        LazyLock::new(|| Mutex::new(()));

    fn to_args(input: &[&str]) -> Vec<String> {
        input.iter().map(|s| s.to_string()).collect()
    }

    fn parse_it(input: &[&str], mode: &str) -> Result<XdpConfig, CliError> {
        let args = to_args(input);
        let mut iter = args.iter().peekable();
        parse_xdp_args(&mut iter, mode)
    }

    // --- parse_xdp_args: off/none ---

    #[test]
    fn parse_xdp_off() {
        let cfg = parse_it(&["off"], "xdp").unwrap();
        assert_eq!(cfg.mode_flags, 0);
        assert!(matches!(cfg.action, XdpAction::Off));
    }

    #[test]
    fn parse_xdp_none() {
        let cfg = parse_it(&["none"], "xdp").unwrap();
        assert!(matches!(cfg.action, XdpAction::Off));
    }

    #[test]
    fn parse_xdpgeneric_off() {
        let cfg = parse_it(&["off"], "xdpgeneric").unwrap();
        assert_eq!(cfg.mode_flags, XDP_FLAGS_SKB_MODE);
        assert!(matches!(cfg.action, XdpAction::Off));
    }

    #[test]
    fn parse_xdpdrv_off() {
        let cfg = parse_it(&["off"], "xdpdrv").unwrap();
        assert_eq!(cfg.mode_flags, XDP_FLAGS_DRV_MODE);
        assert!(matches!(cfg.action, XdpAction::Off));
    }

    #[test]
    fn parse_xdpoffload_off() {
        let cfg = parse_it(&["off"], "xdpoffload").unwrap();
        assert_eq!(cfg.mode_flags, XDP_FLAGS_HW_MODE);
        assert!(matches!(cfg.action, XdpAction::Off));
    }

    // --- parse_xdp_args: object ---

    #[test]
    fn parse_xdp_object() {
        let cfg = parse_it(&["object", "file.o"], "xdp").unwrap();
        assert_eq!(cfg.mode_flags, 0);
        match &cfg.action {
            XdpAction::Object {
                file,
                section,
                verbose,
            } => {
                assert_eq!(file, "file.o");
                assert_eq!(section, "xdp");
                assert!(!verbose);
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn parse_xdp_object_with_section() {
        let cfg = parse_it(&["object", "file.o", "section", "my_prog"], "xdp")
            .unwrap();
        match &cfg.action {
            XdpAction::Object {
                file,
                section,
                verbose,
            } => {
                assert_eq!(file, "file.o");
                assert_eq!(section, "my_prog");
                assert!(!verbose);
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn parse_xdp_object_with_sec_alias() {
        let cfg =
            parse_it(&["object", "f.o", "sec", "xdp_prog"], "xdpdrv").unwrap();
        assert_eq!(cfg.mode_flags, XDP_FLAGS_DRV_MODE);
        match &cfg.action {
            XdpAction::Object { section, .. } => {
                assert_eq!(section, "xdp_prog");
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn parse_xdp_object_verbose() {
        let cfg =
            parse_it(&["object", "f.o", "verbose"], "xdpgeneric").unwrap();
        assert_eq!(cfg.mode_flags, XDP_FLAGS_SKB_MODE);
        match &cfg.action {
            XdpAction::Object { verbose, .. } => {
                assert!(verbose);
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn parse_xdp_object_section_and_verbose() {
        let cfg = parse_it(
            &["object", "f.o", "section", "xdp_prog", "verbose"],
            "xdp",
        )
        .unwrap();
        match &cfg.action {
            XdpAction::Object {
                file,
                section,
                verbose,
            } => {
                assert_eq!(file, "f.o");
                assert_eq!(section, "xdp_prog");
                assert!(verbose);
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn parse_xdp_object_missing_file() {
        let err = parse_it(&["object"], "xdp").unwrap_err();
        assert!(err.msg.contains("filename"));
    }

    #[test]
    fn parse_xdp_obj_alias() {
        let cfg = parse_it(&["obj", "f.o"], "xdp").unwrap();
        match &cfg.action {
            XdpAction::Object { file, .. } => assert_eq!(file, "f.o"),
            _ => panic!("expected Object"),
        }
    }

    // --- parse_xdp_args: pinned ---

    #[test]
    fn parse_xdp_pinned() {
        let cfg = parse_it(&["pinned", "/sys/fs/bpf/xdp_prog"], "xdp").unwrap();
        match &cfg.action {
            XdpAction::Pinned { file } => {
                assert_eq!(file, "/sys/fs/bpf/xdp_prog")
            }
            _ => panic!("expected Pinned"),
        }
    }

    #[test]
    fn parse_xdp_pinned_missing_file() {
        let err = parse_it(&["pinned"], "xdp").unwrap_err();
        assert!(err.msg.contains("filename"));
    }

    // --- parse_xdp_args: errors ---

    #[test]
    fn parse_xdp_missing_action() {
        let err = parse_it(&[], "xdp").unwrap_err();
        assert!(err.msg.contains("Missing XDP action"));
    }

    #[test]
    fn parse_xdp_unknown_action() {
        let err = parse_it(&["unknown"], "xdp").unwrap_err();
        assert!(err.msg.contains("Unknown XDP action"));
    }

    // --- find_elf_section: minimal BPF ELF ---

    fn create_test_bpf_elf() -> Vec<u8> {
        let shstrtab_data = b"\0.shstrtab\0xdp\0license\0";
        let shstrtab_size = shstrtab_data.len();

        let xdp_data: &[u8] = &[
            0xb7, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x95, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let license_data = b"GPL\0";

        let shstrtab_off = 64 + 4 * 64;
        let xdp_off = (shstrtab_off + shstrtab_size + 7) & !7;
        let license_off = xdp_off + xdp_data.len();
        let file_size = license_off + license_data.len();

        let mut elf = vec![0u8; file_size];

        // ELF64Ehdr field offsets (0-based):
        //   e_ident[16] at 0, e_type(u16) at 16, e_machine(u16) at 18,
        //   e_version(u32) at 20, e_entry(u64) at 24, e_phoff(u64) at 32,
        //   e_shoff(u64) at 40, e_flags(u32) at 48, e_ehsize(u16) at 52,
        //   e_phentsize(u16) at 54, e_phnum(u16) at 56, e_shentsize(u16) at 58,
        //   e_shnum(u16) at 60, e_shstrndx(u16) at 62
        elf[0..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[6] = 1;
        elf[16..18].copy_from_slice(&1u16.to_le_bytes());
        elf[18..20].copy_from_slice(&247u16.to_le_bytes());
        elf[20..24].copy_from_slice(&1u32.to_le_bytes());
        elf[24..32].copy_from_slice(&0u64.to_le_bytes());
        elf[32..40].copy_from_slice(&0u64.to_le_bytes());
        elf[40..48].copy_from_slice(&64u64.to_le_bytes());
        elf[48..52].copy_from_slice(&0u32.to_le_bytes());
        elf[52..54].copy_from_slice(&64u16.to_le_bytes());
        elf[54..56].copy_from_slice(&0u16.to_le_bytes());
        elf[56..58].copy_from_slice(&0u16.to_le_bytes());
        elf[58..60].copy_from_slice(&64u16.to_le_bytes());
        elf[60..62].copy_from_slice(&4u16.to_le_bytes());
        elf[62..64].copy_from_slice(&1u16.to_le_bytes());

        // Elf64Shdr field offsets (relative to section header start):
        //   sh_name(u32) at 0, sh_type(u32) at 4, sh_flags(u64) at 8,
        //   sh_addr(u64) at 16, sh_offset(u64) at 24, sh_size(u64) at 32,
        //   sh_link(u32) at 40, sh_info(u32) at 44, sh_addralign(u64) at 48,
        //   sh_entsize(u64) at 56

        // Section header 1: .shstrtab (base offset 128)
        elf[128..132].copy_from_slice(&1u32.to_le_bytes()); // sh_name
        elf[132..136].copy_from_slice(&3u32.to_le_bytes()); // sh_type = SHT_STRTAB
        elf[152..160].copy_from_slice(&(shstrtab_off as u64).to_le_bytes()); // sh_offset
        elf[160..168].copy_from_slice(&(shstrtab_size as u64).to_le_bytes()); // sh_size
        elf[176] = 1; // sh_addralign

        // Section header 2: xdp (base offset 192)
        elf[192..196].copy_from_slice(&11u32.to_le_bytes()); // sh_name
        elf[196..200].copy_from_slice(&1u32.to_le_bytes()); // sh_type = SHT_PROGBITS
        elf[200..208].copy_from_slice(&6u64.to_le_bytes()); // sh_flags
        elf[216..224].copy_from_slice(&(xdp_off as u64).to_le_bytes()); // sh_offset
        elf[224..232].copy_from_slice(&(xdp_data.len() as u64).to_le_bytes()); // sh_size
        elf[240] = 8; // sh_addralign

        // Section header 3: license (base offset 256)
        elf[256..260].copy_from_slice(&15u32.to_le_bytes()); // sh_name
        elf[260..264].copy_from_slice(&1u32.to_le_bytes()); // sh_type = SHT_PROGBITS
        elf[280..288].copy_from_slice(&(license_off as u64).to_le_bytes()); // sh_offset
        elf[288..296]
            .copy_from_slice(&(license_data.len() as u64).to_le_bytes()); // sh_size
        elf[304] = 1; // sh_addralign

        elf[shstrtab_off..shstrtab_off + shstrtab_size]
            .copy_from_slice(shstrtab_data);
        elf[xdp_off..xdp_off + xdp_data.len()].copy_from_slice(xdp_data);
        elf[license_off..license_off + license_data.len()]
            .copy_from_slice(license_data);

        elf
    }

    #[test]
    fn test_find_elf_section_xdp() {
        let elf = create_test_bpf_elf();
        let section = find_elf_section(&elf, "xdp").unwrap();
        assert_eq!(section.len(), 16);
        assert_eq!(section[0], 0xb7);
        assert_eq!(section[8], 0x95);
    }

    #[test]
    fn test_find_elf_section_license() {
        let elf = create_test_bpf_elf();
        let section = find_elf_section(&elf, "license").unwrap();
        assert_eq!(section, b"GPL\0");
    }

    #[test]
    fn test_find_elf_section_missing() {
        let elf = create_test_bpf_elf();
        let err = find_elf_section(&elf, "nonexistent").unwrap_err();
        assert!(err.msg.contains("not found"));
    }

    #[test]
    fn test_find_elf_section_invalid_magic() {
        let data = b"not an elf file";
        let err = find_elf_section(data, "xdp").unwrap_err();
        assert!(err.msg.contains("Not a valid ELF"));
    }

    #[test]
    fn test_find_elf_section_not_bpf() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(b"\x7fELF");
        data[4] = 2;
        data[5] = 1;
        data[6] = 1;
        let err = find_elf_section(&data, "xdp").unwrap_err();
        assert!(err.msg.contains("EM_BPF"));
    }

    // --- build_xdp_attrs: Off ---

    #[test]
    fn build_attrs_off_default() {
        let cfg = XdpConfig {
            mode_flags: 0,
            action: XdpAction::Off,
        };
        let attrs = build_xdp_attrs(&cfg).unwrap();
        assert_eq!(attrs.len(), 1);
        assert!(matches!(attrs[0], LinkXdp::Fd(-1)));
    }

    #[test]
    fn build_attrs_off_with_mode() {
        let cfg = XdpConfig {
            mode_flags: XDP_FLAGS_SKB_MODE,
            action: XdpAction::Off,
        };
        let attrs = build_xdp_attrs(&cfg).unwrap();
        assert_eq!(attrs.len(), 2);
        assert!(matches!(attrs[0], LinkXdp::Fd(-1)));
        assert!(
            matches!(attrs[1], LinkXdp::Flags(f) if f == XDP_FLAGS_SKB_MODE)
        );
    }
}
