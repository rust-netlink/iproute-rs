// SPDX-License-Identifier: MIT

use std::sync::{LazyLock, Mutex};

mod common;
use self::common::{NetnsGuard, with_netns};

const VETH: &str = "test-xdp-v0";

static BPF_TEST_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

fn with_xdp_veth<T>(test: T)
where
    T: FnOnce(&NetnsGuard, &str),
{
    let _lock = BPF_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    with_netns(|ns| {
        ns.exec_cmd(&[
            "ip", "link", "add", VETH, "type", "veth", "peer", "name",
            "xdp-peer",
        ]);
        ns.exec_cmd(&["ip", "link", "set", VETH, "up"]);
        test(ns, VETH);
    });
}

fn create_bpf_obj() -> String {
    let path = "/tmp/test-xdp.o".to_string();
    let elf = create_min_bpf_elf();
    std::fs::write(&path, &elf).unwrap();
    path
}

fn create_min_bpf_elf() -> Vec<u8> {
    let shstrtab = b"\0.shstrtab\0xdp\0license\0";
    let xdp_data: &[u8] = &[
        0xb7, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x95, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];
    let license = b"GPL\0";

    let shoff = 64 + 4 * 64;
    let xoff = (shoff + shstrtab.len() + 7) & !7;
    let loff = xoff + xdp_data.len();
    let sz = loff + license.len();
    let mut e = vec![0u8; sz];

    e[0..4].copy_from_slice(b"\x7fELF");
    e[4] = 2;
    e[5] = 1;
    e[6] = 1;
    e[16..18].copy_from_slice(&1u16.to_le_bytes());
    e[18..20].copy_from_slice(&247u16.to_le_bytes());
    e[20..24].copy_from_slice(&1u32.to_le_bytes());
    e[40..48].copy_from_slice(&64u64.to_le_bytes());
    e[48..52].copy_from_slice(&0u32.to_le_bytes());
    e[52..54].copy_from_slice(&64u16.to_le_bytes());
    e[58..60].copy_from_slice(&64u16.to_le_bytes());
    e[60..62].copy_from_slice(&4u16.to_le_bytes());
    e[62..64].copy_from_slice(&1u16.to_le_bytes());

    e[128..132].copy_from_slice(&1u32.to_le_bytes());
    e[132..136].copy_from_slice(&3u32.to_le_bytes());
    e[152..160].copy_from_slice(&(shoff as u64).to_le_bytes());
    e[160..168].copy_from_slice(&(shstrtab.len() as u64).to_le_bytes());
    e[176] = 1;

    e[192..196].copy_from_slice(&11u32.to_le_bytes());
    e[196..200].copy_from_slice(&1u32.to_le_bytes());
    e[200..208].copy_from_slice(&6u64.to_le_bytes());
    e[216..224].copy_from_slice(&(xoff as u64).to_le_bytes());
    e[224..232].copy_from_slice(&(xdp_data.len() as u64).to_le_bytes());
    e[240] = 8;

    e[256..260].copy_from_slice(&15u32.to_le_bytes());
    e[260..264].copy_from_slice(&1u32.to_le_bytes());
    e[280..288].copy_from_slice(&(loff as u64).to_le_bytes());
    e[288..296].copy_from_slice(&(license.len() as u64).to_le_bytes());
    e[304] = 1;

    e[shoff..shoff + shstrtab.len()].copy_from_slice(shstrtab);
    e[xoff..xoff + xdp_data.len()].copy_from_slice(xdp_data);
    e[loff..loff + license.len()].copy_from_slice(license);
    e
}

#[test]
fn test_xdp_attach_detach_veth() {
    let obj = create_bpf_obj();
    with_xdp_veth(|ns, dev| {
        ns.ip_rs_exec_cmd(&["link", "set", dev, "xdp", "object", &obj]);
        ns.ip_rs_exec_cmd(&["link", "set", dev, "xdp", "off"]);
    });
    let _ = std::fs::remove_file(&obj);
}

#[test]
fn test_xdp_detach_without_program() {
    with_xdp_veth(|ns, dev| {
        ns.ip_rs_exec_cmd(&["link", "set", dev, "xdp", "off"]);
    });
}

#[test]
fn test_xdp_missing_file_error() {
    with_xdp_veth(|ns, dev| {
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ns.ip_rs_exec_cmd(&[
                "link",
                "set",
                dev,
                "xdp",
                "object",
                "/tmp/nonexistent.o",
            ]);
        }));
        assert!(r.is_err());
    });
}
