// SPDX-License-Identifier: MIT

use std::{
    hash::{DefaultHasher, Hash, Hasher as _},
    process::Command,
};

pub struct NetnsGuard {
    pub name: String,
}

impl NetnsGuard {
    fn new() -> Self {
        let mut hasher = DefaultHasher::new();
        std::thread::current().id().hash(&mut hasher);
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            .hash(&mut hasher);
        let name = format!("test_ns_{}", hasher.finish(),);
        assert!(
            Command::new("ip")
                .args(["netns", "add", &name])
                .status()
                .expect("failed to create netns")
                .success()
        );
        // std::thread::sleep(std::time::Duration::from_secs(5));
        Self { name }
    }

    pub fn exec_cmd(&self, args: &[&str]) -> String {
        let mut full_args = vec!["netns", "exec", &self.name];
        full_args.extend_from_slice(args);
        let output = Command::new("ip")
            .args(&full_args)
            .output()
            .unwrap_or_else(|e| {
                panic!("failed to execute command {args:?}: {e}")
            });

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            panic!("Command failed: {args:?}\nstderr: {stderr}");
        }

        String::from_utf8(output.stdout)
            .expect("Failed to convert command output to String")
    }

    pub fn ip_rs_exec_cmd(&self, args: &[&str]) -> String {
        let mut cur_exec_path =
            std::env::current_exe().expect("No current exec path");
        cur_exec_path.pop();
        cur_exec_path.pop();

        let ip_rs_pathbuf = cur_exec_path.join("ip");
        let ip_rs_path = ip_rs_pathbuf.to_str().expect("Not UTF-8 string");

        let mut full_args = vec!["netns", "exec", &self.name];
        full_args.push(ip_rs_path);
        full_args.extend_from_slice(args);

        let output = Command::new("ip")
            .args(&full_args)
            .output()
            .unwrap_or_else(|e| {
                panic!("failed to execute ip-rs command {args:?}: {e}")
            });

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            panic!("Command failed: {args:?}\nstderr: {stderr}");
        }

        String::from_utf8(output.stdout)
            .expect("Failed to convert command output to String")
    }

    pub fn assert_alias_output(
        &self,
        expected_args: &[&str],
        alias_args: &[&str],
    ) {
        let expected_output = self.ip_rs_exec_cmd(expected_args);
        let our_output = self.ip_rs_exec_cmd(alias_args);
        pretty_assertions::assert_eq!(expected_output, our_output);
    }
}

impl Drop for NetnsGuard {
    fn drop(&mut self) {
        Command::new("ip")
            .args(["netns", "del", &self.name])
            .status()
            .ok();
    }
}

pub(crate) fn with_netns<T>(f: impl FnOnce(&NetnsGuard) -> T) -> T {
    let guard = NetnsGuard::new();
    f(&guard)
}
