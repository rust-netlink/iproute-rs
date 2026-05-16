// SPDX-License-Identifier: MIT

pub(crate) fn exec_cmd(args: &[&str]) -> String {
    let output = std::process::Command::new(args[0])
        .args(&args[1..])
        .output()
        .unwrap_or_else(|e| panic!("failed to execute command {args:?}: {e}"));

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!("Command failed: {args:?}\nstderr: {stderr}");
    }

    String::from_utf8(output.stdout)
        .expect("Failed to convert command output to String")
}

pub(crate) fn assert_alias_output(expected_args: &[&str], alias_args: &[&str]) {
    let expected_output = ip_rs_exec_cmd(expected_args);
    let our_output = ip_rs_exec_cmd(alias_args);
    pretty_assertions::assert_eq!(expected_output, our_output);
}

pub(crate) fn ip_rs_exec_cmd(args: &[&str]) -> String {
    let mut cur_exec_path =
        std::env::current_exe().expect("No current exec path");

    cur_exec_path.pop();
    cur_exec_path.pop();

    let output = std::process::Command::new(
        cur_exec_path.join("ip").to_str().expect("Not UTF-8 string"),
    )
    .args(args)
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
