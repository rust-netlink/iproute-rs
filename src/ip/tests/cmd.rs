// SPDX-License-Identifier: MIT

pub(crate) fn exec_cmd(args: &[&str]) -> String {
    let output = std::process::Command::new(args[0])
        .args(&args[1..])
        .output()
        .unwrap_or_else(|e| {
            panic!("failed to execute file command {args:?}: {e}")
        });

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!("Command failed: {args:?}\nstderr: {stderr}");
    }

    String::from_utf8(output.stdout)
        .expect("Failed to convert file command output to String")
}
