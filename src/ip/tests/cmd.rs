// SPDX-License-Identifier: MIT

pub(crate) fn exec_cmd(args: &[&str]) -> String {
    String::from_utf8(
        std::process::Command::new(args[0])
            .args(&args[1..])
            .output()
            .unwrap_or_else(|_| {
                panic!("failed to execute file command {args:?}")
            })
            .stdout,
    )
    .expect("Failed to convert file command output to String")
}
