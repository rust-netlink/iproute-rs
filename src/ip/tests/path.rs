// SPDX-License-Identifier: MIT

pub(crate) fn get_ip_cli_path() -> String {
    let mut cur_exec_path =
        std::env::current_exe().expect("No current exec path");

    cur_exec_path.pop();
    cur_exec_path.pop();

    cur_exec_path
        .join("ip")
        .to_str()
        .expect("Not UTF-8 string")
        .to_string()
}
