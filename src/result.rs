// SPDX-License-Identifier: Apache-2.0

use std::io::Write;

use crate::CliError;

pub trait CanDisplay {
    fn gen_string(&self) -> String;
}

impl<T> CanDisplay for &[T]
where
    T: CanDisplay,
{
    fn gen_string(&self) -> String {
        let strings: Vec<String> = self.iter().map(T::gen_string).collect();
        format!("{}", strings.join("\n"))
    }
}

impl<T> CanDisplay for Vec<T>
where
    T: CanDisplay,
{
    fn gen_string(&self) -> String {
        self.as_slice().gen_string()
    }
}

impl CanDisplay for String {
    fn gen_string(&self) -> String {
        self.to_string()
    }
}

pub trait CanOutput: serde::Serialize + CanDisplay + Sized {
    fn to_cli_string(&self) -> String {
        self.gen_string()
    }

    fn to_json_string(&self) -> String {
        serde_json::to_string(self).expect("Failed to generate JSON string")
    }

    fn to_yaml_string(&self) -> String {
        serde_yaml::to_string(self).expect("Failed to generate JSON string")
    }
}

impl CanOutput for String {}

impl<T> CanOutput for &[T] where T: CanOutput + std::fmt::Display {}
impl<T> CanOutput for Vec<T> where T: CanOutput + std::fmt::Display {}

pub fn print_result_and_exit<T>(result: Result<T, CliError>, fmt: OutputFormat)
where
    T: CanOutput,
{
    match result {
        Ok(s) => {
            let mut stdout = std::io::stdout();
            let output = match fmt {
                OutputFormat::Cli => s.to_cli_string(),
                OutputFormat::Json => serde_json::to_string(&s)
                    .expect("Failed to generate JSON string"),
                OutputFormat::Yaml => serde_yaml::to_string(&s)
                    .expect("Failed to generate YAML string"),
            };
            writeln!(stdout, "{output}").ok();
            std::process::exit(0);
        }
        Err(e) => {
            let mut stderr = std::io::stderr();
            writeln!(stderr, "{e}").ok();
            std::process::exit(e.code);
        }
    }
}

#[derive(Copy, Clone, Default, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum OutputFormat {
    #[default]
    Cli,
    Yaml,
    Json,
}
