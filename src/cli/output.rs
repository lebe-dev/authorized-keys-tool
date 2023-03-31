use std::fmt::{Display, Formatter};
use std::process::exit;

use serde::Serialize;

use crate::EXIT_CODE_ERROR;

#[derive(Clone)]
pub enum OutputFormat {
    Default, Json
}

impl From<&str> for OutputFormat {
    fn from(value: &str) -> Self {
        let lowercase_value = value.to_lowercase();

        match lowercase_value.as_str() {
            "json" => OutputFormat::Json,
            _ => OutputFormat::Default
        }
    }
}

impl Display for OutputFormat {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self {
            OutputFormat::Json => write!(f, "json"),
            _ => write!(f, "default")
        }
    }
}

pub fn print_results(results: &mut Vec<(impl Display + Serialize)>, format: OutputFormat) {
    match format {
        OutputFormat::Json => print_as_json(results),
        _ => print_as_is(results)
    }
}

pub fn print_as_is(input: &Vec<(impl Display + Serialize)>) {
    input.iter().for_each(|i| println!("{}", i))
}

pub fn print_as_json(input: &mut Vec<(impl Display + Serialize)>) {
    match serde_json::to_string(&input) {
        Ok(json) => print!("{json}"),
        Err(e) => {
            eprintln!("{}", e);
            exit(EXIT_CODE_ERROR)
        }
    }
}