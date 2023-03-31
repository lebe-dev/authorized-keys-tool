use std::env;
use std::path::{Path, PathBuf};

use clap::{Arg, ArgMatches, Command, value_parser};

use crate::cli::output::OutputFormat;
use crate::logging::get_logging_config;

pub mod output;

const USER_HOME_VAR: &'static str = "HOME";

pub const LOG_LEVEL_ARGUMENT: &str = "log-level";
pub const LOG_LEVEL_DEFAULT_VALUE: &str = "off";

pub const SHOW_KEYS_COMMAND: &str = "show-keys";

pub const OLDER_THAN_DAYS_OPTION: &str = "older-than-days";
pub const OLDER_THAN_DAYS_DEFAULT_VALUE: usize = 31;

pub const AUTH_LOG_PATH_OPTION: &str = "auth-log-path";
pub const DEFAULT_AUTH_LOG_PATH: &str = "/var/log";

pub const FILE_OPTION: &str = "file-path";

pub const FORMAT_OPTION: &str = "format";

const VERSION: &str = "0.2.0";

pub fn get_cli_app() -> ArgMatches {
    Command::new("akt")
        .about("Authorized Keys Tool for SSH")
        .version(VERSION)
        .subcommand_required(true)
        .arg_required_else_help(true)

        .arg(
            Arg::new(LOG_LEVEL_ARGUMENT)
                .help("set logging level. possible values: debug, info, error, warn, trace")
                .long(LOG_LEVEL_ARGUMENT)
                .default_value(LOG_LEVEL_DEFAULT_VALUE)
        )

        .subcommand(
            Command::new(SHOW_KEYS_COMMAND)
                .about("Show keys which used older than days")
                .arg(
                    Arg::new(OLDER_THAN_DAYS_OPTION)
                        .help("set days")
                        .value_parser(value_parser!(usize))
                        .long(OLDER_THAN_DAYS_OPTION)
                        .required(false)
                )
                .arg(
                    Arg::new(AUTH_LOG_PATH_OPTION)
                        .help("set path to auth logs")
                        .value_parser(value_parser!(PathBuf))
                        .long(AUTH_LOG_PATH_OPTION)
                        .default_value(DEFAULT_AUTH_LOG_PATH)
                        .required(false)
                )
                .arg(
                    Arg::new(FILE_OPTION)
                        .help("set path to authorized_keys file")
                        .value_parser(value_parser!(PathBuf))
                        .long(FILE_OPTION)
                        .required(false)
                )

                .arg(
                    Arg::new(FORMAT_OPTION)
                        .help("set output format. Possible values: default, json")
                        .long(FORMAT_OPTION)
                        .value_parser(value_parser!(OutputFormat))
                        .required(false)
                )
        )

        .get_matches()
}

pub fn init_logging(matches: &ArgMatches) {
    let log_level: &str;

    match matches.get_one::<String>(LOG_LEVEL_ARGUMENT) {
        Some(log_level_arg) => log_level = log_level_arg,
        None => log_level = LOG_LEVEL_DEFAULT_VALUE
    }

    let logging_config = get_logging_config(log_level);
    log4rs::init_config(logging_config).expect("unable to init logging module");
}

pub fn get_default_authorized_keys_file_path() -> PathBuf {
    let home_var = env::var_os(USER_HOME_VAR)
        .expect(&format!("unexpected error: ${USER_HOME_VAR} variable isn't defined"));
    let home_var_str = home_var.into_string().expect(&format!("unsupported value in ${USER_HOME_VAR} variable"));

    Path::new(&home_var_str).join(".ssh").join("authorized_keys")
}