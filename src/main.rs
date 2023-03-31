use std::env;
use std::path::Path;
use std::path::PathBuf;
use std::process::exit;
use authorized_keys::authorizedkeys::{get_authorized_keys_from_file};
use clap::{Arg, ArgMatches, Command, value_parser};
use log::info;
use ssh_auth_log::provider::AuthLogFileProvider;
use crate::logging::get_logging_config;
use crate::usecases::oldkeys::get_keys_older_than;


mod usecases;
mod logging;

#[cfg(test)]
mod tests_common;

#[cfg(windows)]
const USER_HOME_VAR: &'static str = "USERPROFILE";

#[cfg(not(windows))]
const USER_HOME_VAR: &'static str = "HOME";

pub const LOG_LEVEL_ARGUMENT: &str = "log-level";
pub const LOG_LEVEL_DEFAULT_VALUE: &str = "off";

const SHOW_KEYS_COMMAND: &str = "show-keys";

const OLDER_THAN_DAYS_OPTION: &str = "older-than-days";
const OLDER_THAN_DAYS_DEFAULT_VALUE: usize = 31;

const AUTH_LOG_PATH_OPTION: &str = "auth-log-path";
const DEFAULT_AUTH_LOG_PATH: &str = "/var/log";

const FILE_OPTION: &str = "file-path";

const EXIT_CODE_ERROR: i32 = 1;

const VERSION: &str = "0.2.0";

fn main() {
    let matches = Command::new("akt")
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
        )

        .get_matches();

    init_logging(&matches);

    match matches.subcommand() {
        Some((SHOW_KEYS_COMMAND, cmd_matches)) => {
            info!("command: show public keys");

            let mut auth_log_path = PathBuf::from(DEFAULT_AUTH_LOG_PATH);

            if cmd_matches.contains_id(AUTH_LOG_PATH_OPTION) {
                match cmd_matches.get_one::<PathBuf>(AUTH_LOG_PATH_OPTION) {
                    Some(path_value) => auth_log_path = path_value.clone(),
                    None => {}
                }
            }

            let mut file_path = get_default_authorized_keys_file_path();

            if cmd_matches.contains_id(FILE_OPTION) {
                match cmd_matches.get_one::<PathBuf>(FILE_OPTION) {
                    Some(file_path_value) => file_path = file_path_value.clone(),
                    None => {}
                }
            }

            info!("path to authorized_keys file '{}'", file_path.display());

            if cmd_matches.contains_id(OLDER_THAN_DAYS_OPTION) {
                let older_than_days = match cmd_matches.get_one::<usize>(OLDER_THAN_DAYS_OPTION) {
                    Some(days_value) => days_value.clone(),
                    None => OLDER_THAN_DAYS_DEFAULT_VALUE
                };

                info!("older than days {older_than_days}");

                let auth_log_file_provider = AuthLogFileProvider::new(auth_log_path.as_path());
                let authorized_keys_file_path_str = format!("{}", file_path.display());

                match get_keys_older_than(&auth_log_file_provider,
                                          older_than_days,
                                          &authorized_keys_file_path_str) {
                    Ok(keys) => {
                        println!("keys for removal:");
                        keys.iter().for_each(|ak| println!("{}", ak))
                    }
                    Err(e) => {
                        eprintln!("{}", e);
                        exit(EXIT_CODE_ERROR)
                    }
                }

                exit(0)
            }

            match get_authorized_keys_from_file(&file_path) {
                Ok(keys) => {
                    keys.iter().for_each(|ak| println!("{}", ak))
                }
                Err(e) => {
                    eprintln!("{}", e);
                    exit(EXIT_CODE_ERROR)
                }
            }

        }
        _ => {}
    }
}

fn init_logging(matches: &ArgMatches) {
    let log_level: &str;

    match matches.get_one::<String>(LOG_LEVEL_ARGUMENT) {
        Some(log_level_arg) => log_level = log_level_arg,
        None => log_level = LOG_LEVEL_DEFAULT_VALUE
    }

    let logging_config = get_logging_config(log_level);
    log4rs::init_config(logging_config).expect("unable to init logging module");
}

fn get_default_authorized_keys_file_path() -> PathBuf {
    let home_var = env::var_os(USER_HOME_VAR)
        .expect(&format!("unexpected error: ${USER_HOME_VAR} variable isn't defined"));
    let home_var_str = home_var.into_string().expect(&format!("unsupported value in ${USER_HOME_VAR} variable"));

    Path::new(&home_var_str).join(".ssh").join("../proxy-user-tests/authorized_keys")
}
