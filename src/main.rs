use std::path::PathBuf;
use std::process::exit;
use authorized_keys::authorizedkeys::{get_authorized_keys_from_file};
use log::info;
use ssh_auth_log::provider::AuthLogFileProvider;
use crate::cli::{AUTH_LOG_PATH_OPTION, DEFAULT_AUTH_LOG_PATH, FILE_OPTION, get_cli_app, get_default_authorized_keys_file_path, init_logging, OLDER_THAN_DAYS_DEFAULT_VALUE, OLDER_THAN_DAYS_OPTION};
use crate::usecases::oldkeys::get_keys_older_than;

mod cli;

mod usecases;
mod logging;

#[cfg(test)]
mod tests_common;

const EXIT_CODE_ERROR: i32 = 1;

fn main() {
    let matches = get_cli_app();

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


