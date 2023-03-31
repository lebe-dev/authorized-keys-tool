use std::collections::HashMap;
use std::path::Path;

use authorized_keys::authorizedkeys::{AuthorizedKey, get_authorized_keys_from_file};
use chrono::{Local, NaiveDateTime};
use log::{debug, error, info};
use openssh_keys::PublicKey;
use ssh_auth_log::{get_login_with_key_attempts, KeyLoginAttempt};
use ssh_auth_log::provider::AuthLogsProvider;
use ssh_fingerprint_rs::{get_public_key_fingerprints_from_file, PublicKeyFingerprint};

/// 1. Loads all success login attempts with public keys
/// 2. Returns key used older than X days (`days_threshold`)
pub fn get_keys_older_than(auth_logs_provider: &impl AuthLogsProvider,
                           days_threshold: usize,
                           authorized_keys_file_path: &str) -> anyhow::Result<Vec<AuthorizedKey>> {
    info!("get public keys older than {days_threshold} day(s)");
    debug!("authorized_keys path '{authorized_keys_file_path}'");

    let attempts = get_login_with_key_attempts(auth_logs_provider)?;
    info!("success login attempts received: {}", attempts.len());

    let actual_fingerprints = get_public_key_fingerprints_from_file(&authorized_keys_file_path)?;

    let attempts_map: HashMap<String, KeyLoginAttempt> = get_attempts_map(&attempts, &actual_fingerprints);

    let authorized_keys_path = Path::new(authorized_keys_file_path);

    let authorized_keys = get_authorized_keys_from_file(&authorized_keys_path)?;
    debug!("authorized keys {}", authorized_keys.len());

    let candidates_for_removal: Vec<AuthorizedKey> = get_key_candidates_for_removal(
        &authorized_keys, &attempts_map, days_threshold as u64);

    Ok(candidates_for_removal)
}

/// Collects latest attempts by key (fingerprint).
fn get_attempts_map(attempts: &Vec<KeyLoginAttempt>,
                    actual_fingerprints: &Vec<PublicKeyFingerprint>) -> HashMap<String, KeyLoginAttempt> {

    let mut attempts_map: HashMap<String, KeyLoginAttempt> = HashMap::new();

    for login_attempt in attempts {
        let fingerprint_found = actual_fingerprints.iter()
            .find(|af| af.fingerprint == login_attempt.fingerprint);

        if fingerprint_found.is_some() {
            info!("fingerprint '{}' from auth log was found in authorized_keys file",
                                login_attempt.fingerprint);

            let key = login_attempt.fingerprint.to_string();

            if attempts_map.contains_key(&key) {
                if let Some(saved_login_attempt) = attempts_map.get(&key) {
                    if saved_login_attempt.timestamp < login_attempt.timestamp {
                        attempts_map.insert(key, login_attempt.clone());
                    }
                }

            } else {
                attempts_map.insert(key, login_attempt.clone());
            }

        } else {
            info!("fingerprint '{}' from auth log wasn't found in authorized_keys file",
                                login_attempt.fingerprint);
        }
    }

    attempts_map
}

fn get_key_candidates_for_removal(authorized_keys: &Vec<AuthorizedKey>,
                                  attempts_map: &HashMap<String, KeyLoginAttempt>,
                                  days_threshold: u64) -> Vec<AuthorizedKey> {
    info!("get key candidates for removal, days threshold: {days_threshold}");
    debug!("authorized keys: {}", authorized_keys.len());
    debug!("attempts map: {}", attempts_map.len());
    let key_days_threshold = days_threshold as i64;

    let mut candidates_for_removal: Vec<AuthorizedKey> = vec![];

    let now: NaiveDateTime = Local::now().naive_local();

    for authorized_key in authorized_keys {
        let authorized_key_str = format!("{}", authorized_key);

        if let Ok(public_key) = PublicKey::parse(&authorized_key_str) {
            let actual_fingerprint = format!("{}", public_key.fingerprint());

            if attempts_map.contains_key(&actual_fingerprint) {
                if let Some(latest_login_attempt) = &attempts_map.get(&actual_fingerprint) {

                    let since = now.signed_duration_since(latest_login_attempt.timestamp);
                    info!("duration since from now: {}", since.num_seconds());

                    if since.num_days() > key_days_threshold {
                        debug!("since days {}", since.num_days());
                        if !candidates_for_removal.contains(authorized_key) {
                            candidates_for_removal.push(authorized_key.clone());
                            info!("key with fingerprint '{actual_fingerprint}' was added to candidate list");
                        }
                    }

                } else {
                    info!("key with fingerprint '{actual_fingerprint}' wasn't found in auth logs, so it's candidate for removal");
                    candidates_for_removal.push(authorized_key.clone())
                }
            }

        } else {
            error!("unable to parse key: '{authorized_key_str}'")
        }

    }

    candidates_for_removal
}

#[cfg(test)]
mod candidate_for_removal_tests {
    use std::collections::HashMap;

    use authorized_keys::authorizedkeys::AuthorizedKey;
    use openssh_keys::PublicKey;
    use ssh_auth_log::KeyLoginAttempt;

    use crate::tests_common::{get_key_login_attempt, get_random_string, init_logging};
    use crate::tests_common::time::get_datetime_from_now;
    use crate::usecases::oldkeys::get_key_candidates_for_removal;

    #[test]
    fn return_keys_beyond_specified_threshold() {
        init_logging();

        let auth_key1 = get_authorized_key1();
        let auth_key2 = get_authorized_key2();
        let auth_key3 = get_authorized_key3();

        let fingerprint1 = get_fingerprint(&auth_key1);
        let fingerprint2 = get_fingerprint(&auth_key2);
        let fingerprint3 = get_fingerprint(&auth_key3);

        let auth_keys = vec![auth_key1.clone(), auth_key2.clone(), auth_key3.clone()];

        let mut attempts_map: HashMap<String, KeyLoginAttempt> = HashMap::new();

        let ten_days_before = get_datetime_from_now(10);
        let attempt5 = get_key_login_attempt(&ten_days_before, &fingerprint1);
        attempts_map.insert(fingerprint1.clone(), attempt5);

        let five_days_before = get_datetime_from_now(5);
        let attempt1 = get_key_login_attempt(&five_days_before, &fingerprint1);
        attempts_map.insert(fingerprint1.clone(), attempt1);

        let two_days_before = get_datetime_from_now(2);
        let attempt2 = get_key_login_attempt(&two_days_before, &fingerprint1);
        attempts_map.insert(fingerprint1.clone(), attempt2);

        let one_days_before = get_datetime_from_now(1);
        let attempt3 = get_key_login_attempt(&one_days_before, &fingerprint1);
        attempts_map.insert(fingerprint1.clone(), attempt3);

        let eight_days_before = get_datetime_from_now(8);
        let attempt6 = get_key_login_attempt(&eight_days_before, &fingerprint2);
        attempts_map.insert(fingerprint2.clone(), attempt6);

        let eleven_days_before = get_datetime_from_now(11);
        let attempt7 = get_key_login_attempt(&eleven_days_before, &fingerprint3);
        attempts_map.insert(fingerprint3.clone(), attempt7);

        let results = get_key_candidates_for_removal(&auth_keys, &attempts_map, 2);

        assert_eq!(results.len(), 2);

        assert!(!results.contains(&auth_key1));
        assert!(results.contains(&auth_key2));
        assert!(results.contains(&auth_key3));
    }

    fn get_authorized_key1() -> AuthorizedKey {
        AuthorizedKey {
            key_type: "ssh-rsa".to_string(),
            key: "AAAAB3NzaC1yc2EAAAADAQABAAABgQDAd6jIpyOMz50jtD+7FrKhQ3yzYjZTr0zCixTHDTZ2w2nEcrnkGqF/2L1HAiYVv1kub/GlL8po1gv7CwOE4O2F5VwtSNco84YEcl8zL7tTKJCdmOVqajvFtRmYP6vQQ8q1ffODlky7u98HkQN/Pgu+zCd1D104Tx3bpPJoFOGfn3nZm5b3zTgM2Ie2qJwyRHdvJwmtJtmf6IAG9XF1GdzPJ15U6g/7SndvfGX++KodYZzSUWsbLDxC0Vpr4nH1+C8JIWApUFXTTKCSyoSm3hmDSXrreOkmMSltVHj8SQYFNmMeMRMvKZwmqi6RMC5AXock4gFxzaxCsDtqrfc4MYb9UE/uUiSeyQ2GSjW6soq+9K/+s8nmCnzxGTuM7gwGG1Ada7qgIrLAHKdQyiDX9/wwwi7Nax8OO3+orWJjfQymoHL3/aYEhXE0c2pscAeYaB6iiw+UkvTUSJ0nun9bjR8jY3iS0DUM4jYSkKaVGl2/kOv/fZdf4I+cCuHs/0stREc=".to_string(),
            id: get_random_string(),
            row_index: 0,
        }
    }

    fn get_authorized_key2() -> AuthorizedKey {
        AuthorizedKey {
            key_type: "ssh-ed25519".to_string(),
            key: "AAAAC3NzaC1lZDI1NTE5AAAAIDOGSbgN43gI+oP5CebK7JsGWsMT69uymML4YHWUPI2G".to_string(),
            id: get_random_string(),
            row_index: 0,
        }
    }

    fn get_authorized_key3() -> AuthorizedKey {
        AuthorizedKey {
            key_type: "ssh-rsa".to_string(),
            key: "AAAAB3NzaC1yc2EAAAABIwAAAQEA57gP/iLw2reMq2Yqzd/GShYfK1+6YPktMkJesy5DKQGYiv8ncgR5UslTKbTcUUAtVn5Dq73T/HHXrH7n1iK8yrLCbBc8Es856OvBkSDDLA8iemZwWknTPe0zbUxV6waWub2Ynx+6L8ZeYiOUhw9w0H5pXJhUwmKNu+SDYMTAn4dBkn8sjNUFMlgZRla3lML0/HUyJSX3KskXuUJ6lT98pQ6zGhsaHRkMai7bu+Q9/4/8nFiVZ2rzYAR97fMTvmlM2sWYtvV71d9u1urg2Gbuh4k0xW6OvdScoaIM0GGU81mKWE4F3D7KKmvAGPKYyfwaqtzXAKIsu9ZSpXYE5fPIVQ==".to_string(),
            id: get_random_string(),
            row_index: 0,
        }
    }

    fn get_fingerprint(authorized_key: &AuthorizedKey) -> String {
        let authorized_key_str = format!("{}", authorized_key);
        let key = PublicKey::parse(&authorized_key_str).unwrap();

        key.fingerprint()
    }

}

#[cfg(test)]
mod attempts_map_tests {
    use crate::tests_common::{get_key_login_attempt, get_public_key_fingerprint, get_random_string};
    use crate::tests_common::time::get_datetime_from_now;
    use crate::usecases::oldkeys::get_attempts_map;

    #[test]
    fn fingerprint_record_should_contain_the_latest_timestamp() {
        let fingerprint = get_random_string();

        let five_days_before = get_datetime_from_now(5);
        let three_days_before = get_datetime_from_now(3);
        let one_day_before = get_datetime_from_now(1);

        let attempt1 = get_key_login_attempt(&three_days_before, &fingerprint);
        let attempt2 = get_key_login_attempt(&five_days_before, &fingerprint);
        let attempt3 = get_key_login_attempt(&one_day_before, &fingerprint);

        let attempts = vec![attempt1, attempt2, attempt3.clone()];

        let fingerprints = vec![get_public_key_fingerprint(&fingerprint)];

        let attempts_map = get_attempts_map(&attempts, &fingerprints);

        assert!(attempts_map.contains_key(&fingerprint));

        let result_attempt = attempts_map.get(&fingerprint).unwrap();

        assert_eq!(&attempt3, result_attempt);
    }
}