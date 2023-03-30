pub mod time;

use chrono::NaiveDateTime;
use fake::{Fake, Faker};
use log::LevelFilter;
use ssh_auth_log::KeyLoginAttempt;
use ssh_fingerprint_rs::PublicKeyFingerprint;

pub fn init_logging() {
    let _ = env_logger::builder().filter_level(LevelFilter::Debug)
        .is_test(true).try_init();
}

pub fn get_random_string() -> String {
    Faker.fake::<String>()
}

pub fn get_key_login_attempt(timestamp: &NaiveDateTime, fingerprint: &str) -> KeyLoginAttempt {
    KeyLoginAttempt {
        timestamp: timestamp.clone(),
        key_type: "rsa".to_string(),
        fingerprint_type: "SHA256".to_string(),
        fingerprint: fingerprint.to_string(),
        username: "a@b.com".to_string(),
        key_offset: 0,
    }
}

pub fn get_public_key_fingerprint(fingerprint: &str) -> PublicKeyFingerprint {
    PublicKeyFingerprint {
        key_length: 2048,
        fingerprint_type: "SHA256".to_string(),
        fingerprint: fingerprint.to_string(),
        key_id: "a@b.com".to_string(),
        key_type: "RSA".to_string(),
    }
}