use std::fs;
use std::path::Path;
use anyhow::{anyhow, Context};
use log::{debug, error, info};
use regex::Regex;

#[cfg(windows)]
const LINE_ENDING: &'static str = "\r\n";

#[cfg(not(windows))]
const LINE_ENDING: &'static str = "\n";

const UNEXPECTED_ERROR_MISSING_ROW_PART: &str = "unexpected error, missing row part";

#[derive(PartialEq, Debug)]
pub struct AuthorizedKey {
    pub key_type: KeyType,
    pub key: String,
    pub id: String,
}

#[derive(PartialEq, Debug)]
pub enum KeyType {
    RSA,
    ED25519,
    OTHER,
}

impl TryFrom<&str> for KeyType {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.to_lowercase().starts_with("ssh-") {
            let result = match value.to_lowercase().as_ref() {
                "ssh-rsa" => KeyType::RSA,
                "ssh-ed25519" => KeyType::ED25519,
                _ => KeyType::OTHER
            };

            Ok(result)
        } else {
            error!("unsupported row header, expected 'ssh-'");
            Err(anyhow!("unsupported row header"))
        }
    }
}

pub fn get_authorized_keys_from_file(file_path: &Path) -> anyhow::Result<Vec<AuthorizedKey>> {
    info!("get authorized keys from path '{}'", file_path.display());

    if file_path.exists() && file_path.is_file() {
        let file_content = fs::read_to_string(&file_path)
            .context("cannot read file content")?;

        let space_pattern = Regex::new("\\s{2,}").expect("unexpected error, invalid regexp");

        let rows = file_content.split(LINE_ENDING).collect::<Vec<&str>>();

        let mut keys: Vec<AuthorizedKey> = Vec::new();

        for row in rows {
            let normalized_row = space_pattern.replace_all(&row, " ").trim()
                                          .replace("\\s{2,}", " ")
                                          .replace("\t", " ");
            debug!("normalized row: '{normalized_row}'");

            let row_parts = normalized_row.split(" ").collect::<Vec<&str>>();

            if row_parts.len() >= 2 {
                let key_type_str = row_parts.first()
                    .expect(UNEXPECTED_ERROR_MISSING_ROW_PART);

                match KeyType::try_from(*key_type_str) {
                    Ok(key_type) => {
                        let key_str = row_parts.get(1)
                            .expect(UNEXPECTED_ERROR_MISSING_ROW_PART);

                        let mut key_id = "";

                        if row_parts.len() == 3 {
                            key_id = row_parts.get(2)
                                .expect(UNEXPECTED_ERROR_MISSING_ROW_PART);
                        }

                        keys.push(
                            AuthorizedKey {
                                key_type,
                                key: key_str.to_string(),
                                id: key_id.to_string(),
                            }
                        )
                    }
                    Err(e) => error!("{}", e)
                }

            } else {
                info!("unsupported row format: '{row}'")
            }
        }

        info!("keys: {:?}", keys);

        Ok(keys)

    } else {
        Err(anyhow!("File doesn't exist"))
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use crate::authorizedkeys::{AuthorizedKey, get_authorized_keys_from_file, KeyType};
    use crate::tests_common::init_logging;

    /// Parser follows the rules:
    /// - Row should start with 'ssh-'
    /// - Row should have at least two parts separated by single spaces
    #[test]
    fn unknown_records_should_be_ignored() {
        init_logging();

        let path = Path::new("test-data").join("authorized_keys-unknown-records");
        let keys = get_authorized_keys_from_file(&path).unwrap();

        assert!(keys.is_empty())
    }

    #[test]
    fn unnecessary_spaces_should_be_removed() {
        init_logging();

        let path = Path::new("test-data").join("authorized_keys-spaces");

        let keys = get_authorized_keys_from_file(&path).unwrap();

        assert_key(
            KeyType::ED25519,
            "AAAAC3NzaC1lZDI1NTE5AAAAIJRApVG7oMFm8Rz4UHe+L8NDluPrIT3Q9eB/o1PXR2Ld",
            "rick@morty.com", &keys.get(0).unwrap(),
        );
    }

    #[test]
    fn keys_should_be_loaded() {
        init_logging();

        let path = Path::new("test-data").join("authorized_keys");

        let keys = get_authorized_keys_from_file(&path).unwrap();

        assert_eq!(4, keys.len());

        assert_key(
            KeyType::RSA,
            "AAAAB3NzaC1yc2EAAAADAQABAAABgQDAd6jIpyOMz50jtD+7FrKhQ3yzYjZTr0zCixTHDTZ2w2nEcrnkGqF/2L1HAiYVv1kub/GlL9po1gv7CwOE4O2F5VwtSNco84YEcl8zL7tTKJCdmOVqajvFtRmYP6vQQ8q1ffODlky7u98HkQN/Pgu+zCd1D104Tx3bpPJoFOGfn3nZm5b3zTgM2Ie2qJwyRHdvJwmtJtmf6IAG9XF1GdzPJ15U6g/7SndvfGX++KodYZzSUWsbLDxC0Vpr4nH1+C8JIWApUFXTTKCSyoSm3hmDSXrreOkmMSltVHj8SQYFNmMeMRMvKZwmqi6RMC5AXock4gFxzaxCsDtqrfc4MYb9UE/uUiSeyQ2GSjW6soq+9K/+s8nmCnzxGTuM7gwGG1Ada7qgIrLAHKdQyiDX9/wwwi7Nax8OO3+orWJjfQymoHL3/aYEhXE0c2pscAeYaB6iiw+UkvTUSJ0nun9bjR8jY3iS0DUM4jYSkKaVGl2/kOv/fZdf4I+cCuHs/0stREc=",
            "w.thornton@company.de", &keys.get(0).unwrap(),
        );

        assert_key(
            KeyType::ED25519,
            "AAAAC3NzaC1lZDI1NTE5AAAAIJRApVG7oMFm8Rz4UHe+L8NDluPrIT3Q9eB/o1PXR2Ld",
            "b.robertson@gmail.com", &keys.get(1).unwrap(),
        );

        assert_key(
            KeyType::RSA,
            "AAAAB3NzaC1yc2EAAAADAQABAAABgQDAd6jIpyOMz50jtD+7FrKhQ3yzYjZTr0zCixTHDTZ2w2nEcrnkGqF/2L1HAiYVv1kub/GlL9po1gv7CwOE4O2F5VwtSNco84YEcl8zL7tTKJCdmOVqajvFtRmYP6vQQ8q1ffODlky7u98HkQN/Pgu+zCd1D104Tx3bpPJoFOGfn3nZm5b3zTgM2Ie2qJwyRHdvJwmtJtmf6IAG9XF1GdzPJ15U6g/7SndvfGX++KodYZzSUWsbLDxC0Vpr4nH1+C8JIWApUFXTTKCSyoSm3hmDSXrreOkmMSltVHj8SQYFNmMeMRMvKZwmqi6RMC5AXock4gFxzaxCsDtqrfc4MYb9UE/uUiSeyQ2GSjW6soq+9K/+s8nmCnzxGTuM7gwGG1Ada7qgIrLAHKdQyiDX9/wwwi7Nax8OO3+orWJjfQymoHL3/aYEhXE0c2pscAeYaB6iiw+UkvTUSJ0nun9bjR8jY3iS0DUM4jYSkKaVGl2/kOv/fZdf4I+cCuHs/0stREc=",
            "god@zilla.de", &keys.get(2).unwrap(),
        );

        assert_key(
            KeyType::ED25519,
            "AAAAC3NzaC2lZDI1NTE5AAAAIJRApVG7oMFm8Rz4UHe+L8NDluPrIT3Q9eB/o1PXR2Ld",
            "", &keys.get(3).unwrap(),
        );
    }

    fn assert_key(expected_key_type: KeyType, expected_key: &str, expected_id: &str,
                  actual_key: &AuthorizedKey) {
        assert_eq!(expected_key_type, actual_key.key_type);
        assert_eq!(expected_key, actual_key.key);
        assert_eq!(expected_id, actual_key.id);
    }

    #[test]
    fn return_error_for_unknown_file() {
        let path = Path::new("unknown-file");

        assert!(get_authorized_keys_from_file(&path).is_err())
    }
}
