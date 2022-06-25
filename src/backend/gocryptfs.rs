// gocryptfs.rs
//
// Copyright 2021 Martin Pobaschnig
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: GPL-3.0-or-later

use super::BackendError;
use crate::vault::VaultConfig;
use gettextrs::gettext;
use std::process::Command;
use std::{io::Write, process::Stdio};

pub fn is_available() -> Result<bool, BackendError> {
    let output = Command::new("gocryptfs")
        .arg("--version")
        .output()?;

    Ok(output.status.success())
}

pub fn init(vault_config: &VaultConfig, password: String) -> Result<(), BackendError> {
    let mut child = Command::new("gocryptfs")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .arg("--init")
        .arg("-q")
        .arg("--")
        .arg(&vault_config.encrypted_data_directory)
        .spawn()?;

    let mut pw = String::from(&password);
    pw.push_str(&"\n".to_owned());
    pw.push_str(&password);
    pw.push_str(&"\n".to_owned());

    child
        .stdin
        .as_mut()
        .ok_or(BackendError::Generic)?
        .write_all(pw.as_bytes())?;

    let output = child.wait_with_output()?;
    if output.status.success() {
        Ok(())
    } else {
        std::io::stdout().write_all(&output.stdout).unwrap();
        std::io::stderr().write_all(&output.stderr).unwrap();

        Err(status_to_err(output.status.code()))
    }
}

pub fn open(vault_config: &VaultConfig, password: String) -> Result<(), BackendError> {
    let mut child = Command::new("gocryptfs")
        .env("DEBUG", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .arg("-fusedebug")
        .arg(&vault_config.encrypted_data_directory)
        .arg(&vault_config.mount_directory)
        .spawn()?;

    let mut pw = String::from(&password);
    pw.push_str(&"\n".to_owned());

    child
        .stdin
        .as_mut()
        .ok_or(BackendError::Generic)?
        .write_all(pw.as_bytes())?;

    let output = child.wait_with_output()?;
    if output.status.success() {
        Ok(())
    } else {
        std::io::stdout().write_all(&output.stdout).unwrap();
        std::io::stderr().write_all(&output.stderr).unwrap();

        println!("Err code: {:?}", output.status.code());

        Err(status_to_err(output.status.code()))
    }
}

pub fn close(vault_config: &VaultConfig) -> Result<(), BackendError> {
    let child = Command::new("fusermount")
        .stdout(Stdio::piped())
        .arg("-u")
        .arg(&vault_config.mount_directory)
        .spawn()?;

    let output = child.wait_with_output()?;
    if output.status.success() {
        Ok(())
    } else {
        std::io::stdout().write_all(&output.stdout).unwrap();
        std::io::stderr().write_all(&output.stderr).unwrap();

        Err(status_to_err(output.status.code()))
    }
}

fn status_to_err(status: Option<i32>) -> BackendError {
    struct GocryptfsExitStatus {}

    #[allow(dead_code)]
    impl GocryptfsExitStatus {
        pub const SUCCESS: i32 = 0;
        pub const NON_EMPTY_CIPHER_DIR: i32 = 6;
        pub const NON_EMPTY_MOUNT_POINT: i32 = 10;
        pub const WRONG_PASSWORD: i32 = 12;
        pub const EMPTY_PASSWORD: i32 = 22;
        pub const CANNOT_READ_CONFIG: i32 = 23;
        pub const CANNOT_WRITE_CONFIG: i32 = 24;
        pub const FSCK_ERROR: i32 = 26;
    }

    match status {
        Some(status) => match status {
            GocryptfsExitStatus::NON_EMPTY_CIPHER_DIR => {
                BackendError::ToUser(gettext("The encrypted data directory is not empty."))
            }
            GocryptfsExitStatus::NON_EMPTY_MOUNT_POINT => {
                BackendError::ToUser(gettext("The mount directory is not empty."))
            }
            GocryptfsExitStatus::WRONG_PASSWORD => {
                BackendError::ToUser(gettext("The password is wrong."))
            }
            GocryptfsExitStatus::EMPTY_PASSWORD => {
                BackendError::ToUser(gettext("The password is empty."))
            }
            GocryptfsExitStatus::CANNOT_READ_CONFIG => {
                BackendError::ToUser(gettext("Vaults cannot read configuration file."))
            }
            GocryptfsExitStatus::CANNOT_WRITE_CONFIG => {
                BackendError::ToUser(gettext("Vaults cannot write configuration file."))
            }
            GocryptfsExitStatus::FSCK_ERROR => {
                BackendError::ToUser(gettext("The file system check reported an error."))
            }
            _ => BackendError::ToUser(gettext("An unknown error occurred.")),
        },
        None => BackendError::Generic,
    }
}
