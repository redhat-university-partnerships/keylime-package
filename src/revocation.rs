// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

#[macro_use]
use log::*;

use crate::common::config_get;
use crate::crypto;
use crate::error::*;
use crate::secure_mount;

use std::convert::TryInto;
use std::io::Write;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};

use openssl::pkey::PKey;
use serde_json::Value;
use zeromq::{SocketRecv, Socket};

/// Runs a script with a json value as argument (used for revocation actions)
pub(crate) fn run_action(
    dir: &Path,
    script: &str,
    json: Value,
) -> Result<Output> {
    let raw_json = serde_json::value::to_raw_value(&json)?;

    let mut child = Command::new(format!("{}{}", "./", script))
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    child
        .stdin
        .as_mut()
        .unwrap_or_else(|| {
            panic!( //#[allow_ci]
            "unable to get mut ref to child stdin in {}",
            script
        )
        })
        .write_all(raw_json.get().as_bytes());

    let output = child.wait_with_output()?;

    if !output.status.success() {
        return Err(output.try_into()?);
    }

    info!(
        "{}",
        format!("INFO: revocation action {:?} successful", script)
    );
    Ok(output)
}

/// Runs revocation actions received from tenant post-attestation
///
/// An OK result indicates all actions were run successfully.
/// Otherwise, an Error will be returned from the first action that
/// did not run successfully.
pub(crate) fn run_revocation_actions(json: Value) -> Result<Vec<Output>> {
    #[cfg(not(test))]
    pretty_env_logger::init();

    #[cfg(test)]
    let mount = concat!(env!("CARGO_MANIFEST_DIR"), "/tests");

    #[cfg(not(test))]
    let mount = secure_mount::mount()?;
    let unzipped = format!("{}/unzipped", mount);
    let action_file = format!("{}/unzipped/action_list", mount);

    let mut outputs = Vec::new();

    if Path::new(&action_file).exists() {
        let action_data = std::fs::read_to_string(action_file)
            .expect("unable to read action_list");

        let action_list = action_data
            .split('\n')
            .filter(|&script| !script.is_empty())
            .map(|script| script.trim())
            .collect::<Vec<&str>>();

        if !action_list.is_empty() {
            for action in action_list {
                match run_action(Path::new(&unzipped), action, json.clone()) {
                    Ok(output) => {
                        outputs.push(output);
                    }
                    Err(e) => {
                        let msg = format!(
                            "error executing revocation script {}: {:?}",
                            action, e
                        );
                        error!("{}", msg);
                        return Err(Error::Script(
                            String::from(action),
                            e.exe_code()?,
                            e.stderr()?,
                        ));
                    }
                }
            }
        } else {
            warn!("WARNING: no actions found in revocation action list");
        }
    } else {
        warn!("WARNING: no action_list found in secure directory");
    }

    Ok(outputs)
}

/// Handles revocation messages via 0mq
/// See:
/// - URL: https://github.com/keylime/keylime/blob/master/keylime/revocation_notifier.py
///   Function: await_notifications
pub(crate) async fn run_revocation_service() -> Result<()> {
    let mount = secure_mount::mount()?;
    let revocation_cert_path =
        format!("{}/unzipped/RevocationNotifier-cert.crt", mount);

    // Connect to the service via 0mq
    let mut mysock = zeromq::SubSocket::new();

    let revocation_ip = config_get("general", "receive_revocation_ip")?;
    let revocation_port = config_get("general", "receive_revocation_port")?;
    let endpoint = format!("tcp://{}:{}", revocation_ip, revocation_port);

    info!("Connecting to revocation endpoint at {}...", endpoint);

    mysock.connect(endpoint.as_str()).await?;
    mysock.subscribe("").await?;

    // Unlike the python agent we do not attempt lazy loading. We either
    // have the certificate, or we don't. If we don't have a key or can't load
    // the key we return a Configuration error as the service will not work.
    let cert_key = if Path::new(&revocation_cert_path).exists() {
        info!(
            "Loading the revocation certificate from {}",
            revocation_cert_path
        );
        match crypto::rsa_import_pubkey(revocation_cert_path) {
            Ok(v) => v,
            Err(e) => {
                return Err(Error::Configuration(String::from(
                    "Can not load pubkey",
                )))
            }
        }
    } else {
        error!(
            "Path {} for the 0mq socket doesn't exist",
            revocation_cert_path
        );
        return Err(Error::Configuration(format!(
            "Path {} for the 0mq socket socket doesn't exist",
            revocation_cert_path,
        )));
    };

    info!("Waiting for revocation messages on 0mq {}", endpoint);

    // Main revocation service loop. If a message is malformed or
    // can not be verified the loop continues.
    loop {
        let mut rawbody = match mysock.recv().await {
            Ok(v) => v,
            Err(e) => {
                warn!("Unable to read message from 0mq");
                continue;
            }
        };

        let bytes = match rawbody.get(0) {
            Some(v) => v,
            None => {
                warn!("Unable to read message frame from 0mq");
                continue;
            }
        };

        let json = String::from_utf8(bytes.as_ref().to_vec())?;
        let body: Value = serde_json::from_str(&json)?;

        // Ensure we have a signature, otherwise continue the loop
        let signature = match body["signature"].as_str() {
            Some(v) => v,
            _ => {
                warn!("No signature on revocation message from server");
                continue;
            }
        };

        // Ensure we have a msg, otherwise continue the loop
        let message = match body["msg"].as_str() {
            Some(v) => v,
            _ => {
                warn!("No msg on revocation message from server");
                continue;
            }
        };

        // Verify the message and signature with our key
        let mut verified = crypto::asym_verify(&cert_key, message, signature);

        match verified {
            Ok(true) => {
                let msg = body["msg"].as_str();
                let msg_payload: Value =
                    serde_json::from_str(match msg.as_deref() {
                        Some(v) => v,
                        _ => {
                            warn!("Unable to decode json in msg");
                            continue;
                        }
                    })?;
                debug!(
                    "Revocation signature validated for revocation: {}",
                    msg_payload
                );
                let _ = run_revocation_actions(msg_payload)?;
            }
            _ => {
                error!("Invalid revocation message siganture {}", body);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revocation_scripts_ok() {
        let json_file = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/unzipped/test_ok.json"
        );
        let json_str = std::fs::read_to_string(json_file).unwrap(); //#[allow_ci]
        let json = serde_json::from_str(&json_str).unwrap(); //#[allow_ci]

        let outputs = run_revocation_actions(json);
        assert!(outputs.is_ok());
        let outputs = outputs.unwrap(); //#[allow_ci]
        assert!(outputs.len() == 2);

        for output in outputs {
            assert_eq!(
                String::from_utf8(output.stdout).unwrap(), //#[allow_ci]
                "there\n"
            );
        }
    }

    #[test]
    fn revocation_scripts_err() {
        let json_file = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/unzipped/test_err.json"
        );
        let json_str = std::fs::read_to_string(json_file).unwrap(); //#[allow_ci]
        let json = serde_json::from_str(&json_str).unwrap(); //#[allow_ci]

        let outputs = run_revocation_actions(json);
        assert!(outputs.is_err());
    }
}
