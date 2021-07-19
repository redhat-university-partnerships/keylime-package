// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

#![deny(
    nonstandard_style,
    const_err,
    dead_code,
    improper_ctypes,
    non_shorthand_field_patterns,
    no_mangle_generic_items,
    overflowing_literals,
    path_statements,
    patterns_in_fns_without_body,
    private_in_public,
    unconditional_recursion,
    unused,
    while_true,
    missing_copy_implementations,
    missing_debug_implementations,
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused_allocation,
    unused_comparisons,
    unused_parens,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]
// Temporarily allow these until they can be fixed
//  unused: there is a lot of code that's for now unused because this codebase is still in development
//  missing_docs: there is many functions missing documentations for now
#![allow(unused, missing_docs)]

mod cmd_exec;
mod common;
mod crypto;
mod error;
mod hash;
mod keys_handler;
mod quotes_handler;
mod registrar_agent;
mod revocation;
mod secure_mount;
mod tpm;

use actix_web::{web, App, HttpServer};
use common::*;
use compress_tools::*;
use error::{Error, Result};
use flate2::read::DeflateDecoder;
use futures::{future::TryFutureExt, try_join};
use log::*;
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private, Public},
    sign::Signer,
    symm::{decrypt_aead, Cipher},
};
use std::{
    convert::TryFrom,
    fs,
    io::{prelude::*, BufReader, Read, Write},
    os::{
        linux::fs::MetadataExt,
        unix::fs::{OpenOptionsExt, PermissionsExt},
    },
    path::Path,
    process::{Command, Stdio},
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tss_esapi::{
    handles::KeyHandle,
    interface_types::{
        algorithm::AsymmetricAlgorithm, resource_handles::Hierarchy,
    },
    utils, Context,
};
use uuid::Uuid;

static NOTFOUND: &[u8] = b"Not Found";

// This data is passed in to the actix httpserver threads that
// handle quotes.
#[derive(Debug)]
pub struct QuoteData {
    tpmcontext: Mutex<Context>,
    priv_key: PKey<Private>,
    pub_key: PKey<Public>,
    ak_handle: KeyHandle,
    ukeys: Mutex<KeySet>,
    vkeys: Mutex<KeySet>,
    payload_symm_key: Arc<Mutex<SymmKey>>,
    encr_payload: Arc<Mutex<Vec<u8>>>,
    auth_tag: Mutex<[u8; AUTH_TAG_LEN]>,
}

fn get_uuid(agent_uuid_config: &str) -> String {
    match agent_uuid_config {
        "openstack" => {
            info!("Openstack placeholder...");
            "openstack".into()
        }
        "hash_ek" => {
            info!("hash_ek placeholder...");
            "hash_ek".into()
        }
        "generate" => {
            let agent_uuid = Uuid::new_v4();
            info!("Generated a new UUID: {}", &agent_uuid);
            agent_uuid.to_string()
        }
        uuid_config => match Uuid::parse_str(uuid_config) {
            Ok(uuid_config) => uuid_config.to_string(),
            Err(_) => {
                info!("Misformatted UUID: {}", &uuid_config);
                let agent_uuid = Uuid::new_v4();
                agent_uuid.to_string()
            }
        },
    }
}

// Parameters are based on Python codebase:
// https://github.com/keylime/keylime/blob/1ed43ac8f75d5c3bc3a3bbbbb5037f20cf3c5a6a/ \
// keylime/crypto.py#L189
pub(crate) fn decrypt_payload(
    encr: Arc<Mutex<Vec<u8>>>,
    key: Arc<Mutex<SymmKey>>,
) -> Result<Vec<u8>> {
    let symm_key = key.lock().unwrap().bytes; //#[allow_ci]
    let payload = encr.lock().unwrap(); //#[allow_ci]

    // parse out payload iv, tag, ciphertext
    let (iv, rest) = payload.split_at(AES_BLOCK_SIZE);
    let (ciphertext, tag) = rest.split_at(rest.len() - AES_BLOCK_SIZE);
    let cipher = match symm_key.len() {
        16 => Cipher::aes_128_gcm(),
        32 => Cipher::aes_256_gcm(),
        other => {
            return Err(Error::Other(format!(
                "key length {} does not correspond to valid GCM cipher",
                other
            )))
        }
    };

    let decrypted =
        decrypt_aead(cipher, &symm_key, Some(iv), &[], ciphertext, tag)?;

    info!("Successfully decrypted payload");
    Ok(decrypted)
}

// sets up unzipped directory in secure mount location in preparation for
// writing out symmetric key and encrypted payload. returns file paths for
// both.
pub(crate) fn setup_unzipped() -> Result<(String, String, String)> {
    let mount = secure_mount::mount()?;
    let unzipped = format!("{}/unzipped", mount);

    // clear any old data
    if Path::new(&unzipped).exists() {
        fs::remove_dir_all(&unzipped)?;
    }

    let dec_payload_filename = config_get("cloud_agent", "dec_payload_file")?;
    let dec_payload_path = format!("{}/{}", unzipped, dec_payload_filename);

    let key_filename = config_get("cloud_agent", "enc_keyname")?;
    let key_path = format!("{}/{}", unzipped, key_filename);

    fs::create_dir(&unzipped)?;

    Ok((unzipped, dec_payload_path, key_path))
}

// write symm key data and decrypted payload data out to specified files
pub(crate) fn write_out_key_and_payload(
    dec_payload: &[u8],
    dec_payload_path: &str,
    key: Arc<Mutex<SymmKey>>,
    key_path: &str,
) -> Result<()> {
    let symm_key = key.lock().unwrap().bytes; //#[allow_ci]

    let mut key_file = fs::File::create(key_path)?;
    let bytes = key_file.write(&symm_key[..])?;
    if bytes != symm_key.len() {
        return Err(Error::Other(format!("Error writing symm key to {:?}: key len is {}, but {} bytes were written", key_path, symm_key.len(), bytes)));
    }
    info!("Wrote payload decryption key to {:?}", key_path);

    let mut dec_payload_file = fs::File::create(dec_payload_path)?;
    let bytes = dec_payload_file.write(dec_payload)?;
    if bytes != dec_payload.len() {
        return Err(Error::Other(format!("Error writing decrypted payload to {:?}: payload len is {}, but {} bytes were written", dec_payload_path, dec_payload.len(), bytes)));
    }
    info!("Wrote decrypted payload to {:?}", dec_payload_path);

    Ok(())
}

// run a script (such as the init script, if any) and check the status
pub(crate) fn run(dir: &str, script: &str, agent_uuid: &str) -> Result<()> {
    let script_location = format!("{}/{}", dir, script);
    info!("Running script: {:?}", script_location);

    let script_path = Path::new(&script_location);
    if !script_path.exists() {
        return Err(Error::Other(format!("{} not found", script_location)));
    }

    if fs::set_permissions(&script_path, fs::Permissions::from_mode(0o700))
        .is_err()
    {
        return Err(Error::Other(format!(
            "unable to set {} as executable",
            script_location
        )));
    }

    match Command::new("sh")
        .arg("-c")
        .arg(&script_location)
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .status()
    {
        Ok(_) => {
            info!("{:?} ran successfully", script_location);
            Ok(())
        }
        Err(e) => Err(Error::Other(format!(
            "{:?} failed during run: {}",
            script_location, e
        ))),
    }
}

// checks if keylime.conf indicates the payload should be unzipped, and does so if needed.
// the input string is the directory where the unzipped file(s) should be stored.
pub(crate) fn optional_unzip_payload(unzipped: &str) -> Result<()> {
    let is_zip = config_get("cloud_agent", "extract_payload_zip")?;
    if bool::from_str(&is_zip.to_lowercase())? {
        let zipped_payload = config_get("cloud_agent", "dec_payload_file")?;
        let zipped_payload_path = format!("{}/{}", unzipped, zipped_payload);

        info!("Unzipping payload {} to {}", &zipped_payload, &unzipped);

        let mut source = fs::File::open(&zipped_payload_path)?;
        let dest = Path::new(&unzipped);
        uncompress_archive(&mut source, dest, Ownership::Preserve)?;
    }

    Ok(())
}

#[actix_web::main]
async fn main() -> Result<()> {
    pretty_env_logger::init();
    let mut ctx = tpm::get_tpm2_ctx()?;
    //  Retrieve the TPM Vendor, this allows us to warn if someone is using a
    // Software TPM ("SW")
    if tss_esapi::utils::get_tpm_vendor(&mut ctx)?.contains("SW") {
        warn!("INSECURE: Keylime is using a software TPM emulator rather than a real hardware TPM.");
        warn!("INSECURE: The security of Keylime is NOT linked to a hardware root of trust.");
        warn!("INSECURE: Only use Keylime in this mode for testing or debugging purposes.");
    }

    info!("Starting server...");

    // Gather EK and AK key values and certs
    let (ek_handle, ek_cert, ek_tpm2b_pub) =
        tpm::create_ek(&mut ctx, Some(AsymmetricAlgorithm::Rsa))?;

    let (ak_handle, ak_name, ak_tpm2b_pub) =
        tpm::create_ak(&mut ctx, ek_handle)?;

    // Gather configs
    let cloudagent_ip = cloudagent_ip_get()?;
    let cloudagent_port = cloudagent_port_get()?;
    let registrar_ip = registrar_ip_get()?;
    let registrar_port = registrar_port_get()?;
    let agent_uuid_config = config_get("cloud_agent", "agent_uuid")?;
    let agent_uuid = get_uuid(&agent_uuid_config);
    let cloudagent_contact_ip = cloudagent_contact_ip_get();
    let cloudagent_contact_port = cloudagent_contact_port_get();
    info!("Agent UUID: {}", agent_uuid);

    {
        // Request keyblob material
        let keyblob = registrar_agent::do_register_agent(
            &registrar_ip,
            &registrar_port,
            &agent_uuid,
            &ek_tpm2b_pub,
            ek_cert,
            &ak_tpm2b_pub,
            cloudagent_contact_ip,
            cloudagent_contact_port
        )
        .await?;
        info!("SUCCESS: Agent {} registered", agent_uuid);

        let key = tpm::activate_credential(
            &mut ctx, keyblob, ak_handle, ek_handle,
        )?;
        let mackey = base64::encode(key.value());
        let mackey = PKey::hmac(mackey.as_bytes())?;
        let mut signer = Signer::new(MessageDigest::sha384(), &mackey)?;
        signer.update(agent_uuid.as_bytes());
        let auth_tag = signer.sign_to_vec()?;
        let auth_tag = hex::encode(&auth_tag);

        registrar_agent::do_activate_agent(
            &registrar_ip,
            &registrar_port,
            &agent_uuid,
            &auth_tag,
        )
        .await?;
        info!("SUCCESS: Agent {} activated", agent_uuid);
    }

    // Generate key pair for secure transmission of u, v keys. The u, v
    // keys are two halves of the key used to decrypt the workload after
    // the Identity and Integrity Quotes sent by the agent are validated
    // by the Tenant and Cloud Verifier, respectively.
    //
    // Since we store the u key in memory, discarding this key, which
    // safeguards u and v keys in transit, is not part of the threat model.
    let (nk_pub, nk_priv) = crypto::rsa_generate_pair(2048)?;

    let mut payload_symm_key = SymmKey::default();
    let mut encr_payload = Vec::new();

    let symm_key_arc = Arc::new(Mutex::new(payload_symm_key));
    let encr_payload_arc = Arc::new(Mutex::new(encr_payload));

    // these allow the arrays to be referenced later in this thread
    let symm_key = Arc::clone(&symm_key_arc);
    let payload = Arc::clone(&encr_payload_arc);

    let quotedata = web::Data::new(QuoteData {
        tpmcontext: Mutex::new(ctx),
        priv_key: nk_priv,
        pub_key: nk_pub,
        ak_handle,
        ukeys: Mutex::new(KeySet::default()),
        vkeys: Mutex::new(KeySet::default()),
        payload_symm_key: symm_key_arc,
        encr_payload: encr_payload_arc,
        auth_tag: Mutex::new([0u8; AUTH_TAG_LEN]),
    });

    let actix_server = HttpServer::new(move || {
        App::new()
            .app_data(quotedata.clone())
            .service(
                web::resource("/keys/ukey")
                    .route(web::post().to(keys_handler::u_or_v_key)),
            )
            .service(
                // the double slash may be a typo on the python side
                web::resource("//keys/vkey")
                    .route(web::post().to(keys_handler::u_or_v_key)),
            )
            .service(
                web::resource("/quotes/identity")
                    .route(web::get().to(quotes_handler::identity)),
            )
            .service(
                web::resource("/quotes/integrity")
                    .route(web::get().to(quotes_handler::integrity)),
            )
    })
    .bind(format!("{}:{}", cloudagent_ip, cloudagent_port))?
    .run()
    .map_err(Error::from);
    info!("Listening on http://{}:{}", cloudagent_ip, cloudagent_port);

    // do nothing until actix server's handlers have updated the symmetric key
    loop {
        let key = symm_key.lock().unwrap(); //#[allow_ci]

        // if key is still empty, unlock resource by dropping and sleep for 1 sec
        if key.is_empty() {
            drop(key);
            std::thread::sleep(Duration::from_millis(1000));
            continue;
        } else {
            break;
        }
    }

    let dec_payload = decrypt_payload(payload, symm_key.clone())?;

    let (unzipped, dec_payload_path, key_path) = setup_unzipped()?;

    write_out_key_and_payload(
        &dec_payload,
        &dec_payload_path,
        symm_key,
        &key_path,
    )?;

    optional_unzip_payload(&unzipped)?;

    // there may also be also a separate init script
    match config_get("cloud_agent", "payload_script")?.as_str() {
        "" => {
            info!("No payload script specified, skipping");
        }
        script => {
            info!("Payload init script indicated: {}", script);
            run(&unzipped, script, &agent_uuid)?;
        }
    }

    // as the payload may set up revocation certificates, etc., the revocation
    // service should be run only after the agent quotes have been validated
    // and the payload has been decrypted and run. also, this service can be
    // turned off in configuration.
    let run_revocation = config_get("cloud_agent", "listen_notfications")?;
    if bool::from_str(&run_revocation.to_lowercase())? {
        try_join!(revocation::run_revocation_service())?;
    }

    Ok(())
}

/*
 * Input: file path
 * Output: file content
 *
 * Helper function to help the keylime agent read file and get the file
 * content. It is not from the original python version. Because rust needs
 * to handle error in result, it is good to keep this function separate from
 * the main function.
 */
fn read_in_file(path: String) -> std::io::Result<String> {
    let file = fs::File::open(path)?;
    let mut buf_reader = BufReader::new(file);
    let mut contents = String::new();
    let _ = buf_reader.read_to_string(&mut contents)?;
    Ok(contents)
}

// Unit Testing
#[cfg(test)]
mod tests {
    use super::*;

    fn init_logger() {
        pretty_env_logger::init();
        info!("Initialized logger for testing suite.");
    }

    #[test]
    fn test_read_in_file() {
        assert_eq!(
            read_in_file("test-data/test_input.txt".to_string())
                .expect("File doesn't exist"),
            String::from("Hello World!\n")
        );
    }

    #[test]
    fn test_get_uuid() {
        assert_eq!(get_uuid("openstack"), "openstack");
        assert_eq!(get_uuid("hash_ek"), "hash_ek");
        let _ = Uuid::parse_str(&get_uuid("generate")).unwrap(); //#[allow_ci]
        assert_eq!(
            get_uuid("D432FBB3-D2F1-4A97-9EF7-75BD81C00000"),
            "d432fbb3-d2f1-4a97-9ef7-75bd81c00000"
        );
        assert_ne!(
            get_uuid("D432FBB3-D2F1-4A97-9EF7-75BD81C0000X"),
            "d432fbb3-d2f1-4a97-9ef7-75bd81c0000X"
        );
        let _ = Uuid::parse_str(&get_uuid(
            "D432FBB3-D2F1-4A97-9EF7-75BD81C0000X",
        ))
        .unwrap(); //#[allow_ci]
    }

    #[test]
    fn test_run() {
        let dir = tempfile::tempdir().unwrap(); //#[allow_ci]
        let script_path = dir.path().join("test-script.sh");
        {
            let mut script_file = fs::File::create(&script_path).unwrap(); //#[allow_ci]
            let script = r#"
#!/bin/sh

echo hello > test-output
"#;
            let _ = script_file.write(script.as_bytes()).unwrap(); //#[allow_ci]
        }
        run(
            dir.path().to_str().unwrap(), //#[allow_ci]
            script_path.file_name().unwrap().to_str().unwrap(), //#[allow_ci]
            "D432FBB3-D2F1-4A97-9EF7-75BD81C0000X",
        )
        .unwrap(); //#[allow_ci]
        assert!(dir.path().join("test-output").exists());
    }
}
