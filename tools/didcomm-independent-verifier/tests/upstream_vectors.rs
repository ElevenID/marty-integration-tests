use std::{
    fs,
    io::Write,
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
};

use didcomm::{
    secrets::SecretMaterial,
    test_vectors::{ALICE_DID_DOC, BOB_DID_DOC, BOB_SECRETS, ENCRYPTED_MSG_AUTH_X25519},
};
use serde_json::{json, Value};

static INVOCATION_ID: AtomicU64 = AtomicU64::new(0);

fn invoke(envelope: &str) -> Output {
    let root = std::env::temp_dir().join(format!(
        "didcomm-verifier-{}-{}",
        std::process::id(),
        INVOCATION_ID.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).unwrap();
    let keys = BOB_SECRETS
        .iter()
        .filter_map(|secret| match &secret.secret_material {
            SecretMaterial::JWK { private_key_jwk } => {
                let mut jwk = private_key_jwk.as_object().unwrap().clone();
                jwk.insert("kid".to_owned(), Value::String(secret.id.clone()));
                Some(Value::Object(jwk))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let key_file = root.join("keys.json");
    let alice = root.join("alice.json");
    let bob = root.join("bob.json");
    fs::write(
        &key_file,
        serde_json::to_vec(&json!({"keys": keys})).unwrap(),
    )
    .unwrap();
    fs::write(&alice, serde_json::to_vec(&*ALICE_DID_DOC).unwrap()).unwrap();
    fs::write(&bob, serde_json::to_vec(&*BOB_DID_DOC).unwrap()).unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_didcomm-independent-verifier"))
        .args(["unpack", "--key-file"])
        .arg(&key_file)
        .arg("--did-doc")
        .arg(format!("{},{}", alice.display(), bob.display()))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(envelope.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    fs::remove_dir_all(root).unwrap();
    output
}

#[test]
fn cli_unpacks_upstream_authcrypt_vector() {
    let output = invoke(ENCRYPTED_MSG_AUTH_X25519);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["encrypted"], true);
    assert_eq!(result["anonymous"], false);
    assert_eq!(result["signed"], true);
    assert_eq!(result["message"]["from"], "did:example:alice");
}

#[test]
fn cli_rejects_tampered_upstream_authcrypt_vector() {
    let mut envelope: Value = serde_json::from_str(ENCRYPTED_MSG_AUTH_X25519).unwrap();
    let ciphertext = envelope["ciphertext"].as_str().unwrap();
    let replacement = if ciphertext.starts_with('A') {
        'B'
    } else {
        'A'
    };
    envelope["ciphertext"] = Value::String(format!("{replacement}{}", &ciphertext[1..]));
    let output = invoke(&serde_json::to_string(&envelope).unwrap());
    assert!(!output.status.success());
}
