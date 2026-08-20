use std::{
    fs,
    io::Write,
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
};

use affinidi_crypto::jose::key_agreement::{Curve, PrivateKeyAgreement};
use affinidi_messaging_didcomm::jwe::encrypt;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::{json, Value};

static INVOCATION_ID: AtomicU64 = AtomicU64::new(0);
const SENDER_KID: &str = "did:example:alice#key-x25519-1";
const RECIPIENT_KID: &str = "did:example:bob#key-x25519-1";

fn fixture() -> (String, Value, Vec<Value>) {
    let sender_private = PrivateKeyAgreement::from_raw_bytes(Curve::X25519, &[7; 32]).unwrap();
    let recipient_bytes = [9; 32];
    let recipient_private =
        PrivateKeyAgreement::from_raw_bytes(Curve::X25519, &recipient_bytes).unwrap();
    let sender_public = sender_private.public_key();
    let recipient_public = recipient_private.public_key();
    let message = json!({
        "id": "adapter-authcrypt-vector",
        "type": "https://didcomm.org/basicmessage/2.0/message",
        "from": "did:example:alice",
        "to": ["did:example:bob"],
        "body": {"content": "independent authcrypt verification"}
    });
    let envelope = encrypt::authcrypt(
        serde_json::to_string(&message).unwrap().as_bytes(),
        SENDER_KID,
        &sender_private,
        &[(RECIPIENT_KID, &recipient_public)],
    )
    .unwrap();
    let mut recipient_jwk = recipient_public.to_jwk().as_object().unwrap().clone();
    recipient_jwk.insert("kid".to_owned(), Value::String(RECIPIENT_KID.to_owned()));
    recipient_jwk.insert(
        "d".to_owned(),
        Value::String(URL_SAFE_NO_PAD.encode(recipient_bytes)),
    );
    let sender_doc = json!({
        "id": "did:example:alice",
        "verificationMethod": [{
            "id": SENDER_KID,
            "controller": "did:example:alice",
            "type": "JsonWebKey2020",
            "publicKeyJwk": sender_public.to_jwk()
        }],
        "keyAgreement": [SENDER_KID]
    });
    (envelope, json!({"keys": [recipient_jwk]}), vec![sender_doc])
}

fn invoke(envelope: &str, keys: &Value, did_docs: &[Value]) -> Output {
    let root = std::env::temp_dir().join(format!(
        "didcomm-verifier-{}-{}",
        std::process::id(),
        INVOCATION_ID.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).unwrap();
    let key_file = root.join("keys.json");
    fs::write(&key_file, serde_json::to_vec(keys).unwrap()).unwrap();
    let mut doc_paths = Vec::new();
    for (index, document) in did_docs.iter().enumerate() {
        let path = root.join(format!("did-{index}.json"));
        fs::write(&path, serde_json::to_vec(document).unwrap()).unwrap();
        doc_paths.push(path);
    }

    let mut child = Command::new(env!("CARGO_BIN_EXE_didcomm-independent-verifier"))
        .args(["unpack", "--key-file"])
        .arg(&key_file)
        .arg("--did-doc")
        .arg(
            doc_paths
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(","),
        )
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
fn cli_unpacks_authcrypt_envelope() {
    let (envelope, keys, did_docs) = fixture();
    let output = invoke(&envelope, &keys, &did_docs);
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
fn cli_rejects_tampered_authcrypt_envelope() {
    let (envelope, keys, did_docs) = fixture();
    let mut envelope: Value = serde_json::from_str(&envelope).unwrap();
    let ciphertext = envelope["ciphertext"].as_str().unwrap();
    let replacement = if ciphertext.starts_with('A') {
        'B'
    } else {
        'A'
    };
    envelope["ciphertext"] = Value::String(format!("{replacement}{}", &ciphertext[1..]));
    let output = invoke(&serde_json::to_string(&envelope).unwrap(), &keys, &did_docs);
    assert!(!output.status.success());
}

#[test]
fn cli_rejects_wrong_authcrypt_sender_key() {
    let (envelope, keys, mut did_docs) = fixture();
    let wrong_sender = PrivateKeyAgreement::from_raw_bytes(Curve::X25519, &[11; 32]).unwrap();
    did_docs[0]["verificationMethod"][0]["publicKeyJwk"] = wrong_sender.public_key().to_jwk();
    let output = invoke(&envelope, &keys, &did_docs);
    assert!(!output.status.success());
}
