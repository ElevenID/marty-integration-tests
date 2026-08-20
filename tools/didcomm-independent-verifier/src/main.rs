use std::{
    env, fs,
    io::{self, Read},
    path::{Path, PathBuf},
};

use affinidi_crypto::jose::key_agreement::{Curve, PrivateKeyAgreement, PublicKeyAgreement};
use affinidi_messaging_didcomm::jwe::decrypt;
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::{json, Value};

const IMPLEMENTATION: &str = "affinidi/affinidi-tdk-rs:affinidi-messaging-didcomm@v0.15.8#2bec127b171b8fcf69a6c0e6aedca516a3e201b7";

struct Inputs {
    key_file: PathBuf,
    did_docs: Vec<PathBuf>,
}

fn parse_args() -> Result<Option<Inputs>> {
    let mut args = env::args().skip(1);
    let Some(command) = args.next() else {
        bail!(
            "usage: didcomm-independent-verifier unpack --key-file <path> [--did-doc <path,...>]"
        );
    };
    if command == "--version" {
        if args.next().is_some() {
            bail!("--version does not accept arguments");
        }
        println!("{IMPLEMENTATION}");
        return Ok(None);
    }
    if command != "unpack" {
        bail!("unknown command: {command}");
    }

    let mut key_file = None;
    let mut did_docs = Vec::new();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--key-file" => {
                key_file = Some(PathBuf::from(
                    args.next().context("--key-file requires a path")?,
                ));
            }
            "--did-doc" => {
                let value = args.next().context("--did-doc requires paths")?;
                did_docs.extend(
                    value
                        .split(',')
                        .filter(|part| !part.is_empty())
                        .map(PathBuf::from),
                );
            }
            _ => bail!("unknown argument: {arg}"),
        }
    }
    Ok(Some(Inputs {
        key_file: key_file.context("--key-file is required")?,
        did_docs,
    }))
}

fn read_json(path: &Path) -> Result<Value> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))
}

fn curve(jwk: &Value) -> Result<Curve> {
    match jwk.get("crv").and_then(Value::as_str) {
        Some("X25519") => Ok(Curve::X25519),
        Some("P-256") => Ok(Curve::P256),
        Some("secp256k1") => Ok(Curve::K256),
        Some("P-384") => Ok(Curve::P384),
        Some("P-521") => Ok(Curve::P521),
        Some(value) => bail!("unsupported key-agreement curve: {value}"),
        None => bail!("key crv is required"),
    }
}

fn load_recipient(packed: &Value, key_file: &Path) -> Result<(String, PrivateKeyAgreement)> {
    let keys = read_json(key_file)?;
    let keys = keys
        .get("keys")
        .and_then(Value::as_array)
        .context("key file must contain a keys array")?;
    let recipients = packed
        .get("recipients")
        .and_then(Value::as_array)
        .context("encrypted message must contain recipients")?;

    for recipient in recipients {
        let Some(kid) = recipient.pointer("/header/kid").and_then(Value::as_str) else {
            continue;
        };
        let Some(jwk) = keys
            .iter()
            .find(|key| key.get("kid").and_then(Value::as_str) == Some(kid))
        else {
            continue;
        };
        let private = jwk
            .get("d")
            .and_then(Value::as_str)
            .context("recipient private JWK d is required")?;
        let private = URL_SAFE_NO_PAD
            .decode(private)
            .context("decode recipient private JWK d")?;
        let key = PrivateKeyAgreement::from_raw_bytes(curve(jwk)?, &private)
            .context("parse recipient private key")?;
        return Ok((kid.to_owned(), key));
    }
    bail!("no encrypted recipient matches a private key")
}

fn protected_header(packed: &Value) -> Result<Value> {
    let encoded = packed
        .get("protected")
        .and_then(Value::as_str)
        .context("encrypted message protected header is required")?;
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .context("decode protected header")?;
    serde_json::from_slice(&decoded).context("parse protected header")
}

fn sender_kid(header: &Value) -> Result<String> {
    let skid = header
        .get("skid")
        .and_then(Value::as_str)
        .context("authcrypt protected header skid is required")?;
    let apu = header
        .get("apu")
        .and_then(Value::as_str)
        .context("authcrypt protected header apu is required")?;
    let apu = String::from_utf8(
        URL_SAFE_NO_PAD
            .decode(apu)
            .context("decode authcrypt apu")?,
    )
    .context("authcrypt apu must be UTF-8")?;
    if skid != apu {
        bail!("authcrypt skid and apu identify different senders");
    }
    Ok(skid.to_owned())
}

fn load_sender_public(did_docs: &[PathBuf], kid: &str) -> Result<PublicKeyAgreement> {
    for path in did_docs {
        let document = read_json(path)?;
        let methods = document
            .get("verificationMethod")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .chain(
                document
                    .get("keyAgreement")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten(),
            );
        for method in methods {
            if method.get("id").and_then(Value::as_str) != Some(kid) {
                continue;
            }
            let jwk = method
                .get("publicKeyJwk")
                .context("sender verification method publicKeyJwk is required")?;
            return PublicKeyAgreement::from_jwk(jwk).context("parse sender public key");
        }
    }
    bail!("sender key is not present in the provided DID documents")
}

fn main() -> Result<()> {
    let Some(inputs) = parse_args()? else {
        return Ok(());
    };
    let mut packed = String::new();
    io::stdin()
        .read_to_string(&mut packed)
        .context("read packed message")?;
    let packed_value: Value = serde_json::from_str(&packed).context("parse packed message")?;
    let header = protected_header(&packed_value)?;
    let algorithm = header
        .get("alg")
        .and_then(Value::as_str)
        .context("protected header alg is required")?;
    let (recipient_kid, recipient_private) = load_recipient(&packed_value, &inputs.key_file)?;

    let expected_sender = match algorithm {
        "ECDH-1PU+A256KW" => Some(sender_kid(&header)?),
        "ECDH-ES+A256KW" => None,
        value => bail!("unsupported DIDComm key-encryption algorithm: {value}"),
    };
    let sender_public = expected_sender
        .as_deref()
        .map(|kid| load_sender_public(&inputs.did_docs, kid))
        .transpose()?;
    let decrypted = decrypt::decrypt(
        &packed,
        &recipient_kid,
        &recipient_private,
        sender_public.as_ref(),
    )
    .context("decrypt DIDComm message")?;

    if decrypted.recipient_kid != recipient_kid {
        bail!("independent verifier returned a different recipient key");
    }
    if decrypted.legacy_kek_used {
        bail!("message only decrypted with the nonstandard legacy ECDH-1PU derivation");
    }
    if decrypted.authenticated != expected_sender.is_some() {
        bail!("independent verifier authentication classification is inconsistent");
    }
    if decrypted.sender_kid.as_deref() != expected_sender.as_deref() {
        bail!("independent verifier returned a different sender key");
    }
    let message: Value =
        serde_json::from_slice(&decrypted.plaintext).context("parse DIDComm plaintext")?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "encrypted": true,
            "anonymous": !decrypted.authenticated,
            "signed": decrypted.authenticated,
            "message": message,
        }))?
    );
    Ok(())
}
