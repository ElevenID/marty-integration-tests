use std::{
    env, fs,
    io::{self, Read},
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use didcomm::{
    did::{resolvers::ExampleDIDResolver, DIDDoc},
    secrets::{resolvers::ExampleSecretsResolver, Secret, SecretMaterial, SecretType},
    Message, UnpackOptions,
};
use serde_json::{json, Map, Value};

const IMPLEMENTATION: &str =
    "sicpa-dlab/didcomm-rust@v0.4.1#9fd70993e9a6e5fd527058ecfe173ee066bcbc27";

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

fn normalized_did_doc(value: Value) -> Result<DIDDoc> {
    let source = value
        .as_object()
        .context("DID document must be an object")?;
    let id = source
        .get("id")
        .and_then(Value::as_str)
        .context("DID document id is required")?;
    let mut methods = source
        .get("verificationMethod")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut agreements = Vec::new();
    for agreement in source
        .get("keyAgreement")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        match agreement {
            Value::String(id) => agreements.push(Value::String(id.clone())),
            Value::Object(method) => {
                let method_id = method
                    .get("id")
                    .and_then(Value::as_str)
                    .context("embedded keyAgreement id is required")?;
                agreements.push(Value::String(method_id.to_owned()));
                methods.push(Value::Object(method.clone()));
            }
            _ => bail!("DID document keyAgreement entries must be strings or objects"),
        }
    }
    // The verifier only resolves key-agreement material during unpacking. Build
    // the narrower schema expected by didcomm-rust without changing key data.
    serde_json::from_value(json!({
        "id": id,
        "keyAgreement": agreements,
        "authentication": [],
        "verificationMethod": methods,
        "service": [],
    }))
    .context("normalize DID document")
}

fn load_secrets(path: &Path) -> Result<Vec<Secret>> {
    let value = read_json(path)?;
    let keys = value
        .get("keys")
        .and_then(Value::as_array)
        .context("key file must contain a keys array")?;
    keys.iter()
        .map(|key| {
            let mut jwk: Map<String, Value> = key
                .as_object()
                .cloned()
                .context("key entry must be an object")?;
            let id = jwk
                .get("kid")
                .and_then(Value::as_str)
                .context("key kid is required")?
                .to_owned();
            jwk.remove("alg");
            Ok(Secret {
                id,
                type_: SecretType::JsonWebKey2020,
                secret_material: SecretMaterial::JWK {
                    private_key_jwk: Value::Object(jwk),
                },
            })
        })
        .collect()
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let Some(inputs) = parse_args()? else {
        return Ok(());
    };
    let secrets = load_secrets(&inputs.key_file)?;
    let did_docs = inputs
        .did_docs
        .iter()
        .map(|path| read_json(path).and_then(normalized_did_doc))
        .collect::<Result<Vec<_>>>()?;
    let mut packed = String::new();
    io::stdin()
        .read_to_string(&mut packed)
        .context("read packed message")?;
    let did_resolver = ExampleDIDResolver::new(did_docs);
    let secrets_resolver = ExampleSecretsResolver::new(secrets);
    let (message, metadata) = Message::unpack(
        &packed,
        &did_resolver,
        &secrets_resolver,
        &UnpackOptions::default(),
    )
    .await
    .context("unpack DIDComm message")?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "encrypted": metadata.encrypted,
            "anonymous": metadata.anonymous_sender,
            "signed": metadata.authenticated,
            "message": message,
        }))?
    );
    Ok(())
}
