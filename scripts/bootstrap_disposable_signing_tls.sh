#!/bin/sh
# The disposable workload TLS leaf is public. Its signing key lives only in
# OpenBao Transit; the OpenBao dev listener's own key stays in its TLS volume.
set -eu

if [ "${BAO_ADDR:-}" != "https://openbao:8200" ] ||
   [ "${BAO_CACERT:-}" != "/bao/public-ca/vault-ca.pem" ] ||
   [ ! -s "${BAO_CACERT:-/dev/null}" ] || [ -z "${BAO_TOKEN:-}" ]; then
    echo 'Disposable TLS bootstrap requires trusted HTTPS OpenBao' >&2
    exit 1
fi
export VAULT_ADDR="$BAO_ADDR" VAULT_CACERT="$BAO_CACERT" VAULT_TOKEN="$BAO_TOKEN"

if [ -e /tls-server/tls.key ] || [ -e /tls-ca/ca.key ]; then
    echo 'Workload TLS private-key file is forbidden' >&2
    exit 1
fi
existing=false
if [ -e /tls-server/tls.crt ] || [ -e /tls-server/token ] || [ -e /tls-ca/ca.crt ]; then
    if [ ! -s /tls-server/tls.crt ] || [ ! -s /tls-server/token ] ||
       [ ! -s /tls-ca/ca.crt ] ||
       ! grep -q 'BEGIN CERTIFICATE' /tls-server/tls.crt ||
       ! grep -q 'BEGIN CERTIFICATE' /tls-ca/ca.crt ||
       grep -q 'PRIVATE KEY' /tls-server/tls.crt /tls-ca/ca.crt; then
        echo 'Disposable TLS volume is incomplete or contains private material' >&2
        exit 1
    fi
    existing=true
fi
key_path=transit/keys/oss-ci-signing-keys-tls
key_metadata="$(bao read -format=json "$key_path" 2>&1)" || {
    if [ "$key_metadata" != "No value found at $key_path" ]; then
        echo 'Disposable workload TLS key lookup failed' >&2
        exit 1
    fi
    key_metadata=
}
if [ "$existing" = true ] && [ -z "$key_metadata" ]; then
    if ! bao status -format=json | grep -q '"storage_type": "inmem"'; then
        echo 'Missing workload TLS key outside disposable in-memory OpenBao' >&2
        exit 1
    fi
    # `compose down` preserves named volumes but dev OpenBao loses its keys.
    # These files contain only public certificates and a scoped test token.
    rm -f /tls-server/tls.crt /tls-server/token /tls-ca/ca.crt
    existing=false
fi
if [ -z "$key_metadata" ]; then
    bao write transit/keys/oss-ci-signing-keys-tls \
        type=ecdsa-p256 exportable=false allow_plaintext_backup=false >/dev/null
fi
if [ "$(bao read -field=type transit/keys/oss-ci-signing-keys-tls)" != ecdsa-p256 ] ||
   [ "$(bao read -field=exportable transit/keys/oss-ci-signing-keys-tls)" != false ] ||
   [ "$(bao read -field=allow_plaintext_backup transit/keys/oss-ci-signing-keys-tls)" != false ]; then
    echo 'Disposable workload TLS signer lacks non-exportable custody' >&2
    exit 1
fi
if [ "$existing" = true ]; then
    token="$(cat /tls-server/token)"
    if [ "$token" = "$BAO_TOKEN" ] ||
       [ "$(bao token capabilities "$token" transit/sign/oss-ci-signing-keys-tls)" != update ] ||
       [ "$(bao token capabilities "$token" transit/sign/foreign-key)" != deny ]; then
        echo 'Existing disposable workload TLS token is not scoped' >&2
        exit 1
    fi
    echo 'Disposable keyless signing TLS identity ready'
    exit 0
fi

if ! bao secrets list -format=json | grep -q '"pki/"'; then
    bao secrets enable pki >/dev/null
fi
bao write -field=certificate pki/root/generate/internal \
    common_name=marty-disposable-signing-ca ttl=48h key_type=ec key_bits=256 \
    > /tls-ca/ca.crt
bao write pki/roles/oss-ci-signing-keys \
    allow_any_name=true server_flag=true client_flag=false \
    key_type=ec key_bits=256 max_ttl=24h use_csr_sans=false >/dev/null
csr="$(bao write -field=csr transit/keys/oss-ci-signing-keys-tls/csr version=1)"
bao write -field=certificate pki/sign/oss-ci-signing-keys \
    csr="$csr" common_name=signing-keys alt_names=signing-keys ttl=4h \
    > /tls-server/tls.crt
bao policy write oss-ci-signing-keys-tls - >/dev/null <<'POLICY'
path "transit/keys/oss-ci-signing-keys-tls" { capabilities = ["read"] }
path "transit/sign/oss-ci-signing-keys-tls" { capabilities = ["update"] }
POLICY
bao token create -field=token -policy=oss-ci-signing-keys-tls \
    -no-default-policy -orphan -ttl=4h -renewable=false > /tls-server/token
if [ "$(bao token capabilities "$(cat /tls-server/token)" transit/sign/oss-ci-signing-keys-tls)" != update ] ||
   [ "$(bao token capabilities "$(cat /tls-server/token)" transit/sign/foreign-key)" != deny ]; then
    echo 'Disposable workload TLS token is not scoped' >&2
    exit 1
fi
chown 10001:10001 /tls-server /tls-server/tls.crt /tls-server/token
chmod 0700 /tls-server
chmod 0444 /tls-server/tls.crt /tls-ca/ca.crt
chmod 0400 /tls-server/token
echo 'Disposable keyless signing TLS identity ready'
