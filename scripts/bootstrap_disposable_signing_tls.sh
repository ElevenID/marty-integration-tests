#!/bin/sh
# Reuse the services image's keyless TLS provisioner. The signing leaf key
# remains non-exportable in this stack's disposable OpenBao Transit mount.
set -eu

if [ "${BAO_ADDR:-}" != 'https://openbao:8200' ] ||
   [ "${BAO_CACERT:-}" != '/run/openbao-ca/ca.crt' ] ||
   [ "${MARTY_TLS_BOOTSTRAP_PROFILE:-}" != 'selfhost-disposable' ] ||
   [ "${SELFHOST_TLS_OUTPUT_DIR:-}" != '/bootstrap-output' ] ||
   [ -z "${BAO_DEV_ROOT_TOKEN:-}" ]; then
    echo 'Disposable signing TLS bootstrap requires isolated HTTPS OpenBao' >&2
    exit 1
fi

umask 077
chmod 0700 /bootstrap-input /bootstrap-output
printf '%s' "$BAO_DEV_ROOT_TOKEN" > /bootstrap-input/root.token
chmod 0400 /bootstrap-input/root.token

# Compose can start a completed dependency again. Reuse only a still-valid
# certificate whose scoped token is accepted by this OpenBao instance.
if [ -e /tls-server/signing_keys_workload_server_cert ] ||
   [ -e /tls-server/signing_keys_tls_kms_token ] ||
   [ -e /tls-ca/ca.crt ]; then
    if [ -f /tls-server/signing_keys_workload_server_cert ] &&
       [ -f /tls-server/signing_keys_tls_kms_token ] &&
       [ -f /tls-ca/ca.crt ] &&
       openssl verify -CAfile /tls-ca/ca.crt \
           /tls-server/signing_keys_workload_server_cert >/dev/null 2>&1 &&
       openssl x509 -in /tls-server/signing_keys_workload_server_cert \
           -checkend 300 -noout >/dev/null 2>&1 &&
       curl --fail --silent --show-error --max-time 5 --cacert "$BAO_CACERT" \
           --header "X-Vault-Token: $(cat /tls-server/signing_keys_tls_kms_token)" \
           --header 'Content-Type: application/json' \
           --data '{"input":"dGVzdA=="}' \
           "$BAO_ADDR/v1/transit/sign/workload-tls-signing-keys-server" >/dev/null 2>&1; then
        echo 'Disposable keyless signing TLS material ready'
        exit 0
    fi
    echo 'Disposable signing TLS is stale or incomplete; start a fresh Compose project or run down --volumes on this disposable stack' >&2
    exit 1
fi

SELFHOST_TLS_OUTPUT_DIR="$(mktemp -d /bootstrap-output/run.XXXXXX)"
export SELFHOST_TLS_OUTPUT_DIR
/usr/local/bin/marty-passport-tls-bootstrap

cp "$SELFHOST_TLS_OUTPUT_DIR/signing_keys_workload_server_cert" /tls-server/signing_keys_workload_server_cert
cp "$SELFHOST_TLS_OUTPUT_DIR/signing_keys_tls_kms_token" /tls-server/signing_keys_tls_kms_token
cp "$SELFHOST_TLS_OUTPUT_DIR/workload_identity_ca_cert" /tls-ca/ca.crt
chown 10001:10001 /tls-server /tls-server/signing_keys_workload_server_cert \
    /tls-server/signing_keys_tls_kms_token
chmod 0700 /tls-server
chmod 0444 /tls-server/signing_keys_workload_server_cert /tls-ca/ca.crt
chmod 0400 /tls-server/signing_keys_tls_kms_token
echo 'Disposable keyless signing TLS material ready'
