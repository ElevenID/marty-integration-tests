#!/bin/sh
# Generate short-lived service TLS material inside disposable Docker volumes.
set -eu
key_matches_certificate() {
    key_digest="$(openssl pkey -in /tls-server/tls.key -pubout -outform DER 2>/dev/null | openssl dgst -sha256)" || return 1
    cert_digest="$(openssl x509 -in /tls-server/tls.crt -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256)" || return 1
    [ "$key_digest" = "$cert_digest" ]
}
if [ -e /tls-server/tls.key ] || [ -e /tls-server/tls.crt ] ||
   [ -e /tls-ca/ca.crt ]; then
    if [ -f /tls-server/tls.key ] && [ -f /tls-server/tls.crt ] &&
       [ -f /tls-ca/ca.crt ] &&
       openssl verify -CAfile /tls-ca/ca.crt /tls-server/tls.crt >/dev/null 2>&1 &&
       openssl x509 -in /tls-server/tls.crt -checkend 300 -noout >/dev/null 2>&1 &&
       key_matches_certificate; then
        echo 'Disposable signing TLS material ready'
        exit 0
    fi
    echo 'Disposable signing TLS output is incomplete or expired' >&2
    exit 1
fi
umask 077
trap 'rm -f /tls-ca/ca.key /tls-ca/ca.srl /tls-server/server.csr /tls-server/server.ext' EXIT
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -nodes -keyout /tls-ca/ca.key -out /tls-ca/ca.crt \
    -days 1 -subj /CN=marty-disposable-signing-ca \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' >/dev/null 2>&1
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -nodes -keyout /tls-server/tls.key -out /tls-server/server.csr \
    -subj /CN=signing-keys >/dev/null 2>&1
printf '%s\n' 'basicConstraints=critical,CA:FALSE' \
    'keyUsage=critical,digitalSignature' 'extendedKeyUsage=serverAuth' \
    'subjectAltName=DNS:signing-keys' > /tls-server/server.ext
openssl x509 -req -in /tls-server/server.csr -CA /tls-ca/ca.crt \
    -CAkey /tls-ca/ca.key -CAcreateserial -out /tls-server/tls.crt \
    -days 1 -extfile /tls-server/server.ext >/dev/null 2>&1
chown 10001:10001 /tls-server /tls-server/tls.key /tls-server/tls.crt
chmod 0700 /tls-server
chmod 0400 /tls-server/tls.key
chmod 0444 /tls-server/tls.crt /tls-ca/ca.crt
echo 'Disposable signing TLS material ready'
