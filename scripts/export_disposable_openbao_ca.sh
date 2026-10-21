#!/bin/sh
# The private listener volume is mounted only in this one-shot export helper.
set -eu
source=/bao/tls/vault-ca.pem
target=/bao/public-ca/vault-ca.pem
if [ ! -s "$source" ] ||
   ! grep -q '^-----BEGIN CERTIFICATE-----$' "$source" ||
   grep -q 'PRIVATE KEY' "$source"; then
    echo 'OpenBao public CA is missing or contains private material' >&2
    exit 1
fi
cp "$source" "$target"
chmod 0444 "$target"
echo 'Disposable OpenBao public CA ready'
