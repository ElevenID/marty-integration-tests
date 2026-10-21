#!/bin/sh
# One disposable, HTTPS-only OpenBao engine bootstrap for the public stack.
set -eu
if [ "${BAO_ADDR:-}" != "https://openbao:8200" ] ||
   [ "${BAO_CACERT:-}" != "/bao/public-ca/vault-ca.pem" ] ||
   [ ! -s "${BAO_CACERT:-/dev/null}" ] || [ -z "${BAO_TOKEN:-}" ]; then
    echo 'Disposable OpenBao bootstrap requires a trusted HTTPS origin' >&2
    exit 1
fi
export VAULT_ADDR="$BAO_ADDR" VAULT_CACERT="$BAO_CACERT" VAULT_TOKEN="$BAO_TOKEN"
if ! bao secrets list -format=json | grep -q '"transit/"'; then
    bao secrets enable transit >/dev/null
fi
plugin=/plugins/openbao-didcomm-authcrypt
if [ ! -x "$plugin" ]; then
    echo 'Required DIDComm plugin is missing from the signed OpenBao image' >&2
    exit 1
fi
plugin_sha="$(sha256sum "$plugin" | cut -d ' ' -f 1)"
catalog_sha="$(bao plugin info -field=sha256 secret openbao-didcomm-authcrypt 2>/dev/null || true)"
if [ -n "$catalog_sha" ] && [ "$catalog_sha" != "$plugin_sha" ]; then
    echo 'Registered DIDComm plugin differs from signed image' >&2
    exit 1
fi
if [ -z "$catalog_sha" ]; then
    bao plugin register -sha256="$plugin_sha" secret openbao-didcomm-authcrypt >/dev/null
fi
if ! bao secrets list -format=json | grep -q '"didcomm/"'; then
    bao secrets enable -path=didcomm openbao-didcomm-authcrypt >/dev/null
fi
echo 'Disposable OpenBao engines ready'
