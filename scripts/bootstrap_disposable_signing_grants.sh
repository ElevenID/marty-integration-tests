#!/bin/sh
# Disposable public-stack signing authorization. The matching production
# policy owner is marty-ui/docker/openbao-init.sh.
set -eu

if [ "${BAO_ADDR:-}" != "http://openbao:8200" ] || [ -z "${BAO_TOKEN:-}" ]; then
    echo 'Disposable grant bootstrap requires the isolated OpenBao service' >&2
    exit 1
fi
export VAULT_ADDR="$BAO_ADDR" VAULT_TOKEN="$BAO_TOKEN"
if ! bao secrets list -format=json | grep -q '"transit/"'; then
    bao secrets enable transit >/dev/null
fi
bao write transit/keys/integration-secret-envelope-marty-aes256 \
    type=aes256-gcm96 exportable=false allow_plaintext_backup=false >/dev/null
if [ "$(bao read -field=type transit/keys/integration-secret-envelope-marty-aes256)" != aes256-gcm96 ] ||
   [ "$(bao read -field=exportable transit/keys/integration-secret-envelope-marty-aes256)" != false ] ||
   [ "$(bao read -field=allow_plaintext_backup transit/keys/integration-secret-envelope-marty-aes256)" != false ]; then
    echo 'Disposable integration-secret key lacks non-exportable custody' >&2
    exit 1
fi

origins='gateway-service gateway-issuer-did flow-wallet issuance-credential issuance-canvas issuance-readiness issuance-passport'
for origin in $origins; do
    key="marty-sign-grant-${origin}-v1"
    bao write "transit/keys/$key" type=hmac key_size=32 \
        exportable=false allow_plaintext_backup=false >/dev/null
    if [ "$(bao read -field=type "transit/keys/$key")" != hmac ] ||
       [ "$(bao read -field=exportable "transit/keys/$key")" != false ] ||
       [ "$(bao read -field=allow_plaintext_backup "transit/keys/$key")" != false ]; then
        echo 'Disposable grant key lacks non-exportable custody' >&2
        exit 1
    fi
    bao policy write "sign-grant-mint-$origin" - >/dev/null <<EOF
path "transit/hmac/$key/sha2-256" { capabilities = ["update"] }
EOF
done
for origin in $origins; do
    printf 'path "transit/verify/marty-sign-grant-%s-v1/sha2-256" { capabilities = ["update"] }\n' "$origin"
done | bao policy write sign-grant-verify - >/dev/null

write_token() {
    policy="$1"
    destination="$2"
    token="$(bao token create -policy="$policy" -no-default-policy -orphan -ttl=1h -renewable=false -field=token)"
    if [ -z "$token" ] || [ "$token" = "$BAO_TOKEN" ]; then
        echo 'Disposable scoped grant token creation failed' >&2
        exit 1
    fi
    key="${policy#sign-grant-mint-}"
    if [ "$policy" = sign-grant-verify ]; then
        allowed=transit/verify/marty-sign-grant-issuance-credential-v1/sha2-256
        denied=transit/hmac/marty-sign-grant-issuance-credential-v1/sha2-256
    else
        allowed="transit/hmac/marty-sign-grant-${key}-v1/sha2-256"
        denied="transit/verify/marty-sign-grant-${key}-v1/sha2-256"
    fi
    if [ "$(bao token capabilities "$token" "$allowed")" != update ] ||
       [ "$(bao token capabilities "$token" "$denied")" != deny ] ||
       [ "$(bao token capabilities "$token" auth/token/create)" != deny ]; then
        echo 'Disposable grant token scope check failed' >&2
        exit 1
    fi
    printf '%s' "$token" > "$destination"
    chown 10001:10001 "$destination"
    chmod 0400 "$destination"
}

umask 077
write_token sign-grant-verify /grant-verify/token
write_token sign-grant-mint-gateway-service /grant-gateway/service
write_token sign-grant-mint-gateway-issuer-did /grant-gateway/issuer-did
write_token sign-grant-mint-flow-wallet /grant-flow/token
for origin in credential canvas readiness passport; do
    write_token "sign-grant-mint-issuance-$origin" "/grant-issuance/$origin"
done
for directory in /grant-verify /grant-gateway /grant-flow /grant-issuance; do
    chown 10001:10001 "$directory"
    chmod 0700 "$directory"
done
echo 'Disposable scoped signing grants ready'
