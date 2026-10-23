#!/usr/bin/env bash
set -euo pipefail

cert_dir=/certs
scenario_dir="$cert_dir/scenarios"
force_regenerate=${FORCE_REGENERATE:-0}
mkdir -p "$cert_dir" "$scenario_dir"
umask 077

if [[ "$force_regenerate" == 1 ]]; then
    rm -rf "$scenario_dir"
    rm -f "$cert_dir/ca.key" "$cert_dir/ca.crt" "$cert_dir/ca.srl" "$cert_dir/server.key" "$cert_dir/server.csr" "$cert_dir/server.crt"
    mkdir -p "$scenario_dir"
fi

if [[ ! -f "$cert_dir/ca.crt" || ! -f "$cert_dir/ca.key" ]]; then
    openssl genrsa -out "$cert_dir/ca.key" 4096
    openssl req -x509 -new -sha256 -days 3650 -key "$cert_dir/ca.key" \
        -subj '/C=US/O=SecureMailScope Test PKI/CN=SecureMailScope Test Root CA' \
        -addext 'basicConstraints=critical,CA:TRUE,pathlen:1' \
        -addext 'keyUsage=critical,keyCertSign,cRLSign' \
        -addext 'subjectKeyIdentifier=hash' -out "$cert_dir/ca.crt"
fi

sign_profile() {
    local name=$1 common_name=$2 san=$3 bits=$4 expired=${5:-0} digest=${6:-sha256}
    local target="$scenario_dir/$name" ext_file
    [[ -f "$target/server.crt" && "$force_regenerate" != 1 ]] && return
    rm -rf "$target"; mkdir -p "$target"; cp "$cert_dir/ca.crt" "$target/ca.crt"
    openssl genrsa -out "$target/server.key" "$bits"
    openssl req -new -sha256 -key "$target/server.key" -subj "/C=US/O=SecureMailScope/CN=$common_name" -out "$target/server.csr"
    ext_file=$(mktemp)
    printf '%s\n' '[server_ext]' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature,keyEncipherment' \
        'extendedKeyUsage=serverAuth' "subjectAltName=$san" 'subjectKeyIdentifier=hash' 'authorityKeyIdentifier=keyid,issuer' > "$ext_file"
    if [[ "$expired" == 1 ]]; then
        local ca_config="$target/ca-sign.cnf"
        : > "$target/index.txt"; echo 1000 > "$target/serial"
        printf '%s\n' '[ca]' 'default_ca = local_ca' '[local_ca]' "database = $target/index.txt" "serial = $target/serial" "new_certs_dir = $target" "certificate = $cert_dir/ca.crt" "private_key = $cert_dir/ca.key" 'default_md = sha256' 'policy = policy_any' 'copy_extensions = none' '[policy_any]' 'commonName = supplied' 'organizationName = optional' 'countryName = optional' > "$ca_config"
        openssl ca -batch -config "$ca_config" -in "$target/server.csr" -out "$target/server.crt" -startdate 20200101000000Z -enddate 20200102000000Z -md "$digest" -extfile "$ext_file" -extensions server_ext
    else
        openssl x509 -req -"$digest" -days 825 -in "$target/server.csr" -CA "$cert_dir/ca.crt" -CAkey "$cert_dir/ca.key" -CAcreateserial -extfile "$ext_file" -extensions server_ext -out "$target/server.crt"
    fi
    rm -f "$ext_file"
    if [[ "$expired" == 0 ]]; then
        openssl verify -CAfile "$target/ca.crt" "$target/server.crt"
    else
        echo "Certificate profile: $name (intentionally expired; validation skipped)"
    fi
}

# Baseline preserves the original stable TLS 1.2 fixture certificate.
if [[ ! -f "$cert_dir/server.crt" || ! -f "$cert_dir/server.key" ]]; then
    sign_profile baseline_tmp mail.securemailscope.local 'DNS:mail.securemailscope.local,DNS:localhost' 2048
    cp "$scenario_dir/baseline_tmp/server."{crt,key,csr} "$cert_dir/"
    rm -rf "$scenario_dir/baseline_tmp"
fi

sign_profile expired mail.securemailscope.local 'DNS:mail.securemailscope.local,DNS:localhost' 2048 1
sign_profile expired_rsa4096 mail.securemailscope.local 'DNS:mail.securemailscope.local,DNS:localhost' 4096 1
sign_profile expired_sha1 mail.securemailscope.local 'DNS:mail.securemailscope.local,DNS:localhost' 2048 1 sha1
sign_profile wrong_san wrong.securemailscope.local 'DNS:wrong.securemailscope.local' 2048
# RSA-1024 is intentionally generated for a compatibility test. Modern OpenSSL
# may reject it at its default security level; the runner records that outcome.
sign_profile rsa1024 mail.securemailscope.local 'DNS:mail.securemailscope.local,DNS:localhost' 1024
sign_profile rsa4096 mail.securemailscope.local 'DNS:mail.securemailscope.local,DNS:localhost' 4096
sign_profile sha1 mail.securemailscope.local 'DNS:mail.securemailscope.local,DNS:localhost' 2048 0 sha1

if [[ ! -f "$scenario_dir/ecdsa/server.crt" || "$force_regenerate" == 1 ]]; then
    target="$scenario_dir/ecdsa"
    rm -rf "$target"; mkdir -p "$target"; cp "$cert_dir/ca.crt" "$target/ca.crt"
    openssl ecparam -name prime256v1 -genkey -noout -out "$target/server.key"
    openssl req -new -sha256 -key "$target/server.key" \
        -subj '/C=US/O=SecureMailScope/CN=mail.securemailscope.local' -out "$target/server.csr"
    ext_file=$(mktemp)
    printf '%s\n' '[server_ext]' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature' \
        'extendedKeyUsage=serverAuth' 'subjectAltName=DNS:mail.securemailscope.local,DNS:localhost' > "$ext_file"
    openssl x509 -req -sha256 -days 825 -in "$target/server.csr" -CA "$cert_dir/ca.crt" \
        -CAkey "$cert_dir/ca.key" -CAcreateserial -extfile "$ext_file" \
        -extensions server_ext -out "$target/server.crt"
    rm -f "$ext_file"
    openssl verify -CAfile "$target/ca.crt" "$target/server.crt"
fi

if [[ ! -f "$scenario_dir/expired_ecdsa/server.crt" || "$force_regenerate" == 1 ]]; then
    target="$scenario_dir/expired_ecdsa"
    rm -rf "$target"; mkdir -p "$target"; cp "$cert_dir/ca.crt" "$target/ca.crt"
    openssl ecparam -name prime256v1 -genkey -noout -out "$target/server.key"
    openssl req -new -sha256 -key "$target/server.key" \
        -subj '/C=US/O=SecureMailScope/CN=mail.securemailscope.local' -out "$target/server.csr"
    ext_file=$(mktemp)
    printf '%s\n' '[server_ext]' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature' \
        'extendedKeyUsage=serverAuth' 'subjectAltName=DNS:mail.securemailscope.local,DNS:localhost' > "$ext_file"
    ca_config="$target/ca-sign.cnf"
    : > "$target/index.txt"; echo 1000 > "$target/serial"
    printf '%s\n' '[ca]' 'default_ca = local_ca' '[local_ca]' "database = $target/index.txt" "serial = $target/serial" "new_certs_dir = $target" "certificate = $cert_dir/ca.crt" "private_key = $cert_dir/ca.key" 'default_md = sha256' 'policy = policy_any' 'copy_extensions = none' '[policy_any]' 'commonName = supplied' 'organizationName = optional' 'countryName = optional' > "$ca_config"
    openssl ca -batch -config "$ca_config" -in "$target/server.csr" -out "$target/server.crt" -startdate 20200101000000Z -enddate 20200102000000Z -md sha256 -extfile "$ext_file" -extensions server_ext
    rm -f "$ext_file"
    echo "Certificate profile: expired_ecdsa (intentionally expired; validation skipped)"
fi

if [[ ! -f "$scenario_dir/self_signed_leaf/server.crt" || "$force_regenerate" == 1 ]]; then
    target="$scenario_dir/self_signed_leaf"
    rm -rf "$target"; mkdir -p "$target"; cp "$cert_dir/ca.crt" "$target/ca.crt"
    openssl genrsa -out "$target/server.key" 2048
    openssl req -new -x509 -sha256 -days 825 -key "$target/server.key" \
        -subj '/C=US/O=SecureMailScope/CN=mail.securemailscope.local' \
        -addext 'basicConstraints=critical,CA:FALSE' \
        -addext 'keyUsage=critical,digitalSignature,keyEncipherment' \
        -addext 'extendedKeyUsage=serverAuth' \
        -addext 'subjectAltName=DNS:mail.securemailscope.local,DNS:localhost' \
        -out "$target/server.crt"
fi

for profile in "$cert_dir" "$scenario_dir"/*; do
    [[ -f "$profile/server.crt" ]] || continue
    echo "Certificate profile: ${profile#$cert_dir/}"
    openssl x509 -in "$profile/server.crt" -noout -subject -issuer -dates -ext subjectAltName
done
