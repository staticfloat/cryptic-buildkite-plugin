#!/bin/bash

set -eou pipefail
shopt -s extglob

# Helper function to kill execution when something goes wrong
function die() {
    echo "ERROR: ${1}" >&2
    if which buildkite-agent >/dev/null 2>/dev/null; then
        buildkite-agent annotate --style=error "${1}"
    fi
    exit 1
}

# We require `openssl` for basically everything
if [[ -z "$(which openssl 2>/dev/null)" ]]; then
    die "'openssl' tool required!"
fi


##############################################################################
##############                base64 utilities                  ##############
##############################################################################

# binary to base64 encoding/decoding, purposefully eliminating any linebreaks.
function base64enc() {
    openssl base64 -e -A
}
function base64dec() {
    tr -d '\n' | openssl base64 -d -A
}

# Generate N bytes ofrandom gibberish (encoded as base64, with no linebreaks) to stdout
function randbase64() {
    openssl rand -base64 "${1}" | tr -d '\n'
}

##############################################################################
##############                  RSA utilities                   ##############
##############################################################################

# Encrypt something using RSA with the RSA public key as the first argument
function encrypt_rsa() {
    openssl rsautl -encrypt -pubin -inkey "${1}"
}
# Decrypt something using RSA with the RSA private key as the first argument
function decrypt_rsa() {
    openssl rsautl -decrypt -inkey "${1}"
}

# Sign something using RSA with the RSA key as the first argument
function sign_rsa() {
    openssl dgst -sha256 -sign "${1}"
}
# Verify an RSA signature using the RSA key ($1) and the signature ($2), both as files
function check_rsa_signature() {
    openssl dgst -sha256 -verify "${1}" -signature "${2}"
}

# Get the SHA256 hash of an RSA key (autodetecting whether its public or private)
function rsa_fingerprint() {
    if is_rsa_public_key "${1}"; then
        openssl rsa -outform der -pubin -in "${1}" 2>/dev/null | openssl sha256 | cut -d' ' -f2
        return 0
    fi
    if is_rsa_private_key "${1}"; then
        openssl rsa -pubout -in "${1}" 2>/dev/null | openssl rsa -pubin -outform der 2>/dev/null | openssl sha256 | cut -d' ' -f2
        return 0
    fi
    echo "ERROR: invalid keyfile ${1}" >&2
    return 1
}

function is_rsa_public_key() {
    openssl rsa -inform PEM -pubin -in "${1}" -noout 2>/dev/null
}

function is_rsa_private_key() {
    openssl rsa -inform PEM -in "${1}" -noout 2>/dev/null
}

##############################################################################
##############                  AES utilities                   ##############
##############################################################################

# Encrypt something using AES with the symmetric key as the first argument
function encrypt_aes() {
    openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 -pass "file:${1}"
}
# Decrypt something using AES with the symmetric key as the first argument
function decrypt_aes() {
    openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -pass "file:${1}"
}

# Decrypt an AES key ($2) with an RSA key ($1), then use it to encrypt stdin
function decrypt_aes_key_then_encrypt() {
    # No matter what happens, this file dies when we leave
    local TEMP_KEYFILE=$(mktemp)
    trap "rm -f ${TEMP_KEYFILE}" EXIT

    # Decrypt the RSA-encrypted AES key into this temporary file
    decrypt_rsa "${1}" < "${2}" > "${TEMP_KEYFILE}"

    # Use the temporary keyfile to encrypt stdin
    encrypt_aes "${TEMP_KEYFILE}"

    # Clean up our keyfile and our trap
    shred -u "${TEMP_KEYFILE}"
    trap - EXIT
}

# Decrypt an AES key ($2) with an RSA key ($1), then use it to decrypt stdin
function decrypt_aes_key_then_decrypt() {
    # No matter what happens, this file dies when we leave
    local TEMP_KEYFILE=$(mktemp)
    trap "rm -f ${TEMP_KEYFILE}" EXIT

    # Decrypt the RSA-encrypted AES key into this temporary file
    decrypt_rsa "${1}" < "${2}" > "${TEMP_KEYFILE}"

    # Use the temporary keyfile to decrypt stdin
    decrypt_aes "${TEMP_KEYFILE}"

    # Clean up our keyfile and our trap
    shred -u "${TEMP_KEYFILE}"
    trap - EXIT
}

# Generate an AES key then encrypt it with the given RSA key
function gen_encrypted_aes_key() {
    openssl rand 128 | encrypt_rsa "${1}"
}


##############################################################################
##############                random utilities                  ##############
##############################################################################
function filesize() {
    du -b "${1}" | cut -f1
}

function collect_buildkite_array() {
    PARAMETER_NAME="${1}"
    local IDX=0
    while [[ -v "${PARAMETER_NAME}_${IDX}" ]]; do
        # Fetch the pattern
        VARNAME="${PARAMETER_NAME}_${IDX}"
        printf "%s\0" "${!VARNAME}"

        IDX=$((${IDX} + 1))
    done
}
