#!/usr/bin/env bash

set -eou pipefail
shopt -s extglob
shopt -s globstar


# Helper function to kill execution when something goes wrong
function die() {
    echo "ERROR: ${1}" >&2
    if which buildkite-agent >/dev/null 2>/dev/null; then
        # By default, the annotation context is unique to the message
        local CONTEXT=$(echo "${1}" | ${SHASUM})
        if [[ "$#" -gt 1 ]]; then
            CONTEXT="${2}"
        fi
        buildkite-agent annotate --context="${CONTEXT}" --style=error "${1}"
    fi
    exit 1
}

# Returns true if verbose mode is enabled
VERBOSE="${BUILDKITE_PLUGIN_CRYPTIC_VERBOSE:-${VERBOSE:-false}}"
function verbose() {
    [[ "${VERBOSE}" == "true" ]]
}

# Prints things out, but only if we're verbose
function vecho() {
    if verbose; then
        echo "$@" >&2
    fi
}
function vcat() {
    if verbose; then
        cat >&2
    else
        cat >/dev/null
    fi
}

# We require `openssl` for basically everything
if [[ -z "$(which openssl 2>/dev/null)" ]]; then
    die "'openssl' tool required!"
elif [[ "$(openssl version)" == "LibreSSL 2"* ]]; then
    # Homebrew doesn't like to link `openssl`, so let's manually pluck out a homebrew-installed `openssl`, if it exists
    HOMEBREW_PREFIX="$(dirname $(dirname $(which brew 2>/dev/null)))"
    for OPENSSL_DIR in ${HOMEBREW_PREFIX}/Cellar/openssl\@3/*; do
        if [[ -f "${OPENSSL_DIR}/bin/openssl" ]]; then
            echo " -> Homebrew OpenSSL installation found at ${OPENSSL_DIR}"
            PATH="${OPENSSL_DIR}/bin:${PATH}"
        fi
    done
    if [[ "$(openssl version)" == "LibreSSL 2"* ]]; then
        die "'openssl' tool outdated!  If you're on macOS, try 'brew install openssl@3'."
    fi
fi

# Figure out which shasum program to use
if [[ -n $(which sha256sum 2>/dev/null) ]]; then
    SHASUM="sha256sum"
elif [[ -n $(which shasum 2>/dev/null) ]]; then
    SHASUM="shasum -a 256"
else
    die "No sha256sum/shasum available!"
fi

# Figure out the best way to securely delete something
if [[ -n "$(which shred 2>/dev/null)" ]]; then
    function secure_delete() {
        for f in "$@"; do
            if [[ -e "${f}" ]]; then
                shred -u "${f}"
            fi
        done
    }
elif [[ "$(uname)" == "Darwin" ]] || [[ "$(uname)" == *BSD ]]; then
    function secure_delete() {
        rm -fP "$*"
    }
else
    # Suboptimal, but what you gonna do?
    function secure_delete() {
        rm -f "$*"
    }
fi

# Because it's so common to want to use `~/` in expanded paths,
# manually expand that to `$HOME` here. Gratefully adapted from
# https://stackoverflow.com/a/27485157/230778
function expandpath() {
    echo -n "${1/#\~/$HOME}"
}

# MSYS2 usually converts paths for us, but in the case of openssl's
# -pass file:/path/to/file argument style, it fails.  So we manually
# detect running on MSYS2 here, and invoke `cygpath -w` ourselves:
if [[ "$(uname)" == MINGW* ]]; then
    function winpath() {
        cygpath -w "$1"
    }
else
    function winpath() {
        echo -n "$1"
    }
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

# Generate N bytes of random gibberish (encoded as base64, with no linebreaks) to stdout
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
    openssl dgst -sha256 -verify "${1}" -signature "${2}" >/dev/null
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

function is_aes_key() {
    [[ "$(wc -c | xargs)" == "128" ]]
}

##############################################################################
##############                  AES utilities                   ##############
##############################################################################

# Encrypt something using AES with the symmetric key as the first argument
function encrypt_aes() {
    openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 -pass "file:$(winpath ${1})"
}
# Decrypt something using AES with the symmetric key as the first argument
function decrypt_aes() {
    openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -pass "file:$(winpath ${1})"
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
    secure_delete "${TEMP_KEYFILE}"
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
    secure_delete "${TEMP_KEYFILE}"
    trap - EXIT
}

# Our AES keys are just randomness
function gen_aes_key() {
    openssl rand 128
}

# Generate an AES key then encrypt it with the given RSA key
function gen_encrypted_aes_key() {
    gen_aes_key | encrypt_rsa "${1}"
}



# ad-hoc encrypt a secret ${2} with the public key of an agent ${1}.
# Generates an ad-hoc key, encrypts the secret with that key, then
# encrypts both with the public key of the agent.
function encrypt_adhoc_value() {
    # No matter what happens, this file dies when we leave
    local TEMP_KEYFILE=$(mktemp)
    trap "rm -f ${TEMP_KEYFILE}" EXIT

    # Generate an AES key, save it out to `TEMP_KEYFILE` for `encrypt_aes`
    gen_aes_key > "${TEMP_KEYFILE}"


    # encrypt the AES key with the public key of the agent
    encrypt_rsa "${1}" <"${TEMP_KEYFILE}" | base64enc

    # Separate with a semicolon
    echo -n ";"

    # Use AES encryption to generate the encrypted secret
    encrypt_aes "${TEMP_KEYFILE}" <<<"${2}" | base64enc

    # Clean up our keyfile and our trap
    secure_delete "${TEMP_KEYFILE}"
    trap - EXIT
}

# Decrypt an ad-hoc encrypted key/secret pair ${2} with the private
# key of an agent ${1}.
function decrypt_adhoc_value() {
    # No matter what happens, this file dies when we leave
    local TEMP_KEYFILE=$(mktemp)
    trap "rm -f ${TEMP_KEYFILE}" EXIT

    # We need to save stdin after splitting by `;`, so save it in an array
    readarray -d';' -t ADHOC_PAIR

    # Take the key, decrypt it with our RSA private key
    base64dec <<<"${ADHOC_PAIR[0]}" | decrypt_rsa "${1}" > "${TEMP_KEYFILE}"

    if ! is_aes_key <"${TEMP_KEYFILE}"; then
        die "Invalid AES key embedded in ad-hoc secret, counted $(wc -c <"${TEMP_KEYFILE}") bytes!"
    fi

    # Use that decrypted key to decrypt our secret
    base64dec <<<"${ADHOC_PAIR[1]}" | decrypt_aes "${TEMP_KEYFILE}"

    # Clean up our keyfile and our trap
    secure_delete "${TEMP_KEYFILE}"
    trap - EXIT
}

##############################################################################
##############                   treehashing                    ##############
##############################################################################


function collect_glob_pattern() {
    # First argument is either a glob pattern, or a directory.  If it is a directory,
    # we add `/**/*` to it in order to select everything underneath it.
    local target="${1}"
    local prefix="${1}"
    if [[ -d "${target}" ]]; then
        target="${target}/**/*"
    fi

    # Iterate over the glob pattern
    for f in ${target}; do
        # Ignore directories, only list files
        if [[ -f ${f} ]]; then
            printf "%s\0" "${f}"
        fi
    done
}

function calc_shasum() {
    ${SHASUM} "$@" | awk '{ print $1 }'
}

# poor man's treehash of a set of files; use with `collect_glob_pattern`
function calc_treehash() {
    # Fill `FILES` with all the files we're calculating the treehash over
    readarray -d '' FILES

    # If we have no files, exit early!
    if [[ "${#FILES[@]}" == 0 ]]; then
        calc_shasum < /dev/null | awk '{ print $1 }'
        return
    fi

    # Next, we fold things up into directories
    declare -A DIR_HASHES
    for f in $(sort <<< "${FILES[@]}"); do
        hash=$(calc_shasum "${f}" | awk '{ print $1 }')
        dir=$(dirname "${f}")
        DIR_HASHES["${dir}"]+=" $(basename ${f}) ${hash}"
    done

    # Collapse directories into their parents until none survive
    while [[ ${#DIR_HASHES[@]} -gt 1 ]]; do
        DIRS=$(tr ' ' '\n' <<< "${!DIR_HASHES[@]}")
        for f in $(sort <<< "${DIRS}"); do
            # If this directory appears only once, move it up to its parent
            if [[ "$(egrep "^${f}" <<< "${DIRS}")" == "${f}" ]]; then
                dir=$(dirname "${f}")
                hash=$( calc_shasum <<< "${DIR_HASHES["${f}"]}" | awk '{ print $1 }')
                DIR_HASHES["${dir}"]+=" $(basename ${f}) ${hash}"
                unset DIR_HASHES["${f}"]
            fi
        done
    done

    calc_shasum <<< "${DIR_HASHES[@]}"
}


##############################################################################
##############          utiltiies for bin/ scripts              ##############
##############################################################################



function find_private_key() {
    # This is where we typically cache our private key
    DEFAULT_AGENT_PRIVATE_KEY_PATH="${REPO_ROOT}/.buildkite/cryptic_repo_keys/agent.key"

    # Allow the user to provide this through an environment variable
    if [[ -v "CRYPTIC_AGENT_PRIVATE_KEY_PATH" ]]; then
        AGENT_PRIVATE_KEY_PATH="${CRYPTIC_AGENT_PRIVATE_KEY_PATH}"
    fi

    # If we haven't already set `AGENT_PRIVATE_KEY_PATH` (e.g. from `argparse.sh`)
    # then first check to see if it's added to this repository:
    if [[ ! -v "AGENT_PRIVATE_KEY_PATH" ]]; then
        if [[ ! -f "${DEFAULT_AGENT_PRIVATE_KEY_PATH}" ]]; then
            # If we don't already have an agent private key cached in our `cryptic_repo_keys`
            # ask for it from the user, then symlink it into our cached location
            read -e -p 'Private keyfile location: ' AGENT_PRIVATE_KEY_PATH
            AGENT_PRIVATE_KEY_PATH="$(expandpath "${AGENT_PRIVATE_KEY_PATH}")"
        else
            AGENT_PRIVATE_KEY_PATH="${DEFAULT_AGENT_PRIVATE_KEY_PATH}"
        fi
    fi

    # Double-check this is a valid private key
    if ! is_rsa_private_key "${AGENT_PRIVATE_KEY_PATH}"; then
        die "Not a valid RSA private key: '${AGENT_PRIVATE_KEY_PATH}'"
    fi

    # If we've successfully found a private key, if it's externally-provided, lets
    # cache its location in our `cryptic_repo_keys` folder
    if [[ ! -e "${AGENT_PRIVATE_KEY_PATH}" ]]; then
        mkdir -p "$(dirname "${AGENT_PRIVATE_KEY_PATH}")"
        ln -s "${DEFAULT_AGENT_PRIVATE_KEY_PATH}" "${AGENT_PRIVATE_KEY_PATH}"
    fi
}

function find_public_key() {
    # This is where we typically cache our public key
    DEFAULT_AGENT_PUBLIC_KEY_PATH="${REPO_ROOT}/.buildkite/cryptic_repo_keys/agent.pub"

    # Allow the user to provide this through an environment variable
    if [[ -v "CRYPTIC_AGENT_PUBLIC_KEY_PATH" ]]; then
        AGENT_PUBLIC_KEY_PATH="${CRYPTIC_AGENT_PUBLIC_KEY_PATH}"
    fi

    # If we haven't already set `AGENT_PUBLIC_KEY_PATH` (e.g. from `argparse.sh`)
    # then first check to see if it's added to this repository:
    if [[ ! -v "AGENT_PUBLIC_KEY_PATH" ]]; then
        if [[ ! -f "${DEFAULT_AGENT_PUBLIC_KEY_PATH}" ]]; then
            # If we don't already have an agent public key cached in our `cryptic_repo_keys`
            # ask for it from the user, then symlink it into our cached location
            read -e -p 'Public keyfile location: ' AGENT_PUBLIC_KEY_PATH
            AGENT_PUBLIC_KEY_PATH="$(expandpath "${AGENT_PUBLIC_KEY_PATH}")"
        else
            AGENT_PUBLIC_KEY_PATH="${DEFAULT_AGENT_PUBLIC_KEY_PATH}"
        fi
    fi

    # Double-check this is a valid public key
    if ! is_rsa_public_key "${AGENT_PUBLIC_KEY_PATH}"; then
        die "Not a valid RSA public key: '${AGENT_PUBLIC_KEY_PATH}'"
    fi

    # If we've successfully found a public key, if it's externally-provided, lets
    # cache its location in our `cryptic_repo_keys` folder
    if [[ ! -e "${AGENT_PUBLIC_KEY_PATH}" ]]; then
        mkdir -p "$(dirname "${AGENT_PUBLIC_KEY_PATH}")"
        ln -s "${DEFAULT_AGENT_PUBLIC_KEY_PATH}" "${AGENT_PUBLIC_KEY_PATH}"
    fi
}

function find_repository_root() {
    if [[ ! -v "REPO_ROOT" ]]; then
        # If the user is running this from within a repository that is not `cryptic-buildkite-plugin`, then use it!
        REPO_ORIGIN_URL="$(git remote get-url origin 2>/dev/null || true)"
        if [[ -n ${REPO_ORIGIN_URL} ]] && [[ "${REPO_ORIGIN_URL}" != *cryptic-buildkite-plugin* ]]; then
            REPO_ROOT="$(git rev-parse --show-toplevel)"
            echo "Autodetected repository with origin '${REPO_ORIGIN_URL}'"
        else
            # Otherwise, just ask the user
            read -e -p 'Repository location: ' REPO_ROOT
            REPO_ROOT="$(expandpath "${REPO_ROOT}")"
        fi
    fi

    # Trim trailing slashes, because they're ugly
    REPO_ROOT="${REPO_ROOT%%+(/)}"
}

function find_repo_key() {
    if [[ -v "REPO_KEY_PATH" ]]; then
        return
    fi

    # First, check to see if we have a decrypted repo key:
    REPO_KEY_PATH="${REPO_ROOT}/.buildkite/cryptic_repo_keys/repo_key"
    if [[ -f "${REPO_KEY_PATH}" ]]; then
        return
    fi

    # If we don't have a decrypted repo key, let's try decrypting one using an agent private key, if we have it
    if [[ -v "AGENT_PRIVATE_KEY_PATH" ]]; then
        RSA_FINGERPRINT=$(rsa_fingerprint "${AGENT_PRIVATE_KEY_PATH}")
        ENCRYPTED_REPO_KEY_PATH="${REPO_ROOT}/.buildkite/cryptic_repo_keys/repo_key.${RSA_FINGERPRINT:0:8}"
        if [[ -f "${ENCRYPTED_REPO_KEY_PATH}" ]]; then
            # Decrypt the RSA-encrypted AES key into our unencrypted key path
            decrypt_rsa "${AGENT_PRIVATE_KEY_PATH}" <"${ENCRYPTED_REPO_KEY_PATH}" >"${REPO_KEY_PATH}"
            return
        fi
    fi

    # Otherwise, let's complain that we can't find our repository key
    die "repository keyfile not found, or no private agent key available to decrypt!"
}

function find_yaml_paths() {
    # First, check to see if we've already collected a set of YAML paths:
    if [[ -v "YAML_PATHS" ]]; then
        return
    fi

    # We'll collect a glob pattern if we've been given it, defaulting to searching
    # ${REPO_ROOT}/.buildkite for all `.yml` files.
    YAML_SEARCH_PATH="${1:-${REPO_ROOT}/.buildkite/**/*.yml}"

    vecho "Searching for '.yml' files with the pattern '${YAML_SEARCH_PATH}'"
    readarray -d '' YAML_PATHS < <(collect_glob_pattern "${YAML_SEARCH_PATH}")
    
    if [[ "${#YAML_PATHS[@]}" -lt 1 ]]; then
        die "Unable to find any .yml files in the given pattern '${YAML_SEARCH_PATH}'!"
    fi

    vecho "  -> Found ${#YAML_PATHS[@]} .yml files"
}


##############################################################################
##############                random utilities                  ##############
##############################################################################

# Print file size, in kilobytes
function filesize() {
    du -k "${1}" | cut -f1
}

# Read a secret value from stdin, printing `*`'s to stdout as we go
function read_secret() {
    if [[ "${1}" == "-p" ]]; then
        # Display the prompt to the user
        echo -n "${2}"
        shift; shift;
    fi

    # Turn off `echo` for this TTY, but be sure it comes back on
    stty -echo
    trap "stty echo" EXIT ERR

    local _INTERNAL_SECRET_VALUE=""
    while IFS= read -N1 c; do
        # I don't know of a cheaper way to find newlines
        hex="$(echo -n "${c}" | xxd -pu)"
        if [[ "${hex}" == "0a" ]] || [[ "${hex}" == "0d" ]]; then
            break
        fi

        # Append to `_INTERNAL_SECRET_VALUE`
        _INTERNAL_SECRET_VALUE="${_INTERNAL_SECRET_VALUE}${c}"

        # Print out to the user
        echo -n "*"
    done
    echo

    # Turn `echo` on on our TTY again
    stty echo
    trap - EXIT ERR

    # Return value to the user
    eval "${1}=\"${_INTERNAL_SECRET_VALUE}\""
}

function collect_buildkite_array() {
    PARAMETER_NAME="${1}"
    SUFFIX="${2:-}"
    if [[ -n "${SUFFIX}" ]] && [[ "${SUFFIX}" != _* ]]; then
        SUFFIX="_${SUFFIX}"
    fi

    local IDX=0
    while [[ -v "${PARAMETER_NAME}_${IDX}${SUFFIX}" ]]; do
        # Fetch the pattern
        VARNAME="${PARAMETER_NAME}_${IDX}${SUFFIX}"
        printf "%s\0" "${!VARNAME}"

        IDX=$((${IDX} + 1))
    done
}

function receive_keys() {
    # If we think we are authorized, let's check to make sure that our secret keys are actually valid
    AGENT_PRIVATE_KEY_PATH=$(mktemp)
    base64dec <<<"${BUILDKITE_PLUGIN_CRYPTIC_BASE64_AGENT_PRIVATE_KEY_SECRET}" >"${AGENT_PRIVATE_KEY_PATH}"
    if ! is_rsa_private_key "${AGENT_PRIVATE_KEY_PATH}"; then
        die "Invalid RSA private key passed from agent environment hook!"
    fi

    AGENT_PUBLIC_KEY_PATH=$(mktemp)
    base64dec <<<"${BUILDKITE_PLUGIN_CRYPTIC_BASE64_AGENT_PUBLIC_KEY_SECRET}" >"${AGENT_PUBLIC_KEY_PATH}"
    if ! is_rsa_public_key "${AGENT_PUBLIC_KEY_PATH}"; then
        die "Invalid RSA public key passed from agent environment hook!"
    fi

    # Search for repository key based off of the private key fingerprint
    RSA_FINGERPRINT=$(rsa_fingerprint "${AGENT_PRIVATE_KEY_PATH}")
    REPO_KEY_PATH=".buildkite/cryptic_repo_keys/repo_key.${RSA_FINGERPRINT:0:8}"
    if [[ ! -f "${REPO_KEY_PATH}" ]]; then
        die "Cannot find expected repo key at '${REPO_KEY_PATH}'!  Ensure you have added the repository key to ${BUILDKITE_REPO}"
    fi
    UNENCRYPTED_REPO_KEY_PATH=$(mktemp)
    decrypt_rsa "${AGENT_PRIVATE_KEY_PATH}" < "${REPO_KEY_PATH}" > "${UNENCRYPTED_REPO_KEY_PATH}"
}

function cleanup_keys() {
    secure_delete "${AGENT_PRIVATE_KEY_PATH}" "${AGENT_PUBLIC_KEY_PATH}" "${UNENCRYPTED_REPO_KEY_PATH}"
    unset AGENT_PRIVATE_KEY_PATH AGENT_PUBLIC_KEY_PATH UNENCRYPTED_REPO_KEY_PATH RSA_FINGERPRINT
}
