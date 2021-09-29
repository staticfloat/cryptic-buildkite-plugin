#!/bin/bash

set -eou pipefail

## A foundational concept for the usage of this hook is that we can deny access to secrets
## (such as the agent private key or the build token file) by deleting or unmounting the
## `/secrets` folder.  This agent should always be running within some kind of sandbox,
## whether that be a Docker container or whatever.  When the job is finished, the buildkite
## agent should exit, causing the docker container to restart and restore the deleted files.
## This gives us the capability to deny access to these files to later steps within the
## current buildkite job.
SECRETS_MOUNT_POINT="/secrets"

## The secrets that must be contained within:
##    - `agent.{key,pub}`: An RSA private/public keypair (typically generated via the
##       script `bin/create_agent_keypair`).  See the top-level `README.md` for more.
##    - `buildkite-api-token`: A buildkite API token (with `read_builds` permission).

# Helper function
function die() {
    echo "ERROR: ${1}" >&2
    buildkite-agent annotate --style=error "${1}"
    exit 1
}

function base64dec() {
    tr -d '\n' | openssl base64 -d -A
}

function base64enc() {
    openssl base64 -e -A
}

# Set this to wherever your private key lives
PRIVATE_KEY_PATH="${SECRETS_MOUNT_POINT}/agent.key"
PUBLIC_KEY_PATH="${SECRETS_MOUNT_POINT}/agent.pub"
if [[ ! -f "${PRIVATE_KEY_PATH}" ]]; then
    die "Unable to open agent private key path '${PRIVATE_KEY_PATH}'!  Make sure your agent has this file deployed within it!"
else
    if ! openssl rsa -inform PEM -in "${PRIVATE_KEY_PATH}" -noout 2>/dev/null; then
        die "Secret private key path '${PRIVATE_KEY_PATH}' is not a valid private RSA key!"
    fi
fi
if [[ ! -f "${PUBLIC_KEY_PATH}" ]]; then
    die "Unable to open agent public key path '${PUBLIC_KEY_PATH}'!  Make sure your agent has this file deployed within it!"
else
    if ! openssl rsa -inform PEM -pubin -in "${PUBLIC_KEY_PATH}" -noout 2>/dev/null; then
        die "Secret public key path '${PUBLIC_KEY_PATH}' is not a valid public RSA key!"
    fi
fi

# Create a buildkite token with `read_builds` permissions, paste it in here.
BUILDKITE_TOKEN_PATH="${SECRETS_MOUNT_POINT}/buildkite-api-token"
if [[ ! -f "${BUILDKITE_TOKEN_PATH}" ]]; then
    die "Unable to open buildkite token path '${BUILDKITE_TOKEN_PATH}'!  Make sure your agent has this file deployed within it! "
fi
BUILDKITE_TOKEN="$(cat "${BUILDKITE_TOKEN_PATH}")"
if ! [[ "${BUILDKITE_TOKEN}" =~ ^[[:xdigit:]]{40}$ ]]; then
    die "Buildkite token stored at '${BUILDKITE_TOKEN_PATH}' is not a 40-length hexadecimal hash!"
fi

# Helper function to get the first job ID from the currently-running build
function get_initial_job_id() {
    local TOKEN_HEADER="Authorization: Bearer ${BUILDKITE_TOKEN}"
    local URL="https://api.buildkite.com/v2/organizations/${BUILDKITE_ORGANIZATION_SLUG}/pipelines/${BUILDKITE_PIPELINE_SLUG}/builds/${BUILDKITE_BUILD_NUMBER}"
    curl -sfL -H "${TOKEN_HEADER}" "${URL}" | jq '.jobs[0].id' | tr -d '"'
}
export BUILDKITE_INITIAL_JOB_ID="$(get_initial_job_id)"
if ! [[ "${BUILDKITE_INITIAL_JOB_ID}" =~ ^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$ ]]; then
    die "Initial job ID does not look like a UUID: '${BUILDKITE_INITIAL_JOB_ID}'"
fi

function set_cryptic_privileged() {
    # The first thing we do is export a base64-encoded form of the keys for later consumption by the cryptic plugin
    echo "Privileged build detected; unlocking private key"
    export BUILDKITE_PLUGIN_CRYPTIC_BASE64_AGENT_PRIVATE_KEY_SECRET="$(base64enc < "${PRIVATE_KEY_PATH}")"
    export BUILDKITE_PLUGIN_CRYPTIC_BASE64_AGENT_PUBLIC_KEY_SECRET="$(base64enc < "${PUBLIC_KEY_PATH}")"
    export BUILDKITE_PLUGIN_CRYPTIC_PRIVILEGED=true

    # The next thing we do is search for `CRYPTIC_ADHOC_SECRET_*` variables and decrypt them.
    # These should only be used for things like SSH keys, which need to be decrypted before we
    # even have a chance to check out the repository.
    for LONG_ADHOC_NAME in $(set | cut -d"=" -f 1 | grep -E "^CRYPTIC_ADHOC_SECRET_[^ ]+"); do
        EXPORTED_NAME="${LONG_ADHOC_NAME:21}"
        echo " --> Decrypting ad-hoc secret ${EXPORTED_NAME}"

        # No matter what happens, this file dies when we leave
        local TEMP_KEYFILE=$(mktemp)
        trap "rm -f ${TEMP_KEYFILE}" EXIT

        # Use `readarray` to split our combined key/value envvar
        readarray -d';' -t ADHOC_PAIR <<<"${!LONG_ADHOC_NAME}"
        
        # Take the key, decrypt it with our RSA private key
        base64dec <<<"${ADHOC_PAIR[0]}" | openssl rsautl -decrypt -inkey "${PRIVATE_KEY_PATH}" > "${TEMP_KEYFILE}"

        # Make sure the AES key is the right length
        if [[ $(wc -c <"${TEMP_KEYFILE}") != "128" ]]; then
            die "Invalid AES key embedded in ad-hoc secret '${EXPORTED_NAME}', counted '$(wc -c <"${TEMP_KEYFILE}")' bytes instead of 128!"
        fi

        export "${EXPORTED_NAME}"="$(base64dec <<<"${ADHOC_PAIR[1]}" | openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -pass "file:${TEMP_KEYFILE}")"

        # Clean up our keyfile and our trap
        shred -u "${TEMP_KEYFILE}"
        trap - EXIT
        unset ADHOC_PAIR
    done
}

# Now that we have our keys and our buildkite token, we decide whether the keys should be exported into
# the environment or not.  We only do this if one of two conditions are met:
#
#  - If we are the first job to run in this build, we are automatically authorized, as the first job is defined
#    within the WebUI, so it is assumed secure from drive-by pull requests.
#  - If we have an environment variable (`BUILDKITE_PLUGIN_CRYPTIC_BASE64_SIGNED_JOB_ID_SECRET`) and it correctly
#    verifies as a signature on the initial job ID, we consider ourselves a launched child pipeline

if [[ "${BUILDKITE_JOB_ID}" == "${BUILDKITE_INITIAL_JOB_ID}" ]]; then
    set_cryptic_privileged
elif [[ -v "BUILDKITE_PLUGIN_CRYPTIC_BASE64_SIGNED_JOB_ID_SECRET" ]]; then
    # Decode the base64-encoded signature and dump it to a file
    SIGNATURE_FILE="$(mktemp)"
    trap "rm -f ${SIGNATURE_FILE}" EXIT
    openssl base64 -d -A <<<"${BUILDKITE_PLUGIN_CRYPTIC_BASE64_SIGNED_JOB_ID_SECRET}" > "${SIGNATURE_FILE}"

    # Verify that the signature is valid; if it is, then unlock the keys!
    if openssl dgst -sha256 -verify "${PUBLIC_KEY_PATH}" -signature "${SIGNATURE_FILE}" <<<"${BUILDKITE_INITIAL_JOB_ID}"; then
        set_cryptic_privileged
    fi

    rm -f "${SIGNATURE_FILE}"
    trap - EXIT
fi


## Cleanup: Deny access to secrets to future pipeline steps by either unmounting `/secrets`
#  or just deleting the files inside, if that doesn't work.  If neither work, we abort the build.
if ! umount "${SECRETS_MOUNT_POINT}" 2>/dev/null; then
    if ! rm -rf "${SECRETS_MOUNT_POINT}"; then
        die "Unable to unmount secrets at '${SECRETS_MOUNT_POINT}'!  Aborting build!"
    fi
fi

# don't pollute the global namespace
unset SECRETS_MOUNT_POINT BUILDKITE_TOKEN_PATH BUILDKITE_TOKEN PRIVATE_KEY_PATH ADHOC_PAIR
