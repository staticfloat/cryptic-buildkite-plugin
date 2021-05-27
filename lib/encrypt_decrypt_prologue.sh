## There's a lot of shared code at the beginning of `encrypt` and `decrypt`
## so we list it out here so that it doesn't get too diverged as we fix bugs


# Get the RSA private keyfile path, so that we can decrypt the repo key
if [[ "$#" -ge "1" ]]; then
    PRIVATE_KEY_PATH="${1}"
else
    read -p 'Private keyfile location: ' PRIVATE_KEY_PATH
fi

# Double-check this is a valid private key
if ! is_rsa_private_key "${PRIVATE_KEY_PATH}"; then
    die "Not a valid RSA private key: '${PRIVATE_KEY_PATH}'"
fi

# Get the repository root
if [[ "$#" -ge "2" ]]; then
    REPO_ROOT="${2}"
else
    # If the user is running this from within a repository that is not `cryptic-buildkite-plugin`, then use it!
    REPO_ORIGIN_URL="$(git remote get-url origin 2>/dev/null || true)"
    if [[ -n ${REPO_ORIGIN_URL} ]] && [[ "${REPO_ORIGIN_URL}" != *cryptic-buildkite-plugin* ]]; then
        REPO_ROOT="$(git rev-parse --show-toplevel)"
        echo "Autodetected repository with origin '${REPO_ORIGIN_URL}'"
    else
        read -p 'Repository location: ' REPO_ROOT
    fi
fi

# Look for the repo key
RSA_FINGERPRINT=$(rsa_fingerprint "${PRIVATE_KEY_PATH}")
REPO_KEY_PATH="${REPO_ROOT}/.buildkite/cryptic_repo_keys/repo_key.${RSA_FINGERPRINT:0:8}"
if [[ ! -f "${REPO_KEY_PATH}" ]]; then
    die "repository keyfile ${REPO_KEY_PATH} does not exist!"
fi
