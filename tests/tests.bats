#!/usr/bin/env bats

# export BUILDKITE_PLUGIN_COPPERMIND_S3_PREFIX="s3://julialang-buildkite-artifacts/testing"
# export BUILDKITE_PLUGIN_COPPERMIND_INPUTS_0=""
# export BUILDKITE_PLUGIN_COPPERMIND_OUTPUTS_0=""

load "$BATS_PATH/load.bash"
source "/plugin/lib/common.sh"
export PATH="${PATH}:/plugin/bin"

# We're going to create some git repos
git config --global user.email "test@test.com"
git config --global user.name "Testing Tester"


##############################################################################
##############                 CLI utilities                    ##############
##############################################################################

@test "create_agent_keypair" {
    dir="$(mktemp -d)"
    pushd "${dir}"

    # Create agent keypair, ensure it output what we expect
    run create_agent_keypair "${dir}/agent"
    assert_output --partial "Generating private key at ${dir}/agent.key"
    assert_output --partial "Generating public key at ${dir}/agent.pub..."
    assert_success

    # Ensure the files exist and are reasonable
    is_rsa_private_key "${dir}/agent.key"
    is_rsa_public_key "${dir}/agent.pub"

    popd
    rm -rf "${dir}"
}

function create_test_repo() {
    mkdir -p "${1}"
    git -C "${1}" init
    mkdir -p "${1}/.buildkite"
    touch "${1}/.buildkite/pipeline.yml"
    mkdir -p "${1}/src"
    echo "module Foo\nend" > "${1}/src/Foo.jl"
    git -C "${1}" add .
    git -C "${1}" commit -am "initial commit"
    git -C "${1}" remote add origin "git@github.com:username/repo.git"
}

@test "create_repo_key" {
    dir="$(mktemp -d)"

    # Create agent keypair, then create repository key
    create_agent_keypair "${dir}/agent"

    # Create test repository in `"${dir}/repo"`
    create_test_repo "${dir}/repo"

    # Test creating a repo key works
    run create_repo_key --public-key="${dir}/agent.pub" --repo-root="${dir}/repo" </dev/null
    assert_output --partial "Generating 1024-bit AES key and encrypting"
    assert_success
    [[ -f "${dir}/agent.pub" ]]
    [[ -f "${dir}/repo/.buildkite/cryptic_repo_keys/.gitignore" ]]
    [[ -f "${dir}/repo/.buildkite/cryptic_repo_keys/repo_key" ]]

    # Assert that our repo key is properly ignored
    git -C "${dir}/repo" check-ignore -q "${dir}/repo/.buildkite/cryptic_repo_keys/repo_key"

    # Test that if run again, it warns us that we already have an encrypted repo key
    run create_repo_key --public-key="${dir}/agent.pub" --repo-root="${dir}/repo" </dev/null
    assert_output --partial "Encrypted repo key already deployed"
    assert_success

    # Test that we can add encryptions for other agents
    create_agent_keypair "${dir}/second"
    run create_repo_key --public-key="${dir}/second.pub" --repo-root="${dir}/repo" </dev/null
    assert_output --partial "Encrypting pre-existing repo key"
    assert_success

    # Test that if we're missing our unencrypted repo key, we can't add for more agents:
    rm -f "${dir}/repo/.buildkite/cryptic_repo_keys/repo_key"
    create_agent_keypair "${dir}/third"
    run create_repo_key --public-key="${dir}/third.pub" --repo-root="${dir}/repo" </dev/null
    assert_output --partial "Other keys already deployed; you should manually decrypt first!"
    assert_failure

    rm -rf "${dir}"
}

@test "encrypt_file" {
    dir="$(mktemp -d)"
    create_agent_keypair "${dir}/agent"
    create_test_repo "${dir}/repo"
    create_repo_key --public-key="${dir}/agent.pub" --repo-root="${dir}/repo"
    REPO_KEY="${dir}/repo/.buildkite/cryptic_repo_keys/repo_key"

    # Encrypt a file
    run encrypt_file --repo-root="${dir}/repo" "${dir}/repo/src/Foo.jl" </dev/null
    assert_output --partial "Congratulations, you have successfully encrypted a secret."
    assert_output --partial "files:"
    assert_output --partial "- src/Foo.jl"
    assert_success

    # Ensure that we have an encrypted file, and that it decrypts to what we expect
    [[ -f "${dir}/repo/src/Foo.jl.encrypted" ]]
    DECRYPTED_DATA="$(decrypt_aes "${REPO_KEY}" <"${dir}/repo/src/Foo.jl.encrypted")"
    GROUNDTRUTH_DATA="$(cat ${dir}/repo/src/Foo.jl)"
    [[ "${DECRYPTED_DATA}" == "${GROUNDTRUTH_DATA}" ]]

    # Trying to encrypt a second time fails (won't overwrite existing encrypted secret)
    run encrypt_file --repo-root="${dir}/repo" "${dir}/repo/src/Foo.jl" </dev/null
    assert_output --partial "Encrypted file path '${dir}/repo/src/Foo.jl.encrypted' already exists"
    assert_failure

    # Trying to encrypt a nonexistent file fails
    run encrypt_file --repo-root="${dir}/repo" "${dir}/repo/src/blah.jl" </dev/null
    assert_output --partial "No such file or directory"
    assert_failure

    rm -rf "${dir}"
}

@test "encrypt_variable" {
    dir="$(mktemp -d)"
    create_agent_keypair "${dir}/agent"
    create_test_repo "${dir}/repo"
    create_repo_key --public-key="${dir}/agent.pub" --repo-root="${dir}/repo"

    # Encrypt a variable
    run encrypt_variable --repo-root="${dir}/repo" "FOO" "SECRET" </dev/null
    assert_output --partial "Congratulations, you have successfully encrypted a secret variable."
    assert_output --partial "variables:"
    assert_output --partial "- FOO="
    assert_success

    rm -rf "${dir}"
}

@test "encrypt_adhoc" {
    dir="$(mktemp -d)"
    create_agent_keypair "${dir}/agent"
    create_test_repo "${dir}/repo"
    #create_repo_key --public-key="${dir}/agent.pub" --repo-root="${dir}/repo"

    # Encrypt a variable
    run encrypt_adhoc --public-key="${dir}/agent.pub" --repo-root="${dir}/repo" "FOO" "SECRET" </dev/null
    assert_output --partial "Congratulations, you have successfully encrypted an ad-hoc secret variable."
    assert_output --partial "env:"
    assert_output --partial "  CRYPTIC_ADHOC_SECRET_FOO:"
    assert_success

    rm -rf "${dir}"
}

function copy_example_repo() {
    cp -ar "/plugin/example" "${1}"
    git -C "${1}" init
    git -C "${1}" add .
    git -C "${1}" commit -am "initial commit"
}

@test "decrypt" {
    dir="$(mktemp -d)"
    copy_example_repo "${dir}/repo"

    # Ensure we didn't copy over the codesign_key.txt (if we started in a decrypted state)
    rm -f .buildkite/secrets/codesign_key.txt
    
    # Decrypt `codesign.yaml`
    run decrypt --repo-root="${dir}/repo" "${dir}/repo/.buildkite/codesign.yml" </dev/null
    assert_output --partial "Found 0 encrypted variables, 1 files, and 0 adhoc variables"
    assert_output --partial "-> .buildkite/secrets/codesign_key.txt"
    assert_success

    [[ -f "${dir}/repo/.buildkite/secrets/codesign_key.txt" ]]
    [[ "$(cat ${dir}/repo/.buildkite/secrets/codesign_key.txt)" == "codesign key secret text" ]]

    # Ensure that decrypting a file a second time skips the file
    run decrypt --repo-root="${dir}/repo" "${dir}/repo/.buildkite/codesign.yml" </dev/null
    assert_output --partial "Found 0 encrypted variables, 1 files, and 0 adhoc variables"
    assert_output --partial "-> .buildkite/secrets/codesign_key.txt"
    assert_output --partial ", skipped)"
    assert_success

    # Decrypt `deploy.yml`
    run decrypt --repo-root="${dir}/repo" "${dir}/repo/.buildkite/deploy.yml" </dev/null
    assert_output --partial "Found 1 encrypted variables, 0 files, and 0 adhoc variables"
    assert_output --partial "-> S3_ACCESS_KEY=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    assert_success

    # Decrypt `pipeline.yml`
    run decrypt --repo-root="${dir}/repo" --private-key="${dir}/repo/agent.key" "${dir}/repo/.buildkite/pipeline.yml" </dev/null
    assert_output --partial "Found 0 encrypted variables, 0 files, and 1 adhoc variables"
    assert_output --partial "-> SSH_KEY=totally an ssh key"
    assert_success

    # Decrypt all files, showing that it displays everything
    run decrypt --repo-root="${dir}/repo" --private-key="${dir}/repo/agent.key" </dev/null
    assert_output --partial "Found 1 encrypted variables, 0 files, and 0 adhoc variables"
    assert_output --partial "-> S3_ACCESS_KEY=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    assert_output --partial "Found 0 encrypted variables, 1 files, and 0 adhoc variables"
    assert_output --partial "-> .buildkite/secrets/codesign_key.txt"
    assert_output --partial "Found 0 encrypted variables, 0 files, and 1 adhoc variables"
    assert_output --partial "-> SSH_KEY=totally an ssh key"
    assert_success

    rm -rf "${dir}"
}

@test "{sign,verify}_treehashes" {
    dir="$(mktemp -d)"
    copy_example_repo "${dir}/repo"

    # Test that the verification works first
    run verify_treehashes --repo-root="${dir}/repo" </dev/null
    assert_output --partial "[${dir}/repo/.buildkite/pipeline.yml] -> .buildkite/codesign.yml: ✔️"
    assert_output --partial "[${dir}/repo/.buildkite/codesign.yml] -> .buildkite/deploy.yml: ✔️"
    assert_success

    # Next, test that modifying `deploy.yml` breaks verification of `codesign` but not `pipeline`:
    echo >> "${dir}/repo/.buildkite/deploy.yml"
    run verify_treehashes --repo-root="${dir}/repo" "${dir}/repo/.buildkite/pipeline.yml" </dev/null
    assert_success
    run verify_treehashes --repo-root="${dir}/repo" "${dir}/repo/.buildkite/codesign.yml" </dev/null
    assert_failure

    # Now, re-sign `codesign.yml`:
    run sign_treehashes  --repo-root="${dir}/repo" "${dir}/repo/.buildkite/codesign.yml" </dev/null
    assert_output --partial "signature_file '.buildkite/deploy.yml.signature' updated"
    assert_success
    run verify_treehashes  --repo-root="${dir}/repo" "${dir}/repo/.buildkite/pipeline.yml" </dev/null
    assert_output --partial "[${dir}/repo/.buildkite/pipeline.yml] -> .buildkite/codesign.yml: ✔️"
    assert_success
    run verify_treehashes  --repo-root="${dir}/repo" "${dir}/repo/.buildkite/codesign.yml" </dev/null
    assert_output --partial "[${dir}/repo/.buildkite/codesign.yml] -> .buildkite/deploy.yml: ✔️"
    assert_success

    # Next, let's delete a signature file, and note that it auto-suggests embedding the
    # signature as a base64-encoded field in the YAML:
    rm -f "${dir}/repo/.buildkite/deploy.yml.signature"
    run sign_treehashes  --repo-root="${dir}/repo" "${dir}/repo/.buildkite/codesign.yml" </dev/null
    assert_output --partial "signature: "
    refute_output --partial "signature_file '.buildkite/deploy.yml.signature' updated"
    assert_success

    rm -rf "${dir}"
}