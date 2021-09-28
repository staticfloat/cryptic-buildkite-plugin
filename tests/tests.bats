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
}

@test "create_repo_key" {
    dir="$(mktemp -d)"

    # Create agent keypair, then create repository key
    create_agent_keypair "${dir}/agent"

    # Create test repository in `"${dir}/repo"`
    create_test_repo "${dir}/repo"
    pushd "${dir}/repo"

    # Test creating a repo key works
    run create_repo_key "${dir}/agent.pub" "${dir}/repo"
    assert_output --partial "Generating 1024-bit AES key"
    assert_success
    [[ -f "${dir}/agent.pub" ]]

    # Test that if run again, it quits out
    run create_repo_key "${dir}/agent.pub" "${dir}/repo"
    assert_output --partial "ERROR: Key already added to repository"
    assert_failure
    [[ -f "${dir}/agent.pub" ]]

    # Test that if run with a different key, it quits out
    create_agent_keypair "${dir}/second"
    run create_repo_key "${dir}/second.pub" "${dir}/repo"
    assert_output --partial "Other keys already deployed; you should manually decrypt and re-encrypt the repo key instead"
    assert_failure

    popd
    rm -rf "${dir}"
}

@test "encrypt_file" {
    dir="$(mktemp -d)"
    create_agent_keypair "${dir}/agent"
    create_test_repo "${dir}/repo"
    create_repo_key "${dir}/agent.pub" "${dir}/repo"
    REPO_KEY="$(echo ${dir}/repo/.buildkite/cryptic_repo_keys/repo_key.*)"
    pushd "${dir}/repo"

    # Encrypt a file
    run encrypt_file "${dir}/agent.key" "${dir}/repo" "${dir}/repo/src/Foo.jl"
    assert_output --partial "Congratulations, you have successfully encrypted a secret."
    assert_output --partial "files:"
    assert_output --partial "- src/Foo.jl"
    assert_success

    # Ensure that we have an encrypted file, and that it decrypts to what we expect
    [[ -f "${dir}/repo/src/Foo.jl.encrypted" ]]
    ls -la ${dir}/repo/.buildkite/cryptic_repo_keys
    DECRYPTED_DATA="$(decrypt_aes_key_then_decrypt "${dir}/agent.key" "${REPO_KEY}" <"${dir}/repo/src/Foo.jl.encrypted")"
    GROUNDTRUTH_DATA="$(cat ${dir}/repo/src/Foo.jl)"
    [[ "${DECRYPTED_DATA}" == "${GROUNDTRUTH_DATA}" ]]

    # Trying to encrypt a second time fails (won't overwrite existing encrypted secret)
    run encrypt_file "${dir}/agent.key" "${dir}/repo" "${dir}/repo/src/Foo.jl"
    assert_output --partial "Encrypted file path '${dir}/repo/src/Foo.jl.encrypted' already exists"
    assert_failure

    # Trying to encrypt a nonexistent file fails
    run encrypt_file "${dir}/agent.key" "${dir}/repo" "${dir}/repo/src/blah.jl"
    assert_output --partial "No such file or directory"
    assert_failure

    popd
    rm -rf "${dir}"
}

@test "encrypt_variable" {
    dir="$(mktemp -d)"
    create_agent_keypair "${dir}/agent"
    create_test_repo "${dir}/repo"
    create_repo_key "${dir}/agent.pub" "${dir}/repo"
    REPO_KEY="$(echo ${dir}/repo/.buildkite/cryptic_repo_keys/repo_key.*)"
    pushd "${dir}/repo"

    # Encrypt a variable
    run encrypt_variable "${dir}/agent.key" "${dir}/repo" "FOO" "SECRET"
    assert_output --partial "Congratulations, you have successfully encrypted a secret variable."
    assert_output --partial "variables:"
    assert_output --partial "- FOO="
    assert_success

    popd
    rm -rf "${dir}"
}

function copy_test_repo() {
    cp -ar "/plugin/example" "${1}"
    git -C "${1}" init
    git -C "${1}" add .
    git -C "${1}" commit -am "initial commit"
}

@test "decrypt" {
    dir="$(mktemp -d)"
    copy_test_repo "${dir}/repo"
    pushd "${dir}/repo"

    # Ensure we didn't copy over the codesign_key.txt (if we started in a decrypted state)
    rm -f .buildkite/secrets/codesign_key.txt
    
    # Decrypt `codesign.yaml`
    run decrypt "${dir}/repo/example.key" "${dir}/repo" ".buildkite/codesign.yml"
    assert_output --partial "Parsed out 0 encrypted variables, 1 files"
    assert_output --partial "-> .buildkite/secrets/codesign_key.txt"
    assert_success

    [[ -f ".buildkite/secrets/codesign_key.txt" ]]
    [[ "$(cat .buildkite/secrets/codesign_key.txt)" == "codesign key secret text" ]]

    # Ensure that decrypting a file a second time skips the file
    run decrypt "${dir}/repo/example.key" "${dir}/repo" ".buildkite/codesign.yml"
    assert_output --partial "Parsed out 0 encrypted variables, 1 files"
    assert_output --partial "-> .buildkite/secrets/codesign_key.txt"
    assert_output --partial ", skipped)"
    assert_success

    # Decrypt `deploy.yml`
    run decrypt "${dir}/repo/example.key" "${dir}/repo" ".buildkite/deploy.yml"
    assert_output --partial "Parsed out 1 encrypted variables, 0 files"
    assert_output --partial "-> S3_ACCESS_KEY=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    assert_success

    popd
    rm -rf "${dir}"
}

@test "{sign,verify}_treehashes" {
    dir="$(mktemp -d)"
    copy_test_repo "${dir}/repo"
    pushd "${dir}/repo"

    # Test that the verification works first
    run verify_treehashes "${dir}/repo/example.key" "${dir}/repo" ".buildkite/pipeline.yml"
    assert_output --partial "Parsed out 1 pipelines being launched"
    assert_output --partial ".buildkite/codesign.yml: ✔️"
    assert_success

    run verify_treehashes "${dir}/repo/example.key" "${dir}/repo" ".buildkite/codesign.yml"
    assert_output --partial "Parsed out 1 pipelines being launched"
    assert_output --partial ".buildkite/deploy.yml: ✔️"
    assert_success

    # Next, test that modifying `deploy.yml` breaks verify of `codesign` but not `pipeline`:
    echo >> .buildkite/deploy.yml
    run verify_treehashes "${dir}/repo/example.key" "${dir}/repo" ".buildkite/pipeline.yml"
    assert_success
    run verify_treehashes "${dir}/repo/example.key" "${dir}/repo" ".buildkite/codesign.yml"
    assert_failure

    # Now, re-sign `codesign.yml`:
    run sign_treehashes "${dir}/repo/example.key" "${dir}/repo" ".buildkite/codesign.yml"
    assert_output --partial "signature_file: .buildkite/deploy.yml.signature"
    assert_success
    run verify_treehashes "${dir}/repo/example.key" "${dir}/repo" ".buildkite/codesign.yml"
    assert_output --partial ".buildkite/deploy.yml: ✔️"
    assert_success
    run verify_treehashes "${dir}/repo/example.key" "${dir}/repo" ".buildkite/pipeline.yml"
    assert_output --partial ".buildkite/codesign.yml: ✔️"
    assert_success

    # Next, let's delete a signature file, and note that it auto-suggests embedding the
    # signature as a base64-encoded field in the YAML:
    rm -f .buildkite/deploy.yml.signature
    run sign_treehashes "${dir}/repo/example.key" "${dir}/repo" ".buildkite/codesign.yml"
    assert_output --partial "signature: "
    refute_output --partial "signature_file: .buildkite/deploy.yml.signature"
    assert_success

    popd
    rm -rf "${dir}"
}