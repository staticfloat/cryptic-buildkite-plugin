## There's a lot of shared code at the beginning of `decrypt`, `sign_treehashes` and `verify_treehashes`
## so we list it out here so that it doesn't get too diverged as we fix bugs

if ! which shyaml >/dev/null 2>/dev/null; then
    die "We require shyaml to be installed for YAML parsing"
fi


# Calculate the treehashes of each signed pipeline defined within a launching `.yml` file,
# also returning the signature if it exists, (blank string if it doesn't)
function invoke_func_on_steps() {
    # Most of our paths are relative to the root directory, so this is just easier
    pushd "${REPO_ROOT}" >/dev/null

    # Iterate over the steps in the yaml file
    (shyaml -q get-values-0 steps <"${1}" || true) |
    while IFS='' read -r -d '' STEP; do
        # If this step is a `group` step, let's iterate over each of its steps
        if shyaml -q get-value 'group' >/dev/null <<<"${STEP}"; then
            (shyaml -q get-values-0 steps <<<"${STEP}" || true) |
            while IFS='' read -r -d '' INNER_STEP; do
                "${2}" "${INNER_STEP}"
            done
        else
            "${2}" "${STEP}"
        fi
    done

    popd >/dev/null
}


# Extract the `variables:` section of a cryptic `pipeline.yml` plugin section
function extract_encrypted_variables() {
    invoke_func_on_steps "${1}" extract_encrypted_variables_from_step
}

function extract_encrypted_variables_from_step() {
    (shyaml -q get-values-0 plugins <<<"${1}" || true) |
    while IFS='' read -r -d '' PLUGINS; do
        # Get the plugin names
        (shyaml -q keys-0 <<<"${PLUGINS}" || true) |
        while IFS='' read -r -d '' PLUGIN_NAME; do
            # Skip plugins that are not named `cryptic`
            if [[ "${PLUGIN_NAME}" != staticfloat/cryptic* ]]; then
                continue
            fi
            # For each plugin, if its `cryptic`, extract the variables
            (shyaml -q get-values-0 "${PLUGIN_NAME}.variables" <<<"${PLUGINS}" || true) |
            while IFS='' read -r -d '' VAR; do
                printf "%s\n" "${VAR}"
            done
        done
    done
}

# Extract all variables that match "CRYPTIC_ADHOC_SECRET_*"
function extract_adhoc_encrypted_variables() {
    # Iterate over any global env mappings
    (shyaml -q keys-0 env <"${1}" || true) |
    while IFS='' read -r -d '' VARNAME; do
        if [[ "${VARNAME}" == CRYPTIC_ADHOC_SECRET_* ]]; then
            printf "%s\n" "${VARNAME:21}=$(shyaml -q get-value env.${VARNAME} <"${1}")"
        fi
    done

    # Iterate over the steps in the yaml file
    invoke_func_on_steps "${1}" extract_adhoc_encrypted_variables_from_step
}

function extract_adhoc_encrypted_variables_from_step() {
    (shyaml -q get-values-0 steps <"${1}" || true) |
    while IFS='' read -r -d '' STEP; do
        (shyaml -q keys-0 env <<<"${STEP}" || true) |
        while IFS='' read -r -d '' VARNAME; do
            if [[ "${VARNAME}" == CRYPTIC_ADHOC_SECRET_* ]]; then
                printf "%s\n" "${VARNAME:21}=$(shyaml -q get-value env.${VARNAME} <<<"${STEP}")"
            fi
        done
    done
}

# Extract the `files:` section of a cryptic `pipeline.yml` plugin section
function extract_encrypted_files() {
    invoke_func_on_steps "${1}" extract_encrypted_files_from_step
}

function extract_encrypted_files_from_step() {
    # For each step, get its list of plugins
    (shyaml -q get-values-0 plugins <<<"${1}" || true) |
    while IFS='' read -r -d '' PLUGINS; do
        # Get the plugin names
        (shyaml -q keys-0 <<<"${PLUGINS}" || true) |
        while IFS='' read -r -d '' PLUGIN_NAME; do
            # Skip plugins that are not named `cryptic`
            if [[ "${PLUGIN_NAME}" != staticfloat/cryptic* ]]; then
                continue
            fi
            # For each plugin, if its `cryptic`, extract the files
            (shyaml -q get-values-0 "${PLUGIN_NAME}.files" <<<"${PLUGINS}" || true) |
            while IFS='' read -r -d '' FILE; do
                FILE="$(echo ${FILE} | tr -d '"')"
                printf "%s\n" "${FILE}"
            done
        done
    done
}

# Calculate the treehashes of each signed pipeline defined within a launching `.yml` file,
# also returning the signature if it exists, (blank string if it doesn't)
function extract_pipeline_treehashes() {
    vecho "Extracting treehashes from '${YAML_PATH}'"
    invoke_func_on_steps "${1}" extract_treehashes_from_step
}

function extract_treehashes_from_step() {
    # Get the list of plugins
    (shyaml -q get-values-0 plugins <<<"${1}" || true) |
    while IFS='' read -r -d '' PLUGINS; do
        # Get the plugin names
        (shyaml -q keys-0 <<<"${PLUGINS}" || true) |
        while IFS='' read -r -d '' PLUGIN_NAME; do
            # Skip plugins that are not named `cryptic`
            if [[ "${PLUGIN_NAME}" != staticfloat/cryptic* ]]; then
                continue
            fi

            # For each plugin, if its `cryptic`, walk over the pipelines
            (shyaml -q get-values-0 "${PLUGIN_NAME}.signed_pipelines" <<<"${PLUGINS}" || true) |
            while IFS='' read -r -d '' PIPELINE; do
                # For each signed pipeline, get its pipeline path and its inputs
                PIPELINE_PATH="$(shyaml -q get-value "pipeline" <<<"${PIPELINE}" || true)"

                vecho " -> Found pipeline launch:"
                vecho "    -> ${PIPELINE_PATH}"

                # Start by calculating the treehash of the yaml file
                INPUT_TREEHASHES=( "$(calc_treehash <<<"${PIPELINE_PATH}")" )

                # Next, calculate the treehash of the rest of the glob patterns
                readarray -d '' PATTERNS -t < <(shyaml -q get-values-0 "inputs" <<<"${PIPELINE}")
                for PATTERN in "${PATTERNS[@]}"; do
                    HASH="$(collect_glob_pattern "${PATTERN}" | calc_treehash)"
                    vecho "       + ${HASH} <- ${PATTERN}"
                    INPUT_TREEHASHES+=( "${HASH}" )
                done

                # Calculate full treehash
                FULL_TREEHASH="$(printf "%s" "${INPUT_TREEHASHES[@]}" | calc_shasum)"
                vecho "       ∟ ${FULL_TREEHASH}"

                # If `signature_file` is defined, use it!
                local BASE64_ENCRYPTED_TREEHASH=""
                local TREEHASH_FILE_SOURCE=""
                if shyaml get-value "signature_file" <<<"${PIPELINE}" >/dev/null; then
                    TREEHASH_FILE_SOURCE="$(shyaml -q get-value "signature_file" <<<"${PIPELINE}")"
                    if [[ -f "${TREEHASH_FILE_SOURCE}" ]]; then
                        BASE64_ENCRYPTED_TREEHASH="$(base64enc <"${TREEHASH_FILE_SOURCE}")"
                    fi
                else
                    # Try to extract the signature from the yaml directly too
                    BASE64_ENCRYPTED_TREEHASH="$(shyaml -q get-value "signature" <<<"${PIPELINE}" || true)"
                fi

                # Print out treehash and pipeline path
                printf "%s&%s&%s&%s\n" "${PIPELINE_PATH}" "${FULL_TREEHASH}" "${BASE64_ENCRYPTED_TREEHASH}" "${TREEHASH_FILE_SOURCE}"
            done
        done
    done
}
