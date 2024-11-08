## There's a lot of shared code at the beginning of `decrypt`, `sign_treehashes` and `verify_treehashes`
## so we list it out here so that it doesn't get too diverged as we fix bugs

if ! which shyaml >/dev/null 2>/dev/null; then
    die "We require shyaml to be installed for YAML parsing"
fi


# Extract the `variables:` section of a cryptic `pipeline.yml` plugin section
function extract_encrypted_variables() {
    # Function to process steps recursively
    function process_steps() {
        local steps_input="$1"
        # Iterate over the steps in the yaml file
        (shyaml -q get-values-0 steps <<<"${steps_input}" || true) |
        while IFS='' read -r -d '' STEP; do
            # Check if this step has nested steps (is a group)
            if (shyaml -q get-value steps <<<"${STEP}" >/dev/null 2>&1); then
                # Recursively process nested steps
                process_steps "${STEP}"
            else
                # For each step, get its list of plugins
                (shyaml -q get-values-0 plugins <<<"${STEP}" || true) |
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
            fi
        done
    }

    # Start processing from the root of the YAML file
    process_steps "$(cat "${1}")"
}

# Extract all variables that match "CRYPTIC_ADHOC_SECRET_*"
function extract_adhoc_encrypted_variables() {
    function process_env_vars() {
        local yaml_section="$1"
        (shyaml -q keys-0 env <<<"${yaml_section}" || true) |
        while IFS='' read -r -d '' VARNAME; do
            if [[ "${VARNAME}" == CRYPTIC_ADHOC_SECRET_* ]]; then
                printf "%s\n" "${VARNAME:21}=$(shyaml -q get-value env.${VARNAME} <<<"${yaml_section}")"
            fi
        done
    }

    function process_steps() {
        local steps_input="$1"
        # Iterate over the steps in the yaml file
        (shyaml -q get-values-0 steps <<<"${steps_input}" || true) |
        while IFS='' read -r -d '' STEP; do
            # Check if this step has nested steps (is a group)
            if (shyaml -q get-value steps <<<"${STEP}" >/dev/null 2>&1); then
                # Recursively process nested steps
                process_steps "${STEP}"
            else
                # Process environment variables for this step
                process_env_vars "${STEP}"
            fi
        done
    }

    # First process any global env mappings
    process_env_vars "$(cat "${1}")"

    # Then process all steps recursively
    process_steps "$(cat "${1}")"
}

# Extract the `files:` section of a cryptic `pipeline.yml` plugin section
function extract_encrypted_files() {
    function process_steps() {
        local steps_input="$1"
        # Iterate over the steps in the yaml file
        (shyaml -q get-values-0 steps <<<"${steps_input}" || true) |
        while IFS='' read -r -d '' STEP; do
            # Check if this step has nested steps (is a group)
            if (shyaml -q get-value steps <<<"${STEP}" >/dev/null 2>&1); then
                # Recursively process nested steps
                process_steps "${STEP}"
            else
                # For each step, get its list of plugins
                (shyaml -q get-values-0 plugins <<<"${STEP}" || true) |
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
            fi
        done
    }

    # Start processing from the root of the YAML file
    process_steps "$(cat "${1}")"
}

# Calculate the treehashes of each signed pipeline defined within a launching `.yml` file,
# also returning the signature if it exists, (blank string if it doesn't)
function extract_pipeline_treehashes() {
    # Most of our paths are relative to the root directory, so this is just easier
    pushd "${REPO_ROOT}" >/dev/null

    vecho "Extracting treehashes from '${YAML_PATH}'"

    # Function to process plugins and extract treehashes
    function process_plugins() {
        local STEP="$1"
        # Get the list of plugins
        (shyaml -q get-values-0 plugins <<<"${STEP}" || true) |
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

    # Function to process steps recursively
    function process_steps() {
        local steps_input="$1"
        # Iterate over the steps in the yaml file
        (shyaml -q get-values-0 steps <<<"${steps_input}" || true) |
        while IFS='' read -r -d '' STEP; do
            # Check if this step has nested steps (is a group)
            if (shyaml -q get-value steps <<<"${STEP}" >/dev/null 2>&1); then
                # Recursively process nested steps
                process_steps "${STEP}"
            else
                # Process plugins for this step
                process_plugins "${STEP}"
            fi
        done
    }

    # Start processing from the root of the YAML file
    process_steps "$(cat "${1}")"

    # Don't stay in `${REPO_ROOT}`
    popd >/dev/null
}
