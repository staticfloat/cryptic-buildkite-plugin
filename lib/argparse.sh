#!/bin/bash

VERBOSE="${VERBOSE:-false}"
function verbose() {
    [[ "${VERBOSE}" == "true" ]]
}

function expand_home() {
    echo -n "${1/#\~/${HOME}}"
}

POSITIONAL=()
while [[ $# -gt 0 ]]; do
    case "${1}" in
        # Once `--verbose` is found, immediately set `VERBOSE` so that `if verbose` works.
        --verbose|-v)
            VERBOSE="true"
            shift
        ;;

        # Load in agent private/public keys, if provided
        --private-key=*)
            AGENT_PRIVATE_KEY_PATH="$(expand_home ${1#*=})"
            shift;
        ;;
        --private-key)
            AGENT_PRIVATE_KEY_PATH="$(expand_home ${2})"
            shift; shift;
        ;;

        --public-key=*)
            AGENT_PUBLIC_KEY_PATH="$(expand_home ${1#*=})"
            shift;
        ;;
        --public-key)
            AGENT_PUBLIC_KEY_PATH="$(expand_home ${2})"
            shift; shift;
        ;;

        # Load in repository key
        --repo-key=*)
            REPO_KEY_PATH="$(expand_home ${1#*=})"
            shift;
        ;;
        --repo-key)
            REPO_KEY_PATH="$(expand_home ${2})"
            shift; shift;
        ;;

        # Repository root
        --repo-root=*)
            REPO_ROOT="$(expand_home ${1#*=})"
            shift;
        ;;
        --repo-root)
            REPO_ROOT="$(expand_home ${2})"
            shift; shift;
        ;;

        # Everything else is a positional argument
        *)
            POSITIONAL+=("$1")
            shift;
        ;;
    esac
done

if verbose; then
    echo "Successfully parsed the following command-line arguments:"
    echo

    print_if_defined()
    {
        if [[ -v "${1}" ]]; then
            printf '%30s: %s\n' "${1}" "${!1}"
        fi
    }
    print_if_defined "VERBOSE"
    print_if_defined "AGENT_PRIVATE_KEY_PATH"
    print_if_defined "AGENT_PUBLIC_KEY_PATH"
    print_if_defined "REPO_KEY_PATH"
    print_if_defined "REPO_ROOT"
    echo


    if [[ "${#POSITIONAL[@]}" -gt 0 ]]; then
        echo "With ${#POSITIONAL[@]} positional arguments left over:"
        for IDX in "${!POSITIONAL[@]}"; do
            echo "  [${IDX}] ${POSITIONAL[${IDX}]}"
        done
    fi

    echo
    echo
fi

# Restore positional parameters back to `$1`, `$2`, etc...
set -- "${POSITIONAL[@]}"