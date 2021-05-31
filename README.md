# cryptic-buildkite-plugin
> Deploy secrets within partially-trusted buildkite pipelines

# Overview

This plugin enables the deployment and usage of secrets within buildkite pipelines.
In particular, it prevents untrusted contributors from leaking secrets in sensitive pipelines.

A chain of trust is established starting from the WebUI, as these steps are only editable by repository administrators.
The WebUI then launches pipelines, using the `cryptic` plugin, which facilitates verification of treehashes before launching pipelines that expect secrets to be available.
The propagation of the chain of trust after verifying that the repository state has not changed critical files allows unknown contributors to make changes to the majority of the codebase, while retaining a tight leash on critical codepaths that have access to secrets.

## Setting up new agents and repositories for `cryptic`

There are a number of steps required to build a proper chain of trust for the keys and secrets needed by the `cryptic` system:

Agent setup:
  1. First, an agent keypair must be created, using `bin/create_agent_keypair`.
  2. The `hooks/environment.agent` hook must be added as an environment hook on the agent.
    - The hook has paths to the agent keypair embedded within it; customize these to your installation.
  3. The agent must run in some kind of sandboxed environment (such as a docker container).
    - Not only is this a good idea for security/reproducibility, but the `environment.agent` hook will attempt to delete the keypair to deny access to it from future pipeline steps.
    - The sandbox that the agent runs in should therefore rebuild itself from scratch after every job.

Repository setup:
  1. Each repository that wants to utilize secrets must generate a repository key, using `bin/create_repo_key`.
    - This is a symmetric key, and it will be encrypted with the agent key created above.
    - Repositories can have the same repository key encrypted with multiple agent keys, to support multiple agent pools each with a different subset of allowed repository secret access.
  2. Encrypt secret files/variables using `bin/encrypt_{file,variable}`, and add the relevant plugin stanzas to your pipeline.
    - To ensure things are working correctly, you can use `bin/decrypt` to test out how things will be decoded.
  3. To propagate trust to a child pipeline, use the `signed_pipelines` parameter
    - To ensure a malicious contributor cannot run `echo ${SECRET_KEY}` as part of the privileged build, add all scripts invoked during the build to the `inputs` sub-parameter, then use `bin/sign_treehashes` to get a signature that will be checked before the pipeline is launched.
    - If you have a complicated chain of trust (A -> B -> C) it can be tedious to regenerate signatures for all links in the chain simply because there was a change made in C.  For this usecase, you can use `signature_file` instead of `signature`, to decouple the signature from the `.yml` file itself, meaning that `B`'s hash doesn't change just because `C`'s did.

## Utilities

This repository has a few utility scripts:

* [`create_agent_keypair`](bin/create_agent_keypair): Generates the `agent.key` and `agent.pub` files.

* [`create_repo_key`](bin/create_repo_key): Using a pre-generated agent keypair, generates the repository key and stores it in `.buildkite/cryptic_repo_keys`.

* [`encrypt_file`](bin/encrypt_file)/[`encrypt_variable](bin/encrypt_variable): Encrypt files/text strings using the repository key.  Files get stored as `.encrypted` files, and variables can be embedded directly within `pipeline.yml` files.

* [`decrypt`](bin/decrypt): Testing tool to ensure that your encrypted values are round-tripping properly.

* [`sign_treehashes`](bin/sign_treehashes): Consume the `
