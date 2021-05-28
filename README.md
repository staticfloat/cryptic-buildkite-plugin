# cryptic-buildkite-plugin
> Deploy secrets within partially-trusted buildkite pipelines

# Overview

This plugin enables the deployment and usage of secrets within buildkite pipelines.
In particular, it prevents untrusted contributors from leaking secrets in sensitive pipelines.

A chain of trust is established starting from the WebUI, as these steps are only editable by repository administrators.

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
