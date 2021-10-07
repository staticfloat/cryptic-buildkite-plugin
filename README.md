# cryptic-buildkite-plugin
> Deploy secrets within partially-trusted buildkite pipelines

# Overview

This plugin enables the deployment and usage of secrets within buildkite pipelines.
Files and environment variables can be encrypted with a key that is stored in your repository, itself encrypted by a key that is deployed on a buildkite agent.
This plugin also allows workflows that prevent untrusted contributors from leaking secrets in sensitive pipelines.

A chain of trust is established starting from the WebUI, as these steps are only editable by repository administrators.
The WebUI then launches pipelines, using the `cryptic` plugin, which facilitates verification of treehashes before launching pipelines that expect secrets to be available.
The propagation of the chain of trust after verifying that the repository state has not changed critical files allows unknown contributors to make changes to the majority of the codebase, while retaining a tight leash on critical codepaths that have access to secrets.

## Usage

There are four fundamental capabilities that `cryptic` offers:

  - Decrypting encrypted files
  - Decrypting encrypted environment variables
  - Decrypting encrypted "ad-hoc" environment variables
  - Verifying repository state, then launching child pipelines

### Decrypting files and variables

The first two capabilities are quite straightforward; once your repository is setup properly, you list encrypted variables and files in a `cryptic` plugin instance in your pipeline, like so:

```yml
steps:
  - label: "Showcase secrets decrypting"
    # Note, if this is a child pipeline launched by the webUI config, you MUST receive this
    # value from the parent pipeline in order to decrypt secrets.  Further note, do NOT list
    # this environment variable as a top-level key within ANY `.yaml` file, as this will
    # cause the value to be appended to all future pipelines!
    env:
      BUILDKITE_PLUGIN_CRYPTIC_BASE64_SIGNED_JOB_ID_SECRET: ${BUILDKITE_PLUGIN_CRYPTIC_BASE64_SIGNED_JOB_ID_SECRET?}
    plugins:
    - staticfloat/cryptic:
        files:
            # This file is actually only stored as `secret_message.txt.encrypted` in the repo,
            # and `cryptic` will create the `secret_message.txt` file from it, when it decrypts
            # in its `post-checkout` step.  It is recommended to `.gitignore` the decrypted file
            # both for security, to prevent accidental check-in, and so that after decryption,
            # `git` still thinks the repository state is clean.
            - ./.buildkite/secrets/secret_message.txt
        variables:
            - AWS_CREDENTIALS="U2FsdGVkX19/7cDiPvuDTzfH5phgJJjbzptPc5D3WTwmQsK01j51b5HFjVfFvvwb"
    commands: |
        # When writing bash scripts in these .yml files, remember that the buildkite-agent
        # does variable interpolation itself, so you need to double-escape your dollar signs
        # when referring to a bash variable that is defined at runtime:
        echo "To prove that we decrypted 'AWS_CREDENTIALS', here it is: $${AWS_CREDENTIALS}"
        echo "To prove that we decrypted secret_message.txt, here it is:"
        cat ./.buildkite/secrets/secret_message.txt
```

The `cryptic` plugin will decrypt the files and variables, allowing the rest of your pipeline to use the pieces of sensitive data without knowing they were ever encrypted at all.

### Ad-hoc variables

The third capability, ad-hoc environment variables, are an advanced usage where the environment variable must be decrypted before the repository has even been cloned to disk, for instance to deploy an SSH key to the agent so that it can clone the repository at all.
In the previous examples, the files and variables are encrypted with a key that is stored within the repository itself (which itself is encrypted with a key that is deployed onto the buildkite agent machines), such that in order to decrypt the secrets you need acess to both the agents and the repository.
With ad-hoc environment variables, you only need access to an agent, which is slightly less secure.
We recommend only using ad-hoc variables for things like SSH keys, and using the first two capabilities for all other secrets.

### Launching child pipelines

Finally, the fourth capability allows us to generate a chain of trust.
This is only truly needed if your repository has untrusted collaborators, and you want to run CI on pull requests.
This allows you to create pipelines that are verified by signatures on treehashes previously embedded within the CI configuration.

In the buildkite WebUI, add a pipeline such as the following:

```yml
steps:
  # In the WebUI, the `cryptic` launch job _must_ be the first job to run
  - label: ":rocket: launch pipelines"
    plugins:
      - staticfloat/cryptic:
          # Our list of pipelines that should be launched (but don't require a signature)
          # These pipelines can be modified by any contributor and CI will still run.
          # Build secrets will not be available in these pipelines (or their children)
          unsigned_pipelines:
            - .buildkite/pipeline.yml
          # Our list of pipelines that should be launched (and do require a signature)
          # If these pipelines are modified, job execution will fail.
          signed_pipelines:
            - pipeline: .buildkite/secure_pipeline.yml
              signature_file: .buildkite/secure_pipeline.yml.signature
              inputs:
                - .buildkite/utils/*.sh
              allow_hash_override: true
```

In this example, we launch one secure pipeline which will have access to the agent keys to decrypt secrets, but the unsigned pipeline will not, even if a user attempts to add a `cryptic` plugin.
Since the WebUI starts "privileged", with access to the agent keys, using the `signed_pipelines` is one way to pass the keys on to a child pipeline while simultaneously ensuring that the pipeline (and any other files listed in the `inputs` array) are unchanged since the last time the signature was added.
The `allow_hash_override` option enables a committer to bypass a failing signature check and force the pipeline to continue running with access to the secrets.

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
      - Note that another command, `bin/encrypt_adhoc` exists, but it is only recommended to be used with secrets that must be decrypted before the repository has been cloned, e.g. SSH keys.
  3. To propagate trust to a child pipeline, use the `signed_pipelines` parameter
      - To ensure a malicious contributor cannot run `echo ${SECRET_KEY}` as part of the privileged build, add all scripts invoked during the build to the `inputs` sub-parameter, then use `bin/sign_treehashes` to get an encrypted treehash that will be checked before the pipeline is launched.
      - If you have a complicated chain of trust (A -> B -> C) it can be tedious to regenerate signatures for all links in the chain simply because there was a change made in C.  For this usecase, you can use `signature_file` instead of `signature`, to decouple the signature from the `.yml` file itself, meaning that `B`'s hash doesn't change just because `C`'s did.

## Utilities

This repository has a few utility scripts.  Note that most of them are most convenient when invoked from within your repository.

* [`create_agent_keypair`](bin/create_agent_keypair): Generates the `agent.key` and `agent.pub` files.

* [`create_repo_key`](bin/create_repo_key): Using a pre-generated agent keypair, generates the repository key and stores it in `.buildkite/cryptic_repo_keys`.

* [`encrypt_file`](bin/encrypt_file)/[`encrypt_variable](bin/encrypt_variable): Encrypt files/text strings using the repository key.  Files get stored as `.encrypted` files, and variables can be embedded directly within `pipeline.yml` files.

* [`decrypt`](bin/decrypt): Testing tool to ensure that your encrypted values are round-tripping properly.  Decrypts files within the repository (e.g. decrypting `foo.encrypted` -> `foo`) and prints out environment variables.

* [`sign_treehashes`](bin/sign_treehashes): Consume a `pipeline.yml` file, determine the inputs to the treehashes on-disk, and output encrypted treehashes.

* [`verify_treehashes`](bin/verify_treehashes): Testing tool to verify that the signatures within the given `pipeline.yml` file match the treehash as calculated on-disk.
