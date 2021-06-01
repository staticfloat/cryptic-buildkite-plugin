FROM buildkite/plugin-tester

# Install git and python3, use python3 to get `shyaml`
RUN apk add git python3
RUN pip3 install shyaml

# We need a really new version of openssl
RUN apk add --repository=http://dl-cdn.alpinelinux.org/alpine/edge/main openssl
