#!/usr/bin/env bash

build=release
if [[ "$1" == "-d" ]]; then
    build=debug
fi

set -ex

rm -rf target/test
mkdir -p target/test

if [[ "$build" == debug ]]; then
    cargo build
else
    cargo build --release
fi

time pkgar-keys gen \
    --keyfile target/test/secret.toml \
    --pubkeyfile target/test/public.toml \
    --plaintext

time target/$build/pkgar \
    create \
    --secret target/test/secret.toml \
    --archive target/test/src.pkg \
    src

time target/$build/pkgar \
    extract \
    --public target/test/public.toml \
    --archive target/test/src.pkg \
    target/test/src

diff -ruwN src target/test/src

