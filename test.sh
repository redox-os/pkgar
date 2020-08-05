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

time target/$build/pkgar-keys gen \
    --skey target/test/secret.toml \
    --pkey target/test/public.toml \
    --plaintext

time target/$build/pkgar \
    create \
    --skey target/test/secret.toml \
    --archive target/test/src.pkg \
    pkgar/src

time target/$build/pkgar \
    list \
    --pkey target/test/public.toml \
    --archive target/test/src.pkg

time target/$build/pkgar \
    extract \
    --pkey target/test/public.toml \
    --archive target/test/src.pkg \
    target/test/src

diff -ruwN pkgar/src target/test/src

time target/$build/pkgar \
    remove \
    --pkey target/test/public.toml \
    --archive target/test/src.pkg \
    target/test/src

if [[ "$(ls -A target/test/src)" ]]; then
    exit 1
fi

