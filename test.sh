#!/usr/bin/env bash

build=release
if [[ "$1" == "-d" ]]; then
    build=debug
fi

create_flag=
if [[ "$1" == "-c" ]]; then
    create_flag=-c
fi

set -ex

rm -rf target/test
mkdir -p target/test

if [[ "$build" == debug ]]; then
    cargo build --all-features
else
    cargo build --release --all-features
fi

time target/$build/pkgar-keys gen \
    --skey target/test/secret.toml \
    --pkey target/test/public.toml \
    --plaintext

time target/$build/pkgar \
    create $create_flag \
    --skey target/test/secret.toml \
    --archive target/test/src.pkgar \
    pkgar/src

stat -c %s target/test/src.pkgar

time target/$build/pkgar \
    list \
    --pkey target/test/public.toml \
    --archive target/test/src.pkgar

time target/$build/pkgar \
    split \
    --pkey target/test/public.toml \
    --archive target/test/src.pkgar \
    target/test/src.pkgar_head \
    target/test/src.pkgar_data

stat -c %s target/test/src.pkgar_head
stat -c %s target/test/src.pkgar_data

time target/$build/pkgar \
    list \
    --pkey target/test/public.toml \
    --archive target/test/src.pkgar_head

time target/$build/pkgar \
    extract \
    --pkey target/test/public.toml \
    --archive target/test/src.pkgar \
    target/test/src

diff -ruwN pkgar/src target/test/src

time target/$build/pkgar \
    verify \
    --pkey target/test/public.toml \
    --archive target/test/src.pkgar \
    target/test/src

# TODO: Cannot verify with pkgar_head for compressed packaging
time target/$build/pkgar \
    verify \
    --pkey target/test/public.toml \
    --archive target/test/src.pkgar \
    target/test/src

time target/$build/pkgar \
    remove \
    --pkey target/test/public.toml \
    --archive target/test/src.pkgar \
    target/test/src

if [[ "$(find target/test/src '!' -type d)" ]]; then
    exit 1
fi
