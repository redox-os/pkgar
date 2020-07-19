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

time target/$build/pkgar \
    keygen \
    --secret target/test/secret.key \
    --public target/test/public.key

time target/$build/pkgar \
    create \
    --secret target/test/secret.key \
    --file target/test/src.pkg \
    src

time target/$build/pkgar \
    extract \
    --public target/test/public.key \
    --file target/test/src.pkg \
    target/test/src

diff -ruwN src target/test/src

