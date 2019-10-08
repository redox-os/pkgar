#!/usr/bin/env bash

set -ex

rm -rf target/test
mkdir -p target/test

cargo build --release

time target/release/pkgar \
    keygen \
    --secret target/test/secret.key \
    --public target/test/public.key

time target/release/pkgar \
    create \
    --secret target/test/secret.key \
    --file target/test/src.pkg \
    src

time target/release/pkgar \
    extract \
    --public target/test/public.key \
    --file target/test/src.pkg \
    target/test/src

diff -ruwN src target/test/src
