#!/usr/bin/env bash

set -ex

rm -rf target/test
mkdir -p target/test

cargo run --release -- \
    keygen \
    --secret target/test/secret.key \
    --public target/test/public.key

cargo run --release -- \
    create \
    --secret target/test/secret.key \
    --file target/test/src.pkg \
    src

cargo run --release -- \
    extract \
    --public target/test/public.key \
    --file target/test/src.pkg \
    target/test/src

diff -ruwN src target/test/src
