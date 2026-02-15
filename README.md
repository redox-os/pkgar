# pkgar - Package Archive

Pkgar is the package archive format for Redox OS.

## Project Layout
There are currently two crates in this repo. See their READMEs for more specific
docs:
- `pkgar`: The implementation of the pkgar file format as a library, and a cli
  tool for manpulating pkgar packages.
- `pkgar-keys`: Key management tool/library for pkgar.

## Install

- Installing from crates.io:

```sh
cargo install pkgar pkgar-keys --features=cli
```

- Installing locally

```sh
cargo install --path=pkgar --features=cli
cargo install --path=pkgar-keys --features=cli
```
