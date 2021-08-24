# Scripts

This folder contains some helpfull scripts that can be helpfull during development.

## Pre-Requirements

To run the scripts in this folder you have to install a few tools on your system. You can use the following script to install the required tools (just replace `brew` with the packet manager of your choice).

```sh
# nightly toolchain
rustup toolchain install nightly

# llvm toolchain for nightly
rustup component add --toolchain nightly llvm-tools-preview

# cargo-binutils and rustfilt for nightly
cargo +nightly install cargo-binutils rustfilt

# jq from your package manager of choice (just replace brew with apt or a similar manager)
brew install jq
```

## coverage.bash

`coverage.bash` calculates the region & line based code coverage of the tests. Just execute it and it will write the reports to `target/coverage`.

Note: When executing this script `cargo clean` be executed and previous coverage data will be deleted.
