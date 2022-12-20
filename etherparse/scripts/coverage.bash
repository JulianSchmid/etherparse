#!/usr/bin/env bash

# PRE-REQUIREMENTS:
#
# To execute this script you have to have a few additional things installed
# on your system. You can run the following commands to do so:
#
# ```sh
# # nightly toolchain
# rustup toolchain install nightly 
#
# # llvm toolchain for nightly
# rustup component add --toolchain nightly llvm-tools-preview
#
# # cargo-binutils and rustfilt for nightly
# cargo +nightly install cargo-binutils rustfilt
#
# # jq from your package manager of choice (just replace brew with apt or a similar manager)
# brew install jq
# ```

# switch to the etherparse root directory
pushd "$(dirname "${BASH_SOURCE[0]}")/.."

# folder for all the coverage files
coverage_dir="target/coverage"
    
# make sure no cached data is used (can interfere with the instrumentalisation and testruns)
cargo clean

# remove previous runs and setup the result folders
rm -rf "${coverage_dir}"
mkdir -p "${coverage_dir}"
mkdir -p "${coverage_dir}/raw"

# run the instrumented tests
RUSTFLAGS="-Zinstrument-coverage" \
    LLVM_PROFILE_FILE="${coverage_dir}/raw/coverage-%m.profraw" \
    cargo +nightly test --tests

# determine the filenames of the run executables
RUSTFLAGS="-Zinstrument-coverage" \
    LLVM_PROFILE_FILE="${coverage_dir}/raw/coverage-%m.profraw" \
cargo +nightly test --no-run --message-format=json | jq -r "select(.profile.test == true) | .filenames[]" | grep -v dSYM - > "${coverage_dir}/raw/filenames.txt"

cargo profdata -- merge -sparse "${coverage_dir}/raw/coverage-"*".profraw" -o "${coverage_dir}/raw/merge.profdata"

cargo cov -- report \
    --use-color \
    --summary-only \
    --Xdemangler=rustfilt \
    --ignore-filename-regex='/.cargo/registry' \
    --ignore-filename-regex='/.rustup/toolchains' \
    --ignore-filename-regex='/rustc' \
    "--instr-profile=${coverage_dir}/raw/merge.profdata" \
    $(printf -- "-object %s " $(cat "${coverage_dir}/raw/filenames.txt")) \
  > "${coverage_dir}/report_all.txt"

cargo cov -- report \
    --use-color \
    --summary-only \
    --Xdemangler=rustfilt \
    --ignore-filename-regex='/.cargo/registry' \
    --ignore-filename-regex='/.rustup/toolchains' \
    --ignore-filename-regex='/rustc' \
    --ignore-filename-regex='tests/' \
    "--instr-profile=${coverage_dir}/raw/merge.profdata" \
    $(printf -- "-object %s " $(cat "${coverage_dir}/raw/filenames.txt")) \
  > "${coverage_dir}/report_without_tests.txt"

cargo cov -- show --format=html \
    --Xdemangler=rustfilt \
    --ignore-filename-regex='/.cargo/registry' \
    --ignore-filename-regex='/.rustup/toolchains' \
    --ignore-filename-regex='/rustc' \
    "--instr-profile=${coverage_dir}/raw/merge.profdata" \
    $(printf -- "-object %s " $(cat "${coverage_dir}/raw/filenames.txt")) \
    "--output-dir=${coverage_dir}/html_all"

cargo cov -- show --format=html \
    --Xdemangler=rustfilt \
    --ignore-filename-regex='/.cargo/registry' \
    --ignore-filename-regex='/.rustup/toolchains' \
    --ignore-filename-regex='/rustc' \
    --ignore-filename-regex='tests/' \
    "--instr-profile=${coverage_dir}/raw/merge.profdata" \
    $(printf -- "-object %s " $(cat "${coverage_dir}/raw/filenames.txt")) \
    "--output-dir=${coverage_dir}/html_without_tests"

cargo cov -- export --format=lcov \
    --Xdemangler=rustfilt \
    --ignore-filename-regex='/.cargo/registry' \
    --ignore-filename-regex='/.rustup/toolchains' \
    --ignore-filename-regex='/rustc' \
    "--instr-profile=${coverage_dir}/raw/merge.profdata" \
    $(printf -- "-object %s " $(cat "${coverage_dir}/raw/filenames.txt")) \
  > "${coverage_dir}/export.lcov.txt"

cargo cov -- export --format=text \
    --Xdemangler=rustfilt \
    --ignore-filename-regex='/.cargo/registry' \
    --ignore-filename-regex='/.rustup/toolchains' \
    --ignore-filename-regex='/rustc' \
    "--instr-profile=${coverage_dir}/raw/merge.profdata" \
    $(printf -- "-object %s " $(cat "${coverage_dir}/raw/filenames.txt")) \
  > "${coverage_dir}/export.json"

popd