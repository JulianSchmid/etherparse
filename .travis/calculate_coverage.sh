#!/bin/bash

if [[ $TRAVIS_OS_NAME == 'osx' ]]; then
    # Don't calculate the coverage on os x
else
    # On Linux build instrumented for coverage and run the tests
    wget https://github.com/SimonKagstrom/kcov/archive/v35.tar.gz &&
    tar xzf v35.tar.gz &&
    cd kcov-35 &&
    mkdir build &&
    cd build &&
    cmake .. &&
    make &&
    make install DESTDIR=../../kcov-build &&
    cd ../.. &&
    rm -rf kcov-master &&
    for file in target/debug/{unit_tests,etherparse}-*[^\.d]; do mkdir -p "target/cov/$(basename $file)"; ./kcov-build/usr/local/bin/kcov --exclude-pattern=/.cargo,/usr/lib --verify "target/cov/$(basename $file)" "$file"; done &&
    bash <(curl -s https://codecov.io/bash) &&
    echo "Uploaded code coverage"
fi