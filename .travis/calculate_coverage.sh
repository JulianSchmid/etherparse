#!/bin/bash

if [[ $TRAVIS_OS_NAME == 'osx' ]]; then
    # Don't calculate the coverage on os x
    echo "Skipping code coverage calculation on OS X."
else
    # On Linux build instrumented for coverage and run the tests
    wget https://github.com/SimonKagstrom/kcov/archive/v36.tar.gz &&
    tar xzf v36.tar.gz &&
    cd kcov-36 &&
    mkdir build &&
    cd build &&
    cmake .. &&
    make &&
    make install DESTDIR=../../kcov-build &&
    cd ../.. &&
    rm -rf kcov-36 &&
    for file in target/debug/{unit_tests}-*[^\.d]; do mkdir -p "target/cov/$(basename $file)"; ./kcov-build/usr/local/bin/kcov --exclude-pattern=/.cargo,/usr/lib --verify "target/cov/$(basename $file)" "$file"; bash <(curl -s https://codecov.io/bash) -cF unittests; done &&
    for file in target/debug/{etherparse}-*[^\.d]; do mkdir -p "target/cov/$(basename $file)"; ./kcov-build/usr/local/bin/kcov --exclude-pattern=/.cargo,/usr/lib --verify "target/cov/$(basename $file)" "$file"; bash <(curl -s https://codecov.io/bash) -cF whitebox_unitttests; done &&
    echo "Uploaded code coverage"
fi