#!/bin/bash

git submodule update --init --recursive
cd virtualsmartcard/
autoreconf --verbose --install
# Uncomment for first installation
#./configure
make
sudo make install
