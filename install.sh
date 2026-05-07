#!/bin/bash

git submodule update --init --recursive
cd virtualsmartcard/
autoreconf --verbose --install
#./configure
make
sudo make install
