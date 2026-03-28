#!/bin/bash

git submodule update --init --recursive
cd virtualsmartcard/
autoreconf --verbose --install
make
sudo make install

sudo usermod -a -G pcscd $USER