#!/bin/bash
set -eu
cd build
make
cp syncpass ../
