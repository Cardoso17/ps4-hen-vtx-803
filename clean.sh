#!/bin/bash

pushd kpayload
make clean
popd

pushd installer
make clean
popd

rm -f ps4-hen-800-803-PPPwn-vtx.bin payload.js
