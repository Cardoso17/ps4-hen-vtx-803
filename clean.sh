#!/bin/bash

pushd kpayload
make clean
popd

pushd installer
make clean
popd

rm -f ps4-hen-1000-1001-PPPwn-vtx.bin payload.js
