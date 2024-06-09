#!/bin/bash

pushd kpayload
make clean
popd

pushd installer
make clean
popd

rm -f ps4-hen-1050-1071-vtx.bin payload.js
