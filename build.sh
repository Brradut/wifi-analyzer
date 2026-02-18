#!/bin/bash

if [ $1 == "local" ]; then
    CGO_LDFLAGS='-Wl,-rpath,/usr/local/lib' wails build -tags webkit2_41
elif [ $1 == "dev" ]; then
    CGO_LDFLAGS='-Wl,-rpath,/usr/local/lib' wails dev -tags webkit2_41
else
docker build \
    --no-cache-filter build \
    --no-cache-filter runtime \
    --output type=local,dest=./output \
    . -f Dockerfile \
    --progress=plain 
fi