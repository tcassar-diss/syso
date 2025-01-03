#! /usr/bin/env bash

echo "[INFO] Running \`syso\`"

if [[ ! -f Dockerfile ]]; then
    echo "[ERROR] Dockerfile not found"
    exit 1
fi

echo "[INFO] Building image..."

make

if [[ $? -ne 0 ]]; then
    echo "[error] make was unsuccessful (returned code $build_res)"
    exit 1
fi;



docker build . -t syso
build_res=$?

if [[ build_res -ne 0 ]]; then
    echo "[error] docker build was unsuccessful (returned code $build_res)"
    exit 1
fi;

echo "[INFO] Build successful"

echo "[INFO] Running image"

docker run --security-opt=seccomp:unconfined --pid=host --privileged -v ./stats:/app/stats syso ./main
run_res=$?

if [[ run_res -ne 0 ]]; then
    echo "[ERROR] run was unsuccessful (returned code $build_res)"
    exit 1
fi;

echo "[INFO] Wrote output to ./stats"

