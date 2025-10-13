#! /usr/bin/env bash
# Builds and pushes the Docker image for the dtp-auth service.

# cd to the current script directory, then to the repo root
# This ensures the script works when run from any directory
cd "$(dirname "$0")"  || exit 1
cd "$(git rev-parse --show-toplevel)" || exit 1

docker build -t yinchi/dtp-auth:latest --push .
