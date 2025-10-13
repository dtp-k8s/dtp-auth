#! /usr/bin/env bash
# Runs the Docker container for the dtp-auth service.
#
# Uses --net=host to share the host network.  This allows communications between the containerized
# service and MicroK8s services on the host, useful for testing the containerized service before
# deploying to Kubernetes.

docker run --rm --name dtp-auth \
    --net=host \
    --env-file .env \
    "$@" \
    yinchi/dtp-auth:latest
