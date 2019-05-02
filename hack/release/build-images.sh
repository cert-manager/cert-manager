#!/usr/bin/env bash

## Sample bash script demonstrating how to use the release tool.

### Build a local copy of all amd64 image components using a custom repo name

./release \
    --repo-root $PWD \
    --docker-repo index.docker.io/mydockerhubuser \
    --images \
    --images.goarch amd64 \

### Build a local copy of the controller image for amd64

./release.sh \
    --repo-root $PWD \
    --images \
    --images.goarch amd64 \
    --images.components controller
