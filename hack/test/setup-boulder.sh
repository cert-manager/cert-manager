#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail

BOULDER_REPO="github.com/letsencrypt/boulder"
BOULDER_URL="http://127.0.0.1:4000"

echo "Fetching ${BOULDER_REPO}"
go get -d github.com/letsencrypt/boulder || true
echo "Retrieved boulder repository"
cd "${GOPATH}/src/${BOULDER_REPO}"

# Modify boulder configuration
sed -i 's/FAKE_DNS: 127.0.0.1/FAKE_DNS: 10.0.0.10/' docker-compose.yml
sed -i 's/127.0.0.1:8053/10.0.0.10:53/' test/config/va.json
sed -i 's/5002/80/' test/config/va.json
# TODO: set ratelimits

function start {
    if ! docker-compose up; then
        echo "Error running boulder"
        exit 1
    fi
}

start &

echo "Started boulder process in background"
