#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail

BOULDER_URL="http://127.0.0.1:4000"

while ! curl "${BOULDER_URL}" > /dev/null 2>&1 ; do
  echo "Waiting for boulder API to be available..."
  sleep 5
done

echo "Boulder API now available at ${BOULDER_URL}"
