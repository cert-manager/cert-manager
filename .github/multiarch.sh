#!/usr/bin/env bash

set -o errexit
set -o pipefail
# set -x

BASEDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"

IMAGES=(cert-manager-acmesolver
cert-manager-startupapicheck
cert-manager-webhook
cert-manager-controller
cert-manager-cainjector
)

if [[ ${TAG} =~ "fips" ]]; then
    echo "pushing cert-manager images from amd64 only"
    for image in "${IMAGES[@]}"; do
         docker tag  $image-amd64:$TAG $HUB/$image-amd64:$TAG  
         docker push  $HUB/$image-amd64:$TAG         
         docker manifest create $HUB/$image:$TAG --amend $HUB/$image-amd64:$TAG
         docker manifest push $HUB/$image:$TAG
    done
else
    for image in "${IMAGES[@]}"; do
         docker tag  $image-amd64:$TAG $HUB/$image-amd64:$TAG
         docker tag  $image-arm64:$TAG $HUB/$image-arm64:$TAG
         docker push   $HUB/$image-amd64:$TAG
         docker push   $HUB/$image-arm64:$TAG
         docker manifest create $HUB/$image:$TAG --amend $HUB/$image-amd64:$TAG --amend $HUB/$image-arm64:$TAG
         docker manifest push $HUB/$image:$TAG
    done
fi
   

