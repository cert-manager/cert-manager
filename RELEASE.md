# Releases

## Schedule

The release schedule for cert-manager is defined on the [cert-manager website](https://cert-manager.io/docs/releases/).

## Process

The release process is described in detail on the [cert-manager website](https://cert-manager.io/docs/contributing/release-process/).

## Artifacts

The cert-manager project will produce the following artifacts each release. For documentation on how those artifacts are produced see the "Process" section.

- *Container Images* - Container images for the cert-manager project are published for all cert-manager components. 
- *Helm chart* - An official Helm chart is maintained within this repo and published to `charts.jetstack.io` on each cert-manager release.
- *Binaries* - Until version 1.15 the cmctl binary was maintained within this repo and published as part of the cert-manager release. For releases after 1.15 the CLI has moved to its [own repository](https://github.com/cert-manager/cmctl). Binary builds are still available for download from this new location.