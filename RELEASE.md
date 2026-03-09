# Releases

## Schedule

The release schedule for cert-manager is defined on the [cert-manager website](https://cert-manager.io/docs/releases/).

## Process

The release process is described in detail on the [cert-manager website](https://cert-manager.io/docs/contributing/release-process/).

## Artifacts

The cert-manager project will produce the following artifacts each release. For documentation on how those artifacts are produced see the "Process" section.

- *Container Images* - Container images for the cert-manager project are published for all cert-manager components.
- *Helm chart* - An official Helm chart is maintained within this repo and published to an OCI registry on each cert-manager release. The chart is available at `quay.io/jetstack/cert-manager` as well as the legacy location `charts.jetstack.io`.
- *Binaries* - The cmctl CLI has moved to its [own repository](https://github.com/cert-manager/cmctl). Binary builds are available for download from that location.