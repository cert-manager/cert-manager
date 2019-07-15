The long-awaited v0.6 release is here! This release includes a huge number of improvements, bug fixes and new features.

We've made a big focus on the ACME implementation, as well as improving the general user-experience when requesting certificates.

We've exposed new x509 certificate fields via the Certificate resource type, as well as improving support for these options across all Issuer types.

As of the v0.6 release being cut, we've also reached a huge 99 code contributors! This is incredible to see, and we're thankful to all those who have contributed in all forms over the last couple of years!

Read on to get some of the highlights, as well as the full list of note-worthy changes below!

# Highlights
## Introducing ACME 'Order' and 'Challenge' CRDs
This release of cert-manager refactors how ACME certificates are handled significantly.

This should result in:

Fewer API calls to ACME servers - information about orders and challenges is now stored within the Kubernetes API
Better behaviour with regards to rate limits
A cleaner surface for debugging issues - we can now provide more context and information through the Events API as well as the 'status' field on our API types
This is largely an internal change, but with far reaching benefits.
For more details, check out the details in the pull request (#788).

We are keen to hear feedback on this new design, so please create issues including the /area provider-acme text in order to report feedback/problems.

## Improved handling of ACME rate limits
After extensive testing, we've found in the most extreme cases a 100x reduction in ACME API client calls.

This is a massive difference, and helps reduce the load that instances of cert-manager put on services like Let's Encrypt.

As a result, we strongly recommend all users upgrade to the v0.6 release as soon as possible!

## Prometheus metrics for the ACME client
In order to support the API client testing above, we've also added support for Prometheus metrics into our ACME client.

This means you can now start instrumenting cert-manager's own usage of ACME APIs, in order to detect issues and understand behaviour before it becomes a problem.

The metrics are broken down by path, status code and a number of other labels.

## Validating resource webhook enabled by default
In order to provide a better experience out of the box, we've now enabled the validating webhook component by default.

This means that when you submit resources to the API server, they will be checked for misconfigurations before they are persisted to the API, meaning configuration errors are surfaced immediately, and in some cases alongside steps that can be taken to remediate the errors.

## ECDSA keys supported for ACME certificates
It's now possible to create ECDSA private keys when issuing certificates from ACME servers. You can configure the key type and key size using certificate.spec.keyAlgorithm and certificate.spec.keySize respectively.

## Scalability improvements
As part of our validation for this release, we've been able to test cert-manager in larger deployment configurations.

This includes running with an ACME issuer with 6k+ domain names, showing that our client usage remains sensible and cert-manager itself does not begin to strain.

Off the back of this scale testing, we've also got numerous scale-related improvements triaged for the next minor release, v0.7.

# Action Required
There is only one PR that changes previous behaviour in this release.

Between v0.4.0 and v0.5.0, we introduced support for following CNAME records when presenting DNS01 challenges. This inadvertently broke DNS01 challenge solving when a user used a CNAME record at the route of their DNS zone (i.e. on Route53 when using an Amazon ELB).

This change reverts the default behaviour to support this kind of setup without additional changes, and instead introduces a new cnameStrategy field on ACME Issuer resources. You can set this field to Follow to restore the behaviour introduced in v0.5.0.

This note only affects the ACME Issuer type.

# Changelog
## General
- Bump Go version to 1.11 (#1050, @munnerz)
- Removed the Git commit hash from the version string in non canary builds (#997) (#1021, @Nalum)
- Include ca.crt in created secrets for Issuers that support it (vault, ca and selfsigned) (#848, @Queuecumber)
- Added RBAC permissions for user facing roles to access Certificates and Issuers. (#902, @fuel-wlightning)
- Add global.priorityClassName option to Helm chart (#1190, @Art3mK)
- Add --namespace option to limit scope to a single namespace (#1188, @kragniz)
- Print more useful information about Certificate, Order and Challenge resources when running kubectl get (#1194, @munnerz)
## ACME Issuer
- Introduce ACME 'Order' and 'Challenge' resource types & re-implement ACME Issuer to be completely driven by CRDs (#788, @munnerz)
- ACTION REQUIRED: Fix ACME issues relating to wildcard CNAME records and add a 'cnameStrategy' field to the ACME Issuer DNS01 provider config. (#1136, @munnerz)
- Added certmanager.k8s.io/acme-http01-ingress-class annotation to ingress-shim (#1006, @kinolaev)
- Make http01 solver serviceType configurable, so one can use ClusterIP instead of the previously hardcoded type NodePort. NodePort still remains as default. (#924, @arnisoph)
- Revised Cert Issuer Docs for DNS01 challenge and added a doc for AzureDNS (#915, @damienwebdev)
- Make http01 solver pod resource request/limits configurable (#923, @arnisoph)
- Allow ECDSA keys for ACME certificates (#937, @acoshift)
- RFC2136 provider: fixes a minor bug where dns01 nameserver key has value with no port (#908, @splashx)
- Add ACME HTTP client prometheus metrics (#1226, @munnerz)
- Reduce usage of ACME 'new-acct' endpoint (#1227, @munnerz)
- Disable TLS verification when self-checking (#1221, @DanielMorsing)
- Adds new flag --dns01-recursive-nameservers-only=[true|false] that defaults to false. When true, cert-manager will only ever query the configured DNS resolvers to perform the ACME DNS01 self check. This is useful in DNS constrained environments, where access to authoritative nameservers is restricted. Enabling this option could cause the DNS01 self check to take longer due to caching performed by the recursive nameservers. (#1184, @tlmiller)
- Retain Challenge resources when an Order has entered a failed state to make debugging easier (#1197, @munnerz)
- Increase back-off time between ACME order attempts on failure from 5m to 1h (#1195, @munnerz)
- Add 'reason' field when an order/challenge gets marked invalid (#1192, @DanielMorsing)
- Add DigitalOcean DNS Provider (#972, @aslafy-z)
## CA Issuer
- Update CA Issuer status condition usage (#961, @munnerz)
- It is now possible to include a certificate chain in the secret for the ca Issuer. This will then be propagated to generated certificates. (#1077, @mikebryant)
## Vault Issuer
- A new field caBundle added to the Vault Issuer configures a CA certificate used to validate the connection to the Vault Server. (#911, @vdesjardins)
## Bugfixes
- Increase time between retries for failing issuers and clusterissuers (#981, @munnerz)
- Fix concurrent map write race condition in ACME solver (#1033, @munnerz)
- Fix bug when updating ACME server URL on an existing Issuer resource (#1230, @munnerz)
- Fix issuing a certificate into a pre-existing secret resource (#1217, @munnerz)
- Fix affinity and tolerations declaration (#1209, @GuillaumeSmaha)
