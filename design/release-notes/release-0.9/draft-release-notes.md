The v0.9 release is one of our biggest yet, packed with new features and bug
fixes!

The introduction of the new CertificateRequest resource type is significant as
it is a step towards where we want to be for 1.0, defining an API specification
for Certificates and allowing anyone to implement their own issuers and CAs as
first class citizens.

This release includes changes from:

* Aaron Gershman
* Aled James
* Artem Yarmoluk
* Carlos Panato
* Chris Abiad
* Christopher Abiad
* Crystal-Chun
* Dan
* Dobes Vandermeer
* Hans Kristian Flaatten
* Hays Clark
* Ivan Wallis
* James Munnelly
* Joshua Van Leeuwen
* Kevin Woo
* Lachlan Cooper
* Louis Taylor
* Michael Cristina
* Michael Tsang
* PirateBread
* Qiu Yu
* Sergej Nikolaev
* Solly Ross
* Stefan Kolb
* Steven Tobias
* Stuart Hu
* Till Wiese
* kfoozminus

## Notable Items

### New CertificateRequest Resource

A new resource has been introduced - `CertificateRequest` - that is used to
request certificates using a raw x509 certificate signing request. This resource
is not typically used by humans but rather by other controllers or services. For
example, the `Certificate` controller will now create a `CertificateRequest`
resource to resolve its own Spec.

Controllers to resolve `CertificateRequest`s are currently disabled by default
and enabled via the feature gate `CertificateRequestControllers`. This feature
is currently in Alpha and only the CA issuer has been implemented.

This resource is going to enable out of tree, external issuer controllers to
resolve requests. Other issuer implementations and details on how to develop an
out of tree issuer will follow in later releases. You can read more on the
motivations and road map in the [enhancement
proposal](https://github.com/jetstack/cert-manager/blob/master/design/20190708.certificate-request-crd.md)
or how this resource is used in the
[docs](https://docs.cert-manager.io/en/release-0.9/reference/certificaterequests.html).


### DNS Zones support for ACME challenge solver selector

A list of DNS zones can now be added to the ACME challenge solver selector.  The
most specific DNS zone match specified here will take precedence over other DNS
zone matches, so a solver specifying `sys.example.com` will be selected over one
specifying `example.com` for the domain `www.sys.example.com`. If multiple
solvers match with the same dnsZones value, the solver with the most matching
labels in matchLabels will be selected. If neither has more matches, the solver
defined earlier in the list will be selected.

### Certificate Readiness Prometheus Metrics

Cert-manager now exposes Prometheus metrics on Certificate ready statuses as
`certmanager_certificate_ready_status`. This is useful for monitoring
Certificate resources to ensure they have a `Ready=True` status.

### Prometheus Operator ServiceMonitor

Support has been added to include a Prometheus ServiceMonitor for cert-manager
in the helm chart. This enables monitoring of cert-manager when in conjunction
with the [Prometheus Operator](https://github.com/coreos/prometheus-operator).
This is disabled by default but can be enabled via the helm configuration.

### ACMEv2 POST-as-GET

We have now switched to use the new POST-as-GET feature that was introduced
into the latest version of the ACME spec a few months ago.

If you are running your own ACME server, please ensure it supports POST-as-GET
as we no longer supported the old behaviour.

### ACME Issuer Solver Pod Template

The ACME Solver Pod Spec now exposes a template that can be used to change
metadata about that pod. Currently, a template will expose labels, annotations,
node selector, tolerations, and affinity. This is useful when running
cert-manager in multi-arch clusters, or when you run workloads across different
types of nodes and need to restrict where the acmesolver pod runs.

## Action Required

### Length limit for Common Names

Common names with a character length of over 63 will be rejected during
validation. This is due to the upper limit being detailed in RFC 5280.

### Distroless Cert-Manager Base Images

For each container, cert-manager ships with the base image
'gcr.io/distroless/static' which is a minimal image that includes no binaries.
Users who want to debug from within the cert-manager pod will need to attach an
additional container with their debug utilities to the pod's namespace.

### CSRs in Order Resources now PEM Encoded

CSRs in Order resources have previously been incorrectly DER encoded due to an
error in implementation. This has now been corrected to PEM encoding. Current
orders that were created with a previous version of cert-manager will fail to
validate and so will be recreated. This should resume the order normally.

## Changelog

### General

- Reduce cert-manager's RBAC permissions ([#1658](https://github.com/jetstack/cert-manager/pull/1658), [@munnerz](https://github.com/munnerz))
- commented-out extraArg for enable-certificate-owner-ref ([#1828](https://github.com/jetstack/cert-manager/pull/1828), [@aegershman](https://github.com/aegershman))
- Validate that Certificates in a namespace have unique `secretName` ([#1689](https://github.com/jetstack/cert-manager/pull/1689), [@cheukwing](https://github.com/cheukwing))
- Feature addition: Support for PKCS&#35;8 keys. ([#1308](https://github.com/jetstack/cert-manager/pull/1308), [@Crystal-Chun](https://github.com/Crystal-Chun))
- Add the removal of certificates when no longer required by the owner ingress ([#1705](https://github.com/jetstack/cert-manager/pull/1705), [@cheukwing](https://github.com/cheukwing))
- Fix bug causing ECDSA certificates to be issued using 2048-bit RSA private keys ([#1757](https://github.com/jetstack/cert-manager/pull/1757), [@munnerz](https://github.com/munnerz))
- Updated the labels in the helm charts to use the newer ones. ([#1769](https://github.com/jetstack/cert-manager/pull/1769), [@cpanato](https://github.com/cpanato))
- Allow disabling issuing temporary certificates with feature flag `--feature-gates=IssueTemporaryCertificate=false` ([#1764](https://github.com/jetstack/cert-manager/pull/1764), [@gordonbondon](https://github.com/gordonbondon))
- Switch to using distroless for base images ([#1663](https://github.com/jetstack/cert-manager/pull/1663), [@munnerz](https://github.com/munnerz))
- Limit length for CommonName to 63 bytes ([#1818](https://github.com/jetstack/cert-manager/pull/1818), [@cheukwing](https://github.com/cheukwing))

### ACME Issuer

- Properly encode the CSR field on Order resources as PEM data instead of DER ([#1884](https://github.com/jetstack/cert-manager/pull/1884), [@munnerz](https://github.com/munnerz))
- Fire informational Event if an ACME solver cannot be chosen for a domain on an Order ([#1856](https://github.com/jetstack/cert-manager/pull/1856), [@munnerz](https://github.com/munnerz))
- Fix bug with auto-generated Order names being longer than 63 characters ([#1765](https://github.com/jetstack/cert-manager/pull/1765), [@cheukwing](https://github.com/cheukwing))
- Fix a panic when a misconfigured Issuer is used for HTTP01 challenge solving ([#1758](https://github.com/jetstack/cert-manager/pull/1758), [@munnerz](https://github.com/munnerz))
- Fix a bug where the logic to select a solver would always return the last solver and may return the wrong kind of solver for the challenge that it returned. ([#1717](https://github.com/jetstack/cert-manager/pull/1717), [@dobesv](https://github.com/dobesv))
- Fix indentation on ACME setup examples ([#1785](https://github.com/jetstack/cert-manager/pull/1785), [@lachlancooper](https://github.com/lachlancooper))
- Fix a the logic to select the most specific solver from an issuer if multiple matched ([#1715](https://github.com/jetstack/cert-manager/pull/1715), [@dobesv](https://github.com/dobesv))
- Adds support for `nodeSelector` and `tolerations` in `podTemplate.spec` ([#1803](https://github.com/jetstack/cert-manager/pull/1803), [@cheukwing](https://github.com/cheukwing))
- support azure non-public regions ([#1830](https://github.com/jetstack/cert-manager/pull/1830), [@stuarthu](https://github.com/stuarthu))
- Fix issue causing challenge controller to attempt to list Secrets across all namespaces even when --namespace is specified ([#1849](https://github.com/jetstack/cert-manager/pull/1849), [@munnerz](https://github.com/munnerz))
- Adds the handling of updates to the `spec.acme.email` field in Issuers ([#1763](https://github.com/jetstack/cert-manager/pull/1763), [@cheukwing](https://github.com/cheukwing))
- Fix issue with private managed-zone being picked in CloudDNS ([#1704](https://github.com/jetstack/cert-manager/pull/1704), [@cheukwing](https://github.com/cheukwing))
- Expose pod template for the ACME issuer solver pod ([#1749](https://github.com/jetstack/cert-manager/pull/1749), [@JoshVanL](https://github.com/JoshVanL))
- Ingress skips updating Certificate resource if already exists and not owned ([#1670](https://github.com/jetstack/cert-manager/pull/1670), [@cheukwing](https://github.com/cheukwing))
- Add support for ACMEv2 POST-as-GET ([#1648](https://github.com/jetstack/cert-manager/pull/1648), [@munnerz](https://github.com/munnerz))
- Fix incorrect handling of `issuewild` tag when verifying CAA ([#1777](https://github.com/jetstack/cert-manager/pull/1777), [@cheukwing](https://github.com/cheukwing))
- Add support for selecting ACME challenge solver to use by specifying 'dnsZones' in the selector ([#1806](https://github.com/jetstack/cert-manager/pull/1806), [@munnerz](https://github.com/munnerz))
- Use proxy environment variables in self-check request ([#1850](https://github.com/jetstack/cert-manager/pull/1850), [@kinolaev](https://github.com/kinolaev))

### Venafi Issuer

- Venafi: use vCert v4.1.0 ([#1827](https://github.com/jetstack/cert-manager/pull/1827), [@munnerz](https://github.com/munnerz))
- Bump Venafi vcert dependency to latest version ([#1754](https://github.com/jetstack/cert-manager/pull/1754), [@munnerz](https://github.com/munnerz))

### Webhook

- cert-manager-webhook secret exists in cert-manager ns ([#1791](https://github.com/jetstack/cert-manager/pull/1791), [@jetstack-bot](https://github.com/jetstack-bot))
- Support CRD conversion webhooks in the CA injector controller. ([#1505](https://github.com/jetstack/cert-manager/pull/1505), [@DirectXMan12](https://github.com/DirectXMan12))

### CA Issuer

- Adds CSR signing to CA issuer ([#1835](https://github.com/jetstack/cert-manager/pull/1835), [@JoshVanL](https://github.com/JoshVanL))

### CertificateRequest

- Adds CertificateRequest resource ([#1789](https://github.com/jetstack/cert-manager/pull/1789), [@JoshVanL](https://github.com/JoshVanL))
- Adds CA issuer controller to resolve CertificateRequests where CA is the issuer reference ([#1836](https://github.com/jetstack/cert-manager/pull/1836), [@JoshVanL](https://github.com/JoshVanL))
- Adds Sign interface to Issuers ([#1807](https://github.com/jetstack/cert-manager/pull/1807), [@JoshVanL](https://github.com/JoshVanL))
- Adds `group` to `issuerRef` in `CertificateRequest` resources to distinguish resource ownership of incoming CertificateRequests so enabling full external issuer support.  ([#1860](https://github.com/jetstack/cert-manager/pull/1860), [@JoshVanL](https://github.com/JoshVanL))

### Documentation

- Adds Design and Proposals page to website docs ([#1876](https://github.com/jetstack/cert-manager/pull/1876), [@JoshVanL](https://github.com/JoshVanL))
- Adds CertificateRequest proposal ([#1866](https://github.com/jetstack/cert-manager/pull/1866), [@JoshVanL](https://github.com/JoshVanL))

### Monitoring

- Prometheus metrics for deleted Certificates are cleaned up ([#1681](https://github.com/jetstack/cert-manager/pull/1681), [@cheukwing](https://github.com/cheukwing))
- Adds `ControllerSyncCallCount` prometheus metric to count sync calls from each controller ([#1692](https://github.com/jetstack/cert-manager/pull/1692), [@cheukwing](https://github.com/cheukwing))
- Add support for Prometheus Operator ServiceMonitor object in Helm Chart ([#1761](https://github.com/jetstack/cert-manager/pull/1761), [@Starefossen](https://github.com/Starefossen))
- Add Prometheus metrics for tracking Certificate readiness ([#1811](https://github.com/jetstack/cert-manager/pull/1811), [@cheukwing](https://github.com/cheukwing))
