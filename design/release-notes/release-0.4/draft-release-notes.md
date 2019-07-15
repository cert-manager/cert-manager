This is the next feature release of cert-manager, containing a number of additions
that have been in the works for a while now.

As you will notice from the release notes below, we are seeing a lot more community
contributions to the project which is brilliant! smile

A massive thank you to everyone involved in making this release a reality.

We have moved to a more regular minor-release schedule, and aim to cut new feature
releases monthly. That means the next minor release (v0.5) is scheduled for
around the 11th August.

# Highlights
## Resource validation for Issuers, ClusterIssuers and Certificates
A common pain point for users has been around submitting invalid resources to the
API, which cannot be handled or processed.

Other Kubernetes API types handle this well by applying 'validation' before the
resource is persisted or operated upon, and up until now we have not supported this.

When submitting your resources to the Kubernetes apiserver, they will now be validated
and if invalid, cert-manager will inform you of why and how they are invalid and
suspend processing of that resource.

In the next release, this validation will be turned into a 'ValidatingWebhookConfiguration'
which will allow us to prevent these resources being persisted into the API in
the first place, similar to all other Kubernetes resource types.

Due to some limitations with the current release of Helm, we have been unable to
support this webhook operation mode in the v0.4 release of cert-manager.
However, releasing validation this way allows us to pilot the new validation rules
we have in place and it allows you to get started with it immediately!

## Added reference documentation for API types
Regularly, users ask us "what can I specify on my resources". In the past, we have
had to recommend users check out our source code (namely types.go) in order to
find out what can and cannot be specified.

Digging through source code is no longer required! As part of our documentation
publishing process, we now generate reference API documentation (similar to the
upstream Kubernetes project!). This is available under the
'Reference documentation -> API documentation' section of our docs site!

## Better support for 'split horizon' DNS environments with ACME DNS01 challenges
A number of users have noticed that when running cert-manager with DNS01 challenges
in split-horizon DNS environments (using the ACME issuer), the self check stage
of the validation process failed as the 'internal' DNS resolvers were used to
check for challenge record propagation.

We have added a new flag, --dns01-self-check-nameservers, that allows users to specify
custom recursive DNS servers to use for performing DNS01 self checks.

In these environments, this flag can be set to some external nameserver list that
will be used for DNS01 resolution, e.g. 8.8.8.8:53,8.8.4.4:53.

## Self-signed Issuers
We recently merged support for 'self signed' issuers. This allows users to create
the basis for a completely cert-manager managed PKI by 'self signing' certificates.

This can be useful when debugging, or once cert-manager also supports setting the
isCA bit on a Certificate, for creating a self signed root CA!

Read up on how to get started with this new issuer type in the documentation.

# Changelog
## Action Required
- Check the acme issuer has the 'HTTP01' challenge type configured if in use. (#629, @groner)
ACME http01 validation is no longer attempted using an
Issuer/ClusterIssuer with no ACME http01 config. Note that the minimal
http01: {} config IS sufficient.

If you rely on ACME http01 validation, you should check your issuers to make
sure http01 validation is explicitly enabled as in previous release, this was
not verified!

## Other notable changes
### ACME Issuer
- Add --dns01-nameservers flag for setting nameservers for DNS01 check (#710, @kragniz)
- Fix bugs affecting eTLD and CNAMEs during DNS zone resolution (#582, @ThatWasBrilliant)
- Run acmesolver container as non-root user (#585, @klausenbusk)
- Support for ACME HTTP01 validations when using istio-ingress with a mTLS enabled mesh (#622, @munnerz)
### Vault Issuer
- Configurable Vault appRole authentication path using the attribute is spec.vault.auth.authPath in the issuer. (#612, @vdesjardins)
### Self-signed Issuer
- Add 'self signed' Issuer type (#637, @munnerz)
### Docs
- Add reference documentation for API types (#644, @munnerz)
### Helm
- Added configuration variables to set http_proxy, https_proxy and no_proxy environment variables in Helm chart. (#680, @fllaca)
- added option to set additional environment variable values to the helm chart (#556, @nazarewk)
### Other
- Add certmanager.k8s.io/certificate-name label to secrets. (#719, @kragniz)
- Add resource validation at start of sync loops, and mark resources as not Ready when invalid (#682, @munnerz)
- To disable ingress-shim, you can now set this flag: --controllers=issuers,clusterissuers,certificates (#717, @kragniz)
