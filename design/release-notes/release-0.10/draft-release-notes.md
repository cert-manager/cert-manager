The v0.10 release comes quick on the heels of v0.9. It continues the work on
the new CertificateRequest resource type, moving us towards a world where
out-of-tree Issuer types are first class citizens.

As a project, we're pushing towards a 'stable' API release and eventually, a
v1.0 release. This release, and the releases to follow over the coming months,
lay the foundation for these milestones. Keep an eye on the releases page over
the coming months for some exciting new developments!

You can get started using the new CertificateRequest controllers by enabling
the `CertificateRequestControllers` feature gate - all Issuer types are now
supported, and your feedback is extremely valuable before we switch the new
implementation to be the default in v0.11!

We've also simplified the way we bootstrap TLS certificates for the 'webhook'
component. Now, instead of creating an Issuer and Certificate resource for the
webhook (requiring you to disable validation on the cert-manager namespace),
we've implemented a dedicated 'webhookbootstrap' controller which will manage
TLS assets for the webhook.

---

This release includes changes from:

* Alejandro Garrido Mota
* Alpha
* Hans Kristian Flaatten
* James Munnelly
* Jonas-Taha El Sesiy
* JoshVanL
* Marcello Romani
* Moritz Johner
* Nicolas Kowenski
* Olaf Klischat
* Vasilis Remmas
* stuart.warren
* zeeZ

## Notable Items

### All Issuer types now supported with CertificateRequests

The CertificateRequest design proposal, first implemented in v0.9, changes the
way we request certificates from Issuers in order to allow out-of-tree Issuer
types.
This required us to refactor and adapt our existing in-tree Issuer types to
follow a similar pattern.

The v0.10 release finishes this refactoring so that all Issuer types now
support the new format.

As the feature is currently still in an 'alpha' state, you must set the
`issuerRef.group` field on your Certificate resources to `certmanager.k8s.io`,
as well as enabling the `CertificateRequestControllers` feature gate on the
`controller` component of cert-manager.

### Simplified webhook TLS bootstrapping

In past releases, we've managed TLS for the webhook component by creating an
internal self signed and CA issuer that is used to mint serving certificates
for the apiserver to authenticate the webhook's identity.

This introduced a number of complexities in our installation process and has
caused trouble for users in the past.

In order to simplify this process and to support running a CRD conversion
webhook in future (to provide seamless migration between API versions), we've
introduced a dedicated `webhookbootstrap` controller that relies on flags and
Secret resources in order to configure TLS for the webhook.

This will mean easier installation as well as future-proofing for our upcoming
plans in future releases.

### KeyUsages on Certificate resources

In order to support a more diverse set of applications, including apps that
require client-auth certificates, a new field `keyUsages` has been added which
accepts a list of usages that must be present on a Certificate.

These will be automatically added when certificates are issued, just like any
other field on the Certificate.

Thanks to Stuart Warren from Ocado for this change!

### Preparation for v1alpha2 and beyond

Over the last few releases, we've been making a number of significant changes
to our API types (i.e. moving ACME configuration from Certificate resources
onto the Issuer resource). This has involved deprecating some old API fields.

In a future release, we'll be removing these deprecated fields altogether,
requiring users to update their manifests to utilise the new way to specify
configuration.

A number of steps have been taken in our own codebase to support this change,
and in a future release, you'll be required to update **all** your manifests for
this new format. Future API revisions (e.g. v1beta1 and v1) will be
automatically converted using a Kubernetes conversion webhook (available in
beta from Kubernetes 1.15 onwards).

## Action Required

No special actions are required as part of this release.

## Changelog

### General

- Add DisableDeprecatedACMECertificates feature gate to disable the old deprecated ACME config format ([#1923](https://github.com/jetstack/cert-manager/pull/1923), [@munnerz](https://github.com/munnerz))
- chart: fix formatting of values table in README.md ([#1936](https://github.com/jetstack/cert-manager/pull/1936), [@Starefossen](https://github.com/Starefossen))
- Add internal API version and implement machinery for defaulting & conversion ([#2002](https://github.com/jetstack/cert-manager/pull/2002), [@munnerz](https://github.com/munnerz))
- Fix concurrent map write panic in certificates controller ([#1980](https://github.com/jetstack/cert-manager/pull/1980), [@munnerz](https://github.com/munnerz))
- cainjector: allow injecting CAs directly from Secret resources ([#1990](https://github.com/jetstack/cert-manager/pull/1990), [@munnerz](https://github.com/munnerz))
- Mark 'spec' and 'status' as non-required fields in CRDs ([#1957](https://github.com/jetstack/cert-manager/pull/1957), [@munnerz](https://github.com/munnerz))
- Add ability to specify key usages and extended key usages in certificates ([#1996](https://github.com/jetstack/cert-manager/pull/1996), [@stuart-warren](https://github.com/stuart-warren))

### ACME Issuer

- Add option to assume role in Route53 DNS01 provider ([#1917](https://github.com/jetstack/cert-manager/pull/1917), [@moolen](https://github.com/moolen))
- Fix documentation for AzureDNS service principal creation ([#1960](https://github.com/jetstack/cert-manager/pull/1960), [@elsesiy](https://github.com/elsesiy))

### Webhook

- Use dedicated controller for webhook TLS bootstrapping ([#1993](https://github.com/jetstack/cert-manager/pull/1993), [@munnerz](https://github.com/munnerz))

### CertificateRequest

- Add ACME CertificateRequest controller implementation ([#1943](https://github.com/jetstack/cert-manager/pull/1943), [@JoshVanL](https://github.com/JoshVanL))
- Add Vault CertificateRequest controller implementation ([#1934](https://github.com/jetstack/cert-manager/pull/1934), [@JoshVanL](https://github.com/JoshVanL))
- Add SelfSigned CertificateRequest controller implementation ([#1906](https://github.com/jetstack/cert-manager/pull/1906), [@JoshVanL](https://github.com/JoshVanL))
- Add Venafi CertificateRequest controller implementation ([#1968](https://github.com/jetstack/cert-manager/pull/1968), [@JoshVanL](https://github.com/JoshVanL))
- Don't validate issuerRef.kind field if issuerRef.group is set in order to support out-of-tree Issuer types ([#1949](https://github.com/jetstack/cert-manager/pull/1949), [@munnerz](https://github.com/munnerz))
- Adds CertificateRequest FailureTime. The Certificate controller will re-try failed CertificateRequests at least one hour after this failed time. ([#1979](https://github.com/jetstack/cert-manager/pull/1979), [@JoshVanL](https://github.com/JoshVanL))

### Monitoring

- Added variable to specify custom namespace where to deploy ServiceMonitor resource ([#1970](https://github.com/jetstack/cert-manager/pull/1970), [@mogaal](https://github.com/mogaal))
- helm: fix labels and add Service for Prometheus ServiceMonitor ([#1942](https://github.com/jetstack/cert-manager/pull/1942), [@Starefossen](https://github.com/Starefossen))
