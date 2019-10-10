The v0.11 release is a significant milestone for the cert-manager project, and
is full of new features.
We are making a number of changes to our CRDs in a backwards incompatible way,
in preparation for moving into `v1beta1` and eventually `v1` in the coming
releases:

* Renaming our API group from `certmanager.k8s.io` to `cert-manager.io`
* Bumping the API version from v1alpha1 to v1alpha2
* Removing fields deprecated in v0.8 (`certificate.spec.acme`,
  `issuer.spec.http01` and `issuer.spec.dns01`)
* Renaming annotation prefixes on Ingress & cert-manager resources to use the
  new `cert-manager.io` prefix, and in some cases `acme.cert-manager.io`
* Using the `status` subresource for submitting status updates to the API,
  first introduced in Kubernetes 1.9.
* Tightening use of common name vs DNS name with ACME certificates

We have also switched to using the new [CertificateRequest] based Certificate
issuance implementation, first introduced in alpha in cert-manager v0.9.

These changes enable exciting new integrations points in cert-manager, enabling
new things like:

* External issuer types, such as the [Smallstep Step Issuer]
* Deeper integrations into Kubernetes, with an experimental [CSI driver] that
  can be used to automatically mount signed certificates into pods
* Experimental integration with Istio, allowing you to utilise any of
  cert-manager's configured issuer types/CAs with the [node agent]
* Retrieving certificates without giving cert-manager access to your private
  keys

This is a really exciting time for cert-manager, as these changes have been
made possible by refining our past decisions around API types, and they will
enable us to push ahead with many new features in the project.

## Important information

With all of these great changes, there is also work to do.

The changes to our CRD resources mean that upgrading requires more manual
intervention than in previous releases.

It's recommended that you backup and completely [uninstall
cert-manager](https://docs.cert-manager.io/en/release-0.11/tasks/uninstall/index.html)
before re-installing the v0.11 release.

You will also need to manually update all your backed up cert-manager resource
types to use the new `apiVersion` setting.

A table of resources and their old and new `apiVersion`s:

| Kind               | Old apiVersion                | New apiVersion                  |
|--------------------|-------------------------------|---------------------------------|
| Certificate        | `certmanager.k8s.io/v1alpha1` | `cert-manager.io/v1alpha2`      |
| Issuer             | `certmanager.k8s.io/v1alpha1` | `cert-manager.io/v1alpha2`      |
| ClusterIssuer      | `certmanager.k8s.io/v1alpha1` | `cert-manager.io/v1alpha2`      |
| CertificateRequest | `certmanager.k8s.io/v1alpha1` | `cert-manager.io/v1alpha2`      |
| Order              | `certmanager.k8s.io/v1alpha1` | `acme.cert-manager.io/v1alpha2` |
| Challenge          | `certmanager.k8s.io/v1alpha1` | `acme.cert-manager.io/v1alpha2` |

You must also make sure to update all references to cert-manager in annotations to their
new prefix:

| Annotation                                   | Affected resources         | New annotation                              |
|----------------------------------------------|----------------------------|---------------------------------------------|
| certmanager.k8s.io/acme-http01-edit-in-place | Ingress                    | acme.cert-manager.io/http01-edit-in-place   |
| certmanager.k8s.io/acme-http01-ingress-class | Ingress                    | acme.cert-manager.io/http01-ingress-class   |
| certmanager.k8s.io/issuer                    | Ingress                    | cert-manager.io/issuer                      |
| certmanager.k8s.io/cluster-issuer            | Ingress                    | cert-manager.io/cluster-issuer              |
| certmanager.k8s.io/acme-challenge-type       | Ingress                    | REMOVED                                     |
| certmanager.k8s.io/acme-dns01-provider       | Ingress                    | REMOVED                                     |
| certmanager.k8s.io/alt-names                 | Ingress, Secret            | cert-manager.io/alt-names                   |
| certmanager.k8s.io/ip-sans                   | Ingress, Secret            | cert-manager.io/ip-sans                     |
| certmanager.k8s.io/common-name               | Ingress, Secret            | cert-manager.io/common-name                 |
| certmanager.k8s.io/issuer-name               | Ingress, Secret            | cert-manager.io/issuer-name                 |
|                                              | Ingress, Secret            | cert-manager.io/issuer-kind                 |
|                                              | Ingress, Secret            | cert-manager.io/issuer-group                |
|                                              | Ingress, Secret            | cert-manager.io/uri-sans                    |
|                                              | Certificate                | cert-manager.io/issue-temporary-certificate |
|                                              | CertificateRequest         | cert-manager.io/private-key-secret-name     |
| certmanager.k8s.io/certificate-name          | CertificateRequest, Secret | cert-manager.io/certificate-name            |


## Contributors

This release has seen code contributions from a number of people in the
community :tada:

* Adam Kunicki
* Alpha
* Brian Hong
* Dan Farrell
* Dig-Doug
* Galo Navarro
* Ingo Gottwald
* James Munnelly
* JoshVanL
* Kevin Lefevre
* Lachlan Cooper
* Michel Blankleder
* Toni Menzel
* Wellington F Silva
* Woz
* dulltz

As always, a big thank you to those opening issues, replying to issues and
helping out in the Slack channel. As well as working in other projects to help
users secure services running on Kubernetes.

## Notable changes

### Renamed API group

Due to new policies in the upstream Kubernetes project, we have renamed the
API group from `certmanager.k8s.io` to `cert-manager.io`.

This is a breaking change to our API surface as mentioned above, but it
is a long time coming. The original `k8s.io` suffix was used when the project
first started as there was not official guidance or information on how
`ThirdPartyResources` should be structured. Now that this area of the
Kubernetes project has evolved further, we're retrospectively changing this to
conform with the new requirements.

### Moving to v1alpha2

When cert-manager first started, we defined our APIs based on what we thought
made sense for end-users.

Over time, through gathering feedback and monitoring the way users are actually
using cert-manager, we've identified some issues with our original API design.

As part of the project moving towards v1, we've identified certain areas of our
APIs that are not fit for purpose.

In order to begin the process of moving towards `v1`, we first deprecated a
number of fields in our `v1alpha1` API. We've now **dropped** these API fields
in `v1alpha2`, in preparation for declaring this new API as `v1beta1` in the
coming releases.

### New CertificateRequest resource type

The activation of `CertificateRequest` controllers are no longer behind a
feature and are now instead enabled by default. This means that when requesting
certificates using the `Certificate` resource the `CertificateRequest` resource
will be used as the default and only way to honour the request. The addition of
this resource introduces the ability for much greater extension points to
cert-manager, notably out-of-tree issuers, istio integrations, and experimental
tooling such as a CSI driver. You can read more about the motivation and design
of this resource in the [enhancement
document](https://github.com/jetstack/cert-manager/blob/master/design/20190708.certificate-request-crd.md).

This change should cause no disruption to how end users interact with
cert-manager, with the exception of debugging now requiring this resource to be
inspected also.

### Support for out-of-tree issuer types

With the graduation of the `CertificateRequest` resource, cert-manager now
supports out-of-tree issuers by default and treats them the same as any other
core issuer. This process is facilitated by the addition of the `group` field on
issuer references inside your `Certificate` and `CertificateRequest` resources.

If you're interested in implementing your own out-of-tree issuer, or if there
is a provider you would like see implemented, feel free to reach out either
through a [GitHub
issue](https://github.com/jetstack/cert-manager/issues/new?template=feature-request.md)
or send us a message in the #cert-manager channel on [Kubernetes
Slack](http://slack.kubernetes.io/)!

### New fields on Certificate resources

This release includes a new field `URISANs` on the `Certificate` resource. With
this, you can specify unique resource identifier URLs as subject alternative
names on your certificates. This addition unblocks development for an istio
integration where mTLS can be configured using cert-manager as the backend and
in turn opens up all cert-manager issuer types as valid certificate providers in
your istio PKI.

### Improved ACME Order controller design

Some users may have noticed issues with the 'Order' resource not automatically
detecting changes to their configure 'solvers' on their Issuer resources.

In v0.11, we've rewritten the ACME Order handling code to:

1) better handle updates to Issuers during an Order
2) improve ACME API usage - we now cache more information about the ACME Order
   process in the Kubernetes API, which allows us to act more reliably and
   without causing excessive requests to the ACME server.

### No longer generating 'temporary certificates' by default

Previously, we have issued a temporary certificate when a `Certificate` resource
targeting an ACME issuer has been created. This would later be overridden once
the real signed certificate has been issued. The reason for this behaviour was
to facilitate compatibility with ingress-gce however, many users have had trouble
with this in the past and has led to lots of confusion - namely where
applications would need restarting to take on the signed certificate rather than
the temporary.

In this release, no temporary certificates will be created unless explicitly
requested. This can be done using the annotation
`"cert-manager.io/issue-temporary-certificate": "true` on `Certifcate`
resources.

We've additionally changed the behaviour of ingress-shim to now add this new
annotation to `Certificate` resources if
`"acme.cert-manager.io/http01-edit-in-place"` is present on the Ingress
resource.

## Changelog

## Action Required

- Rename `certmanager.k8s.io` API group to `cert-manager.io` ([#2096](https://github.com/jetstack/cert-manager/pull/2096), [@munnerz](https://github.com/munnerz))
- Move Order and Challenge resources to the acme.cert-manager.io API group ([#2093](https://github.com/jetstack/cert-manager/pull/2093), [@munnerz](https://github.com/munnerz))
- Move v1alpha1 API to v1alpha2 ([#2087](https://github.com/jetstack/cert-manager/pull/2087), [@munnerz](https://github.com/munnerz))
- Allow controlling whether temporary certificates are issued using a new annotation "certmanager.k8s.io/issue-temporary-certificate"
  on Certificate resources. Previously, when an ACME certificate was requested, a temporary certificate would be issued in order
  to improve compatibility with ingress-gce. ingress-shim has been updated to automatically set this annotation on managed Certificate
  resources when using the 'edit-in-place' annotation, but users that have manually created their Certificate resources will need to
  manually add the new annotation to their Certificate resources. ([#2089](https://github.com/jetstack/cert-manager/pull/2089), [@munnerz](https://github.com/munnerz))

## Other Notable Changes

- Change the default leader election namespace to 'kube-system' instead of the same namespace as the cert-manager pod, to avoid multiple copies of cert-manager accidentally being run at once ([#2155](https://github.com/jetstack/cert-manager/pull/2155), [@munnerz](https://github.com/munnerz))
- Adds `URISANs` field to `Certificate.Spec` resource. ([#2085](https://github.com/jetstack/cert-manager/pull/2085), [@JoshVanL](https://github.com/JoshVanL))
- Move status to a CRD Subresource ([#2097](https://github.com/jetstack/cert-manager/pull/2097), [@JoshVanL](https://github.com/JoshVanL))
- Enables supporting out of tree issuers with ingress annotations ([#2105](https://github.com/jetstack/cert-manager/pull/2105), [@JoshVanL](https://github.com/JoshVanL))
- Bump Kubernetes dependencies to 1.16.0 ([#2095](https://github.com/jetstack/cert-manager/pull/2095), [@munnerz](https://github.com/munnerz))
- Adds Certificate conformance suite ([#2034](https://github.com/jetstack/cert-manager/pull/2034), [@JoshVanL](https://github.com/JoshVanL))
- Build using Go 1.13.1 ([#2114](https://github.com/jetstack/cert-manager/pull/2114), [@munnerz](https://github.com/munnerz))
- Adds Kubernetes authentication type for Vault Issue ([#2040](https://github.com/jetstack/cert-manager/pull/2040), [@JoshVanL](https://github.com/JoshVanL))
- Service account annotation support in Helm chart ([#2086](https://github.com/jetstack/cert-manager/pull/2086), [@serialx](https://github.com/serialx))
- Update AWS Go SDK to 1.24.1 to support IAM Roles for Service Accounts ([#2083](https://github.com/jetstack/cert-manager/pull/2083), [@serialx](https://github.com/serialx))
- Remove deprecated API fields and functionality ([#2082](https://github.com/jetstack/cert-manager/pull/2082), [@munnerz](https://github.com/munnerz))
- Update `hack/ci/run-dev-kind.sh` script to use the right path of cert-manager charts. ([#2074](https://github.com/jetstack/cert-manager/pull/2074), [@srvaroa](https://github.com/srvaroa))
- Simplify, improve and rewrite the acmeorders controller ([#2041](https://github.com/jetstack/cert-manager/pull/2041), [@munnerz](https://github.com/munnerz))
