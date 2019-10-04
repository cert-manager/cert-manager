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
| Order              | `certmanager.k8s.io/v1alpha1` | `acme.cert-manager.io/v1alpha2` |
| Challenge          | `certmanager.k8s.io/v1alpha1` | `acme.cert-manager.io/v1alpha2` |
| CertificateRequest | `certmanager.k8s.io/v1alpha1` | `acme.cert-manager.io/v1alpha2` |

You must also make sure to update all references to cert-manager in annotations to their
new prefix:

| Annotation | Affected resources | New annotation |
|------------|--------------------|----------------|

## Contributors

This release has seen code contributions from a number of people in the
community :tada:

TODO: add list

As always, a big thank you to those opening issues, replying to issues and
helping out in the Slack channel. As well as working in other projects to help
users secure services running on Kubernetes.

## Action required

## Notable changes

### Renamed API group

### Release v1alpha2

### Deprecated old config fields

### New CertificateRequest resource type

With this release comes the graduation of the `CertificateRequest` resource from
alpha to beta. This means that when requesting certificates using the
`Certificate` resource the `CertificateRequest` resource will be used as the
default and only way to honour the request. The addition of this resource
introduces the ability for much greater extension points to cert-manager,
notably out-of-tree issuers, istio integrations, and experimental tooling such
as a CSI driver. You can read more about the motivation and design of this
resource in the [enhancement
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
or send us a message in the #cert-mangager channel on [Kubernetes
Slack](http://slack.kubernetes.io/)!

### New fields on Certificate resources

This release includes a new field `URISANs` on the `Certificate` resource. With
this, you can specify unique resource identifier URLs as subject alternative
names on your certificates. This addition unblocks development for an istio
integration where mTLS can be configured using cert-manager as the backend and
in turn opens up its providers to be all that cert-manger supports.

### Improved ACME Order controller design

### No longer generating 'temporary certificates' by default

Previously, we have issued a temporary certificate when a `Certificate` resource
targeting an ACME issuer has been created. This would later be overridden once
the real signed certificate has been issued. The reason for this behaviour was
to facilitate compatibility with ingress-gce however many users have had trouble
with in the past and has led to lots of confusion.

In this release, no temporary certificate will be created unless explicitly
requested. This can be done using the annotation
`"cert-manager.io/issue-temporary-certificate": "true` on `Certifcate`
resources, or using the `"acme.cert-manager.io/http01-edit-in-place"` annotation
on ingress resources that will in turn write the temporary certificate
annotation onto the generated `Certificate` resource.

## Changelog
