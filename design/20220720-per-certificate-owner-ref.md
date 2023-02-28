# Design: Per-Certificate Secret Owner Reference

> 🌟 This design document was written by Maël Valais on 20 July 2022 in order to facilitate Denis Romanenko's feature request presented in [#5158](https://github.com/cert-manager/cert-manager/pull/5158).

- [Release Signoff Checklist](#release-signoff-checklist)
- [Summary](#summary)
- [Use-cases](#use-cases)
- [Questions](#questions)
- [Proposal](#proposal)
- [Design Details](#design-details)
  - [Test Plan](#test-plan)
  - [Graduation Criteria](#graduation-criteria)
  - [Upgrade / Downgrade Strategy](#upgrade--downgrade-strategy)
  - [Supported Versions](#supported-versions)
- [Alternatives](#alternatives)
<!-- /toc -->

## Release Signoff Checklist

This checklist contains actions which must be completed before a PR implementing this design can be merged.

- [ ] This design doc has been discussed and approved
- [ ] Test plan has been agreed upon and the tests implemented
- [ ] Feature gate status has been agreed upon (whether the new functionality will be placed behind a feature gate or not)
- [ ] Graduation criteria is in place if required (if the new functionality is placed behind a feature gate, how will it graduate between stages)
- [ ] User-facing documentation has been PR-ed against the release branch in [cert-manager/website](https://github.com/cert-manager/website)

## Summary

The flag `--enable-certificate-owner-ref` allows you to configure cert-manager to delete Secret resources when the associated Certificate is removed. 

We propose to introduce the same setting at the Certificate level so that users of the Certificate resource can decide whether the Secret resource should be removed or not.

## Use-cases

**Use-case 1: managed cert-manager installations**

[Flant](https://flant.com) manages Kubernetes clusters for their customers. The installation of cert-manager is managed by Flant. Flant uses `--enable-certificate-owner-ref=false` to lower the chance of outages of their managed components. On the other hand, customers are relying on long-lived “dev” namespaces in which they install and uninstall their applications over and over with random names. The Certificate resources are correctly removed, but the Secret resources stay and accumulate.

Source: https://github.com/deckhouse/deckhouse/pull/1601

## Questions

**Is this feature too niche?**

I think that the user of the Certificate resource should be deciding on the fate of the Secret resource, not the person operating the cert-manager installation.

**What happens when I upgrade cert-manager?**

The flag `--enable-certificate-owner-ref` will still continue to function as before. No action is needed to upgrade.

**What happens when I downgrade cert-manager?**

Downgrading requires two actions: (1) removing the new flag `--default-secret-cleanup-policy` from the Deployment, adding the corresponding `--enable-certificate-owner-ref` and (2) emptying the `cleanupPolicy` field from every Certificate in the cluster.

**Why is there a new "duplicate" flag `--default-secret-cleanup-policy` that does the same thing as `--enable-certificate-owner-ref`?**

The existing flag `--enable-certificate-owner-ref` does not match the new API (`OnDelete` and `Never`), that is why we decided to add a new flag to reflect the new API.

**Do we intend to add more to `OnDelete` and `Never`?**

No, I don't think there will be another value. The intent of these two values (as opposed to using a boolean) is to make the API more explicit, but a boolean could have done the trick.

**Will `--default-secret-cleanup-policy` be removed?**

We intend to remove `--default-secret-cleanup-policy` within 3 to 6 releases.

## Proposal

cert-manager has the ability to set the owner reference field in generated Secret resources.
The option is global, and takes the form of the flag `--enable-certificate-owner-ref` set in
the cert-manager controller Deployment resource.

Let us take an example Certificate resource:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: cert-1
  namespace: ns-1
  uid: 1e0adf8
spec:
  secretName: cert-1
```

When `--enable-certificate-owner-ref` is passed to the cert-manager controller, cert-manager,
when issuing the X.509 certificate, will create a Secret resource that looks like this:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: cert-1
  namespace: ns-1
  ownerReferences:
    - controller: true
      blockOwnerDeletion: false
      uid: 1e0adf8
      name: cert-1
      kind: Certificate
      apiVersion: cert-manager.io/v1
data:
  tls.crt: "..."
  tls.key: "..."
  ca.crt: "..."
```

The proposition is to add a new field `cleanupPolicy` to the Certificate resource:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
spec:
  secretName: cert-1
  cleanupPolicy: [OnDelete|Never] # ✨ Can be left empty.
```

The new field `cleanupPolicy` has three possible values:

1. When not set, the value set by `--default-secret-cleanup-policy` is inherited.
2. When `OnDelete`, the owner reference is always created on the Secret resource.
3. When `Never`, the owner reference is never created on the Secret resource.

> At first, the proposed field was named `certificateOwnerRef` and was a
> nullable boolean. James Munnelly reminded us that the Kubernetes API
> never uses boolean fields, and instead uses the string type with
> "meaningful values". On top of being more readable, it also makes the
> field extensible.

When changing the value of the field `cleanupPolicy` from `OnDelete` to `Never`,
the associated Secret resource immediately loses its owner reference. The user
doesn't need to wait until the certificate is renewed. Similarly, when `cleanupPolicy`
is changed from `OnDelete` to `Never`, the associated Secret resource loses its
owner reference.

Along with this new field, we propose to deprecate the flag `--enable-certificate-owner-ref`
and introduce the new flag `--default-secret-cleanup-policy`. Its values are as follows:

- When `--default-secret-cleanup-policy` is set to `Never`, the Certificate resources
  that don't have the `cleanupPolicy` field set will have their associated Secret
  resources updated (i.e., the owner reference gets removed) on the next issuance of
  the Certificate.
- When `--default-secret-cleanup-policy` is set to `OnDelete`, the Certificate resources
  that don't have the `cleanupPolicy` field set will have their associated Secret
  resources updated (i.e., the owner reference gets added) on the next issuance of
  the Certificate.
  
The effect of changing `--default-secret-cleanup-policy` from `Never` to `OnDelete`
or from `OnDelete` to `Never` is not immediate: the change requires a re-issuance
of the Certificate resources.

The default value for `--default-secret-cleanup-policy` is `Never`.

When changing the flag from `Never` to `OnDelete`, the existing Certificate resources
that don't have `cleanupPolicy` set are immediately affected, meaning that their
associated Secrets will gain a new owner reference. When changing the flag from
`OnDelete` to `Never`, the Secrets associated to Certificates that have no `cleanupPolicy`
set will see their owner reference immediately removed.

The reason we decided to deprecate `--enable-certificate-owner-ref` is because this
flag behaves differently from how the new `cleanupPolicy` behaves:

- When `--enable-certificate-owner-ref` is not passed (or is set to false), the existing
  Secret resources that have an owner reference are not changed even after a re-issuance.
  With `--default-secret-cleanup-policy` and given that `cleanupPolicy` is not set, the
  behavior is slightly different: unlike with the old flag, the existing Secret resources
  will have their owner references removed.
- When `--enable-certificate-owner-ref` is set to true, the behavior is the same as
  when `--default-secret-cleanup-policy` is set to `OnDelete` and `cleanupPolicy` is not
  set.  

The deprecated flag `--enable-certificate-owner-ref` keeps precendence over the new flag
in order to keep backwards compatibility.

When upgrading to the new flag, users can refer to the following table:

| If... | then they should replace it with... |
|-----|-----|
| `--enable-certificate-owner-ref` not passed to the controller | No change needed |
| `--enable-certificate-owner-ref=false` | Replace with `--default-secret-cleanup-policy=Never` |
| `--enable-certificate-owner-ref=true` | Replace with `--default-secret-cleanup-policy=OnDelete` |

## Design Details

cert-manager would have to change in a few places.

**Mutating webhook**

We propose to have no "value defaulting" for `cleanupPolicy` because the
"empty" value has a meaning for us: when `cleanupPolicy` is empty, the
presence or not of the flag `--enable-certificate-owner-ref` takes over.
To give more context, some other resources, such as the Pod resource,
will mutate the object when the value is "empty", for example the
`imagePullPolicy` value will default to `IfNotPresent`.

**PostIssuancePolicyChain**

In ([policies.go#L95](https://github.com/cert-manager/cert-manager/blob/b78af1ef867f8776715cae3dd6a8b83049c4d9b2/internal/controller/certificates/policies/policies.go#L95-L104)), cert-manager does a few sanity checks right after the issuer (either an
internal or an external issue) has filled the CertificateRequest's status
with the signed certificate.

One of the checks is called
[`SecretOwnerReferenceValueMismatch`](https://github.com/cert-manager/cert-manager/blob/b78af1ef867f8776715cae3dd6a8b83049c4d9b2/internal/controller/certificates/policies/checks.go#L511)
and checks that the owner reference on the Secret resource matches the one
on the Certificate resource.

### Test Plan

- Unit tests for the changes in the secret manager controller.
- Integration tests (either fake client or envtest) checking various API behaviours.

### Graduation Criteria

We propose to release this feature in GA immediately and skip the "beta"
phase that consists of gathering user feedback, since this feature has a
low user-facing surface. We think that we will be able to take a good
decision (e.g., the name of the new field, whether it is a boolean or a
string, and which values the field can take) while developing the feature
in the PR.

We don't think this feature needs to be [feature gated][feature gate].

[feature gate]: https://git.k8s.io/community/contributors/devel/sig-architecture/feature-gates.md

### Upgrade / Downgrade Strategy

Upgrading from a version without this feature to a version with this
feature won't be breaking.

Downgrading, however, will be a breaking change, since a new field will be
introduced.

### Supported Versions

This feature will be supported in all the versions of Kubernetes that are supported by cert-manager.

## Alternatives

**CSI driver**

It is possible to use the
[`csi-driver`](https://github.com/cert-manager/csi-driver) to circumvent
the problem of "too many ephemeral Secret resources stored in etcd". Using
the CSI driver, no Secret resource is created, alleviating the issue. Since Flant offers its customers the capability to use Certificate resources,
and wants to keep supporting the Certificate type, switching from Certificate
resources to the CSI driver isn't an option.

**Ad-hoc tool to delete orphaned Secrets**

It would be possible to develop a custom tool that removes Secret resources that aren’t referenced by any Certificate resource, possibly using an annotation.

**Multiple installations of cert-manager**

Another solution would be to install cert-manager twice: once with `--enable-certificate-owner-ref=true`, and the other without. But running multiple instances of cert-manager is not supported.

**Removal of the ephemeral dev namespace**

Flant reported that developers are using long-term dev namespaces, meaning that they can't rely on the removal of the dev namespace in order to have the leftover Secrets removed.
