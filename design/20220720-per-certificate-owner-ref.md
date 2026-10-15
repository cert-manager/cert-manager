# Design: Per-Certificate Secret Owner Reference

> 🌟 This design document was originally written by Maël Valais on 20 July 2022 in order to facilitate Denis Romanenko's feature request presented in [#5158](https://github.com/cert-manager/cert-manager/pull/5158).

- [Release Signoff Checklist](#release-signoff-checklist)
- [Summary](#summary)
- [Stories](#stories)
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
- [ ] User-facing documentation has been PR-ed against the release branch in [cert-manager/website][]

[cert-manager/website]: https://github.com/cert-manager/website

## Summary

The existing flag `--enable-certificate-owner-ref` allows you to configure cert-manager to delete Secret resources when the associated Certificate is removed.

We propose to introduce a new field, `deletionPolicy`, on the Certificate resource so that users can decide whether or not the Secret resource should be removed.

And since the semantics of `--enable-certificate-owner-ref` are different from the semantics of `deletionPolicy`, we propose to deprecate `--enable-certificate-owner-ref` and introduce a new flag, `--default-secret-deletion-policy`, that will set the default value of `deletionPolicy` when it is not set.

## Stories

**Story 1: managed cert-manager installations and "dev" clusters**

[Flant](https://flant.com) manages large multi-tenant Kubernetes clusters. The installation of cert-manager is managed by Flant, and customers cannot edit cert-manager's configuration. Customers have access to a "prod" cluster and a "dev" cluster. On both clusters, Flant uses `--enable-certificate-owner-ref=false` to lower the chance of outages of their managed components such as the ingress controller.

On the "dev" cluster, customers are given long-lived namespaces in which they install and uninstall their applications over and over with random names, including Certificate resources. With hundreds of customers deploying approximately ten times a day to the "dev" cluster, the Secret resources that are left over by cert-manager accumulate (around 10,000 Secret resources after a few months), and the Kubernetes API becomes slow, with people having to wait for 10 seconds to list the secrets in a given namespace.

To solve this problem, Flant aims at using `deletionPolicy: Orphan` on the certificates used for their managed components and use `--default-secret-deletion-policy=Delete` for the rest of the Certificates. Users won't have to change their Certificate resources.

On the "prod" cluster, Flant recommends customers to keep the Secret resource on removal to lower the risk of outages. Flant aims to use `--default-secret-deletion-policy=Orphan` for the "prod" cluster and also aims to document the reason for this difference between "prod" and "dev".

## Questions

**Is this feature too niche?**

I think that the user of the Certificate resource should be deciding on the fate of the Secret resource, not the person operating the cert-manager installation.

**Why is there a new "duplicate" flag `--default-secret-deletion-policy` that does the same thing as `--enable-certificate-owner-ref`?**

The existing flag `--enable-certificate-owner-ref` does not match the new API (`Delete` and `Orphan`), that is why we decided to add a new flag to reflect the new API.

**Do we intend to add more to `Delete` and `Orphan`?**

No, I don't think there will be another value. The intent of these two values (as opposed to using a boolean) is to make the API more explicit, but a boolean could have done the trick.

**Will `--enable-certificate-owner-ref` be removed?**

We intend to remove `--enable-certificate-owner-ref` within 3 to 6 releases. Or maybe never since the maintenance burden won't be high. We will strongly recommend users to switch to `--default-secret-deletion-policy`.

**Why did we choose `deletionPolicy` over `cleanupPolicy`?**

During the design process, we initially considered using `cleanupPolicy` with
values `[OnDelete|Never]`, but ultimately chose `deletionPolicy` with values
`[Delete|Orphan]` because it is slightly more declarative, and a bit more
familiar to the ecosystem ([Crossplane](https://docs.crossplane.io/v1.20/concepts/managed-resources/#deletionpolicy),
[FluxCD](https://fluxcd.io/flux/components/kustomize/kustomizations/#deletion-policy), and
[External Secrets Operator](https://external-secrets.io/latest/guides/ownership-deletion-policy/#deletion-policy)
all use `deletionPolicy`).

Note that while `deletionPolicy` has a slightly different meaning in Crossplane
(where it works more like finalizers), in cert-manager it simply controls
whether the secret gets deleted along with the certificate without complex
coordination mechanisms.

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
      blockOwnerDeletion: true
      uid: 1e0adf8
      name: cert-1
      kind: Certificate
      apiVersion: cert-manager.io/v1
data:
  tls.crt: "..."
  tls.key: "..."
  ca.crt: "..."
```

The proposition is to add a new field `deletionPolicy` to the Certificate resource:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
spec:
  secretName: cert-1
  deletionPolicy: [Delete|Orphan] # ✨ Can be left empty.
```

The new field `deletionPolicy` has three possible values:

1. When not set, the value set by `--default-secret-deletion-policy` is inherited.
2. When `Delete`, the owner reference is always created on the Secret resource.
3. When `Orphan`, the owner reference is never created on the Secret resource.

> At first, the proposed field was named `certificateOwnerRef` and was a
> nullable boolean. James Munnelly reminded us that the Kubernetes API
> never uses boolean fields, and instead uses the string type with
> "meaningful values". On top of being more readable, it also makes the
> field extensible.

When changing the value of the field `deletionPolicy` from `Delete` to `Orphan`,
the associated Secret resource immediately loses its owner reference. The user
doesn't need to wait until the certificate is renewed.
Along with this new field, we propose to deprecate the flag `--enable-certificate-owner-ref`
and introduce the new flag `--default-secret-deletion-policy`. Its values are as follows:

- When `--default-secret-deletion-policy` is set to `Orphan`, the Certificate resources
  that don't have the `deletionPolicy` field set have the owner reference removed from
  their associated Secret resources.
- When `--default-secret-deletion-policy` is set to `Delete`, the Certificate resources
  that don't have the `deletionPolicy` field set have the owner reference added to
  their associated Secret resources.

Changing the flag takes effect the next time each Certificate is reconciled, which
happens as soon as the controller restarts with the new value. No re-issuance is
needed: the owner reference is part of the Secret metadata that the post-issuance
checks keep in sync (see [Design Details](#design-details)). The same is true for
the `deletionPolicy` field itself.

The default value for `--default-secret-deletion-policy` is `Orphan`.

We deprecate `--enable-certificate-owner-ref` because its boolean shape does not
match the new API, not because the two flags behave differently:

- When `--enable-certificate-owner-ref` is not passed (or is set to false), the
  owner references that cert-manager itself added to existing Secret resources
  are removed on the next reconcile, and owner references added by anything else
  are left untouched. This has been the behavior since cert-manager 1.8
  ([#4888](https://github.com/cert-manager/cert-manager/pull/4888)), and it is the
  same as `--default-secret-deletion-policy=Orphan` with `deletionPolicy` unset.
- When `--enable-certificate-owner-ref` is set to true, the behavior is the same
  as when `--default-secret-deletion-policy` is set to `Delete` and
  `deletionPolicy` is not set.

`--enable-certificate-owner-ref=true` keeps precedence over the new flag in order to
keep backwards compatibility. `--enable-certificate-owner-ref=false` is the same as
not passing the flag, as it is today.

When upgrading to the new flag, users can refer to the following table:

| If... | then they should replace it with... |
| ----- | ----------------------------------- |
| `--enable-certificate-owner-ref` not passed to the controller | No change needed |
| `--enable-certificate-owner-ref=false` | Replace with `--default-secret-deletion-policy=Orphan` |
| `--enable-certificate-owner-ref=true` | Replace with `--default-secret-deletion-policy=Delete` |

## Design Details

cert-manager would have to change in a few places.

**Mutating webhook**

We propose to have no "value defaulting" for `deletionPolicy` because the
"empty" value has a meaning for us: when `deletionPolicy` is empty, the
controller-wide default takes over (`--default-secret-deletion-policy`, or
`Delete` when `--enable-certificate-owner-ref=true` is passed). To give more
context, some other resources, such as the Pod resource, will mutate the object
when the value is "empty", for example the `imagePullPolicy` value will default
to `IfNotPresent`.

**PostIssuancePolicyChain**

In [policies.go](https://github.com/cert-manager/cert-manager/blob/master/internal/controller/certificates/policies/policies.go),
cert-manager runs a few sanity checks on the Secret metadata whenever a
Certificate is reconciled outside of an issuance. Two of them,
`SecretOwnerReferenceMismatch` and `SecretOwnerReferenceManagedFieldMismatch`,
check that the owner reference on the Secret resource matches what the
Certificate expects: present when the effective deletion policy is `Delete`,
absent otherwise. A mismatch makes the controller re-apply the Secret metadata
without re-issuing the certificate, which is what makes changes to
`deletionPolicy` and to the default flag take effect immediately.

The owner reference is only ever added to the Secret that the Certificate owns,
that is the Secret whose `cert-manager.io/certificate-name` annotation names the
Certificate, or that carries no such annotation yet. A Certificate whose
`secretName` points at a Secret owned by another Certificate never gets an owner
reference on it, whatever its `deletionPolicy` says, so it cannot cause that
Secret to be garbage collected. Two Certificates sharing one `secretName` remain
unsupported.

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

[feature gate]: https://cert-manager.io/docs/installation/featureflags/#list-of-current-feature-gates

### Upgrade / Downgrade Strategy

Upgrading from a version without this feature to a version with this
feature won't require intervention.

Downgrading requires manual intervention: removing the new flag
`--default-secret-deletion-policy` from the Deployment, adding the corresponding
`--enable-certificate-owner-ref` and emptying the `deletionPolicy` field from
every Certificate in the cluster.

### Supported Versions

This feature will be supported in all the versions of Kubernetes that are supported by cert-manager.

## Alternatives

**CSI driver**

It is possible to use a
[`csi-driver`](https://github.com/cert-manager/csi-driver) to circumvent
the problem of "too many ephemeral Secret resources stored in etcd". Using
a CSI driver, no Secret resource is created, alleviating the issue. Since Flant offers its customers the capability to use Certificate resources,
and wants to keep supporting the Certificate type, switching from Certificate
resources to a CSI driver isn't an option.

**Ad-hoc tool to delete orphaned Secrets**

It would be possible to develop a custom tool that removes Secret resources that aren’t referenced by any Certificate resource, possibly using an annotation.

**Multiple installations of cert-manager**

Another solution would be to install cert-manager twice: once with `--enable-certificate-owner-ref=true`, and the other without. But running multiple instances of cert-manager is not supported.

**Removal of the ephemeral dev namespace**

Flant reported that developers are using long-term dev namespaces, meaning that they can't rely on the removal of the dev namespace in order to have the leftover Secrets removed.
