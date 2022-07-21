# Design: Per-Certificate Secret Owner Reference

> 🌟 This design document was written by Maël Valais on 20 July 2022 in order to facilitate Denis Romanenko's feature request presented in [#5158](https://github.com/cert-manager/cert-manager/pull/5158).

<!--
This template is adapted from Kubernetes Enchancements KEP template https://raw.githubusercontent.com/kubernetes/enhancements/a86942e8ba802d0035ec7d4a9c992f03bca7dce9/keps/NNNN-kep-template/README.md
-->

# CHANGEME: Title

<!-- toc -->

- [Release Signoff Checklist](#release-signoff-checklist)
- [Summary](#summary)
- [Motivation](#motivation)
  - [Goals](#goals)
  - [Non-Goals](#non-goals)
- [Proposal](#proposal)
  - [User Stories (Optional)](#user-stories-optional)
    - [Story 1](#story-1)
    - [Story 2](#story-2)
  - [Notes/Constraints/Caveats (Optional)](#notesconstraintscaveats-optional)
  - [Risks and Mitigations](#risks-and-mitigations)
- [Design Details](#design-details)
  - [Test Plan](#test-plan)
  - [Graduation Criteria](#graduation-criteria)
  - [Upgrade / Downgrade Strategy](#upgrade--downgrade-strategy)
  - [Supported Versions](#supported-versions)
- [Production Readiness](#production-readiness)
- [Drawbacks](#drawbacks)
- [Alternatives](#alternatives)
<!-- /toc -->

## Release Signoff Checklist

This checklist contains actions which must be completed before a PR implementing this design can be merged.

- [ ] This design doc has been discussed and approved
- [ ] Test plan has been agreed upon and the tests implemented
- [ ] Feature gate status has been agreed upon (whether the new functionality will be placed behind a feature gate or not)
- [ ] Graduation criteria is in place if required (if the new functionality is placed behind a feature gate, how will it graduate between stages)
- [ ] User-facing documentation has been PR-ed against the release branch in [cert-manager/website]

## Summary

<!--
This section is important for producing high-quality, user-focused
documentation such as release notes.

A good summary is probably around a paragraph in length.

[documentation style guide]: https://github.com/kubernetes/community/blob/master/contributors/guide/style-guide.md
-->

## Motivation

<!--
This section is for explicitly listing the motivation, goals, and non-goals of
the proposed enhancement.  Describe why the change is important and the benefits to users. The
motivation section can optionally provide links to
demonstrate the interest in this functionality amongst the community.
-->

### Goals

<!--
List specific goals. What is this proposal trying to achieve? How will we
know that this has succeeded?
-->

### Non-Goals

<!--
What is out of scope for this proposal? Listing non-goals helps to focus discussion
and make progress.
-->

## Proposal

<!--
This is where we get down to the specifics of what the proposal actually is.
What is the desired outcome and how do we measure success?
This should have enough detail that reviewers can understand exactly what
you're proposing, but should not include things like API designs or
implementation- those should go into "Design Details" below.
-->

### User Stories (Optional)

<!--
Detail the things that people will be able to do if this proposal gets implemented.
Include as much detail as possible so that people can understand the "how" of
the system. The goal here is to make this feel real for users without getting
bogged down.
-->

#### Story 1

#### Story 2

### Notes/Constraints/Caveats (Optional)

<!--
What are the caveats to the proposal?
What are some important details that didn't come across above?
Go into as much detail as necessary here.
This might be a good place to talk about core concepts and how they relate.
-->

### Risks and Mitigations

<!--
What are the risks of this proposal, and how do we mitigate? Think broadly.
For example, consider both security and how this will impact the larger
Kubernetes/PKI ecosystem.

-->

## Design Details

<!--
This section should contain enough information that the specifics of your
change are understandable. This may include API specs (though not always
required) or even code snippets. If there's any ambiguity about HOW your
proposal will be implemented, this is the place to discuss them.
-->

### Test Plan

<!---
Describe how the new functionality will be tested (unit tests, integration tests (if applicable), e2e tests)
-->

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

This feature will be supported in all the versions of Kubernetes that are
supported by cert-manager.

## Production Readiness

<!--
This section should confirm that the feature can be safely operated in production environment and can be disabled or rolled back in case it is found to increase failures.
-->

### How can this feature be enabled / disabled for an existing cert-manager installation?

<!--

Can the feature be disabled after having been enabled?

Consider whether any additional steps will need to be taken to start/stop using this feature, i.e change existing resources that have had new field added for the feature before disabling it.


Do the test cases cover both the feature being enabled and it being disabled (where relevant)?

-->

### Does this feature depend on any specific services running in the cluster?

No.

### Will enabling / using this feature result in new API calls (i.e to Kubernetes apiserver or external services)?

No.

### Will enabling / using this feature result in increasing size or count of the existing API objects?

No.

### Will enabling / using this feature result in significant increase of resource usage? (CPU, RAM...)

No.

## Drawbacks

## Alternatives

<!--
What other approaches did you consider, and why did you rule them out? These do
not need to be as detailed as the proposal, but should include enough
information to express the idea and why it was not acceptable.
-->

---

cert-manager has the ability to set the owner reference field in generated Secret resources. The option is global, and takes the form of the flag `--enable-certificate-owner-ref` set in the cert-manager controller Deployment resource.

Let us take an example of Certificate resource:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: cert-1
  namespace: ns-1
  uid: 1e0adf8
spec:
  secretRef: cert-1
```

When `--enable-certificate-owner-ref` is passed to the cert-manager controller, when issuing the X.509 certificate, cert-manager will create a Secret resource that looks like this:

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

The proposition is to add a new field `certificateOwnerRef` to the Certificate resource:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
spec:
  secretRef: cert-1
  certificateOwnerRef: true # ✨
```

It has three possible values:

1. When "empty", the behavior will default to not creating an owner reference on the Secret resource, unless `--enable-certificate-owner-ref` is passed.
2. When `true`, the default behavior as described in the "empty" case is overridden and the owner reference is always created on the Secret resource.
3. When `false`, the default behavior as described in the "empty" case is overridden and the owner reference is never created on the Secret resource.

> **⁉️ Question:** the field name `certificateOwnerRef` does not reflect the behavior that it aims to enable. A more appropriate, less confusing name could be found, e.g., `deleteSecretUponDeletion`.

## Use-cases

Flant manages certificates for users, and has hit a Kubernetes apiserver limitation where too many left-over Secret resources were slowing the apiserver down. This issue has happened because Certificate resources are created using auto-generated names, and Certificate resources are often deleted shortly after being created.

## Questions

-
- I assume we are going to add this to the `postIssuancePolicyChain`? I don't see that in the PR currently. Can we add a note that we are going to do this and include it in testing.
- What happens when I upgrade or downgrade cert-manager?
- Has the [`csi-driver`](https://github.com/cert-manager/csi-driver) been considered? If so, why is that not a good enough alternative to the use case?
