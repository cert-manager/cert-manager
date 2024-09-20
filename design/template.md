<!--
This template is adapted from Kubernetes Enhancements KEP template https://raw.githubusercontent.com/kubernetes/enhancements/a86942e8ba802d0035ec7d4a9c992f03bca7dce9/keps/NNNN-kep-template/README.md
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
implementation - those should go into "Design Details" below.
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

<!--

Describe whether the proposed functionality will be feature gated and why (or why not).

Define graduation milestones and criteria if it should be feature-gated.

Feature maturity is defined using stages alpha, beta, GA.
Feature-gated functionality starts off at alpha and graduates through stages following the defined graduation criteria.
A feature that is in alpha or beta must be opt-in.

Example graduation criteria:

Alpha:

- Feature implemented behind a feature flag
- It is clearly defined which Kubernetes versions this feature supports
- CI tests pass for all supported Kubernetes versions

Beta:

- Gather user feedback

GA:

- N examples of real-world usage
- N installs
- Allowing time for feedback
- Works on all versions of Kubernetes supported by the version of cert-manager at which this feature becomes GA

References in Kubernetes documentation:

[feature gate]: https://git.k8s.io/community/contributors/devel/sig-architecture/feature-gates.md
[maturity-levels]: https://git.k8s.io/community/contributors/devel/sig-architecture/api_changes.md#alpha-beta-and-stable-versions
-->

### Upgrade / Downgrade Strategy

<!--
Will this feature affect upgrade/downgrade of cert-manager?
-->

### Supported Versions

<!--
What versions of Kubernetes (and other external services if applicable) will this feature support?
-->

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

<!--
For example, are external dependencies such as ingress controllers, third party CRDs etc required for this feature to function?
-->

### Will enabling / using this feature result in new API calls (i.e to Kubernetes apiserver or external services)?
<!--
We should ensure that cert-manager does not hammer any external services with excessive calls.
Consider whether there will be sufficient backoff if any external calls fail and need to be retried.
-->

### Will enabling / using this feature result in increasing size or count of the existing API objects?

<!--
For example, will cert-manager `CustomResourceDefinition`s increase in size, will there be more `Secret`s or `CertificateRequest`s created?
-->

### Will enabling / using this feature result in significant increase of resource usage? (CPU, RAM...)

<!--
For example, will implementing this feature result in more objects being cache thus increasing memory consumption?
-->

## Drawbacks

<!--
Why should this proposal _not_ be implemented?
-->

## Alternatives

<!--
What other approaches did you consider, and why did you rule them out? These do
not need to be as detailed as the proposal, but should include enough
information to express the idea and why it was not acceptable.
-->
