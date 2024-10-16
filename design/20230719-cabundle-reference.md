---
title: Certificate Request CRD
authors:
  - "@AppalaKarthik"
  - "@sankalp-at-github"
creation-date: 2023-07-19
last-updated: 2023-07-19
#status: implementable
---

# Design: Certficate Authority Bundle Reference Using Secrets, Configmaps


<!-- toc -->
- [Problem Statement](#problem-statement)
- [Summary](#summary)
- [Motivation](#motivation)
  - [Goals](#goals)
  - [Non-Goals](#non-goals)
- [Proposal](#proposal)
- [Design Details](#design-details)
  - [Graduation Criteria](#graduation-criteria)
- [Drawbacks](#drawbacks)
- [Alternatives](#alternatives)
<!-- /toc -->

## Problem Statement

In Issuer/ClusterIssuer resources caBundle field must be specified as a base64 encoded string.

```
spec:
  venafi:
    tpp:
      caBundle: <B64_ENCODED_STRING>
      credentialsRef:
        name: tpp-token
      url: https://my-server.com/vedsdk/
    zone: Certificates\public
```

This becomes a configuration management issue when many issuers are there in a cluster using the same TPP endpoint, the same CA information has to be copied in all the issuers and there can be mistakes made as this would be manual.

## Summary

Ability to reference caBundle from the contents of secrets, configmap.

## Motivation
The proposed change would encourage the way caBundle is referenced in kubernetes native way.

### Goals

To be able to refer caBundle using secret.
To be able to refer caBundle using configmap.

### Non-Goals

To include reference using resources other than mentioned.

## Proposal

Enable reading of cabundle from native kubernetes objects like secrets and configmaps.

## Design Details

Add secrets and configMaps as optional fields to the spec which can be used to refer a key to find the caBundle. Below is the example for venafi issuer.

```
spec:
  venafi:
    tpp:
      caBundle: <B64_ENCODED_STRING>
      caBundleSecretRef:
        name: <>
        key: <>
      caBundleConfigMapRef:
        name: <>
        key: <>
      credentialsRef:
        name: tpp-token
      url: https://my-server.com/vedsdk/
    zone: Certificates\public
```


### Graduation Criteria

Placing the `caBundleSecetRef` and `caBundleConfigMapRef` specification functionality behind a feature gate should be required.
Placing this functionality behind a feature gate would allow the cert-manager
authors gain confidence about its correctness, and ensure there are no
regressions in the stability of controller reconciliation.

### How can this feature be enabled / disabled for an existing cert-manager installation?

By using a feature gate `--enablecabundleref`

### Will enabling / using this feature result in new API calls (i.e to Kubernetes apiserver or external services)?

This would make calls to fetch the key of secret/configmap. 

## Drawbacks

Has keys for each individual reference object, instead of single key that has details of the object that can be referenced.

## Alternatives

In v2 we can implement the same using single key that can refer different type of objects
```
spec:
  venafi:
    tpp:
      caBundleRef: # A new key could be either or with the existing `caBundle`
        type: configMap  # configMap | secret | bundle
        name:  tpp-trust-bundle
        key: ca-certificates.crt
      credentialsRef:
        name: tpp-token
      url: https://my-server.com/vedsdk/
    zone: Certificates\public
```
