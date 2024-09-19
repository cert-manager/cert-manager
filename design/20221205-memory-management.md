# Memory consumption reduction

<!-- toc -->
- [Release Signoff Checklist](#release-signoff-checklist)
- [Summary](#summary)
- [Motivation](#motivation)
  - [Goals](#goals)
  - [Non-Goals](#non-goals)
  - [Nice-to-Have](#nice-to-have)
  - [Must-not](#must-not)
- [Proposal](#proposal)
  - [Background](#background)
  - [User Stories](#user-stories)
    - [Story 1](#story-1)
  - [Risks and Mitigations](#risks-and-mitigations)
- [Design Details](#design-details)
  - [Implementation](#implementation)
  - [Metrics](#metrics)
    - [cluster-with-many-cert-manager-unrelated-secrets](#cluster-with-large-cert-manager-unrelated-secrets)
      - [cert-manager-v1-11](#cert-manager-v111)
      - [partial metadata prototype](#partial-metadata-prototype)
    - [issuance-of-a-large-number-of-certificates](#issuance-of-a-large-number-of-certificates)
      - [latest cert-manager](#latest-cert-manager)
      - [partial metadata prototype](#partial-metadata)
  - [Pros](#pros)
  - [Cons](#cons)
  - [Test Plan](#test-plan)
  - [Graduation Criteria](#graduation-criteria)
  - [Upgrade / Downgrade Strategy](#upgrade--downgrade-strategy)
  - [Supported Versions](#supported-versions)
  - [Notes](#notes)
    - [Current state](#current-state)
      - [Secrets for Certificates](#secrets-for-certificates)
      - [Secrets for issuers](#secrets-for-clusterissuers)
    - [Upstream mechanisms](#upstream-mechanisms)
      - [Filtering](#filtering)
      - [Partial object metadata](#partial-object-metadata)
      - [Transform functions](#transform-functions)
- [Production Readiness](#production-readiness)
- [Drawbacks](#drawbacks)
- [Alternatives](#alternatives)
  - [Transform functions](#use-transform-functions-to-remove-data-for-non-labelled-secrets-before-adding-them-to-informers-cache)
  - [PartialMetadata only](#use-partialmetadata-only)
  - [Paging limit](#use-paging-to-limit-the-memory-spike-when-controller-starts-up)
  - [Filter watched Secrets](#filter-the-secrets-to-watch-with-a-label)
  - [Custom filter](#allow-users-to-pass-a-custom-filter)
  - [Standalone typed cache](#use-a-standalone-typed-cache-populated-from-different-sources)
<!-- /toc -->

## Release Signoff Checklist

This checklist contains actions which must be completed before a PR implementing this design can be merged.


- [ ] This design doc has been discussed and approved
- [ ] Test plan has been agreed upon and the tests implemented
- [ ] Feature gate status has been agreed upon (whether the new functionality will be placed behind a feature gate or not)
- [ ] Graduation criteria is in place if required (if the new functionality is placed behind a feature gate, how will it graduate between stages)
- [ ] User-facing documentation has been PR-ed against the release branch in [cert-manager/website]


## Summary

[cert-manager's controller](https://cert-manager.io/docs/cli/controller/) watches and caches all `Secret` resources in cluster.
This causes high memory consumption for cert-manager controller pods in clusters which contain many large `Secret`s such as Helm release `Secret`s.

This proposal suggests a mechanism how to avoid caching cert-manager unrelated `Secret` data.

## Motivation

### Goals

- make cert-manager installation more reliable (no OOM kills caused by events against large cert-manager unrelated `Secret`s)

- reduce cost of running cert-manager installation (need to allocate less memory)

- make it easier to predict how much memory needs to be allocated to cert-manager controller

### Non-Goals

- memory improvements related to caching objects other than `Secret`s

- memory improvements related to caching cert-manager related `Secret`s

- rewrite cert-manager controllers as controller-runtime controllers

#### Nice to have

- have this mechanism eventually be on by default (users shouldn't need to have to discover a feature flag to not cache unrelated `Secret`s)

- use the same mechanism to improve memory consumption by cainjector. This proposal focuses on controller only as it is the more complex part however we need to fix this problem in cainjector too and it would be nice to be consistent

  > 📖 Update: In [#7161: Reduce memory usage by only caching the metadata of Secret resources](https://github.com/cert-manager/cert-manager/pull/716199)
  > we addressed the high startup memory usage of cainjector with metadata-only caching features of controller-runtime.
  > We did not use the split cache design that was implemented for the
  > controller, and this contradicts the goal above: "use the same mechanism to
  > improve memory consumption by cainjector ... to be consistent".
  > Why? Because the split cache mechanism is overkill for cainjector.
  > The split cache design is designed to reduce memory use **and** minimize the
  > ongoing load on the K8S API server; which is appropriate for the controller
  > because it has multiple controller loops each reading Secret resources every
  > time a Certificate is reconciled.
  > It is not necessary for cainjector, because cainjector reads relatively few
  > Secret resources, infrequently; `cainjector` only reads Secrets having the
  > `cert-manager.io/allow-direct-injection` or Secrets created from
  > Certificates having that annotation. And it only reads the Secret data once
  > during while reconciling the target resource.

#### Must not

- make our controllers less reliable (i.e by introducing edge cases where a cert-manager related event does not trigger a reconcile). Given the wide usage of cert-manager and the various different usage scenarios, any such edge case would be likely to occur for some users

- make our issuance flow harder to reason about or less intuitive

- break any existing installation/issuance flows (i.e where some resources, such as issuer `Secret`s are created after the issuer and the flow relies on the `Secret` creation event to trigger the issuer reconcile)

- significantly slow down issuance

## Proposal

The current `Secret`s informer will have a filter to watch only `Secret`s that are known to be cert-manager related (using a label selector).
A new informer will be added that knows how to watch `PartialMetadata` for `Secret`s. This informer will have a filter to watch only `Secret`s that don't have a known cert-manager label. This will ensure that for each `Secret` either full data is cached in the typed informer's cache or metadata only is cached in metadata informer's cache.
Cert-manager will label `cert.spec.secretName` and temporary private key `Secret`s. These are the most frequently accessed `Secret` resources. Users could also optionally apply the label to other `Secret`s that cert-manager controller needs to watch to ensure that those get cached.

This will reduce the excessive memory consumption caused by caching full contents of cert-manager unrelated `Secret`s whilst still ensuring that most of the `Secret`s that cert-manager needs frequently are retrieved from cache and cert-manager relevant events are not missed.

### Background

The excessive memory consumption comes from the amount of cluster objects being stored in the [shared informers caches](https://github.com/kubernetes/client-go/blob/v12.0.0/tools/cache/shared_informer.go#L47-L58), mostly from `Secret`s.
cert-manager uses client-go's [informer factory](https://github.com/kubernetes/client-go/tree/master/informers) to create informers for core types. We have [auto-generated informers](https://github.com/cert-manager/cert-manager/tree/v1.10.1/pkg/client/informers/externalversions) for cert-manager.io types. These informers do not directly expose the cache or the [ListerWatcher](https://github.com/kubernetes/client-go/blob/v12.0.0/tools/cache/shared_informer.go#L188) which is responsible for listing and setting up watches for objects.
When cert-manager controller starts, all `Secret`s are listed and processed, which causes a memory spike.
When there is change to `Secret`s, the cache gets resynced, which can also cause a memory spike.
For the rest of the time, `Secret`s remain in controller's cache.

cert-manager needs to watch all `Secret`s in the cluster because some user created `Secret`s, for example issuer credentials, might not be labelled and we do want to trigger issuer reconciles when those `Secret`s change because:

- in cases where an issuer gets created and is unready because its credential has not yet been applied/is incorrect and a user at some point applies or corrects it, it is a better user experience that the creation/update event triggers an immediate reconcile instead of the user having to wait for the failed issuer to be reconciled again after the backoff period ([max wait can be 5 minutes for the issuers workqueue](https://github.com/cert-manager/cert-manager/blob/v1.10.1/pkg/controller/issuers/controller.go#L70))

- in cases where an issuer credential change should trigger issuer status update (i.e Venafi credentials `Secret` gets updated with incorrect credentials) it is a better user experience if the update event caused a reconcile and the issuer status would be changed to unready instead of failing at issuance time

- in some cases a missing `Secret` does not cause issuer reconcile ([such as a missing ACME EAB key where we explicitly rely on `Secret` events to retry issuer setup](https://github.com/cert-manager/cert-manager/blob/v1.10.1/pkg/issuer/acme/setup.go#L228)). In this case, it is more efficient as well as a better user experience to reconcile on `Secret` creation event as that way we avoid wasting CPU cycles whilst waiting for the user to create the `Secret` and when the `Secret` does get created, the issuer will be reconciled immediately.

The caching mechanism is required for ensuring quick issuance and not taking too much of kube apiserver's resources. `Secret`s with the issued X.509 certificates and with temporary private keys get retrieved a number of times during issuance and all the control loops involved in issuance need full `Secret` data. Currently the `Secret`s are retrieved from informers cache. Retrieving them from kube apiserver would mean a large number of additional calls to kube apiserver, which is undesirable. The default cert-manager installation uses a rate-limited client (20QPS with a burst of 50). There is also server-side [API Priority and Fairness system](https://kubernetes.io/docs/concepts/cluster-administration/flow-control/) that prevents rogue clients from overwhelming kube apiserver. Both these mechanisms mean that the result of a large number of additional calls will be slower issuance as cert-manager will get rate limited (either client-side or server-side). The rate limiting can be modified to allow higher throughput for cert-manager, but this would have an impact of kube apiserver's availability for other tenants, so in either case additional API calls would have a cost for the user.

### User Stories

#### Story 1

User has a cluster with 4 cert-manager `Certificate`s and 30k other (cert-manager unrelated) `Secret`s.
They observe unreasonably high memory consumption in proportion to the amount of cert-manager resources.

See issue description here https://github.com/cert-manager/cert-manager/issues/4722

### Risks and Mitigations

- Risk of slowing down issuance in cases where cert-manager needs to retrieve unlabelled `Secret`s, such as CA issuer's `Secret`.
  Users could mitigate this by labelling the `Secret`s.

- Risk of unintentionally or intentionally overwhelming kube apiserver with the additional requests.
  A default cert-manager installation uses rate limiting (default 50 QPS with a burst of 20). This should be sufficient to ensure that in case of a large number of additional requests from cert-manager controller, the kube apiserver is not slowed down. Cert-manager controller allows to configure rate limiting QPS and burst (there is no upper limit). Since 1.20, Kubernetes by default uses [API Priority and Fairness](https://kubernetes.io/docs/concepts/cluster-administration/flow-control/) for fine grained server side rate limiting, which should prevent clients that don't sufficiently rate limit themselves from overwhelming the kube apiserver.
  In a cluster where API Priority and Fairness is disabled and cert-manager's rate limiter has been configured with a very high QPS and burst, it might be possible to overwhelm kube apiserver. However, this is already possible today, if a user has the rights to configure cert-manager installation, i.e by creating a large number of cert-manager resources in a tight loop.
  To limit the possibility of overwhelming the kube apiserver:
  - we should ensure that control loops that access secrets do not unnecessarily retry on errors (i.e if a secret is not found or has invalid data).
    This should already be the case today, but worth reading through all possible paths
  - we could store initialized clients for all issuers as we already do for ACME issuer instead of retrieving credential secrets every time a certificate request needs to be signed
  - recommend that users label `Secret` resources
  - start with a non-GA implementation (this design suggests that the implementation starts as an alpha feature) to catch any potential edge cases and gate GA on user feedback from larger installations


## Design details
### Implementation

Ensure that `certificate.Spec.SecretName` `Secret` as well as the `Secret` with temporary private key are labelled with a `controller.cert-manager.io/fao: true` [^2] label.
The temporary private key `Secret` is short lived so it should be okay to only label it on creation.
The `certificate.Spec.SecretName` `Secret` should be checked for the label value on every reconcile of the owning `Certificate`, same as with the secret template labels and annotations, see [here](https://github.com/cert-manager/cert-manager/blob/v1.10.1/pkg/controller/certificates/issuing/issuing_controller.go#L187-L191).

Add a partial metadata informers factory, set up with [a client-go client that knows how to make GET/LIST/WATCH requests for `PartialMetadata`](https://github.com/kubernetes/client-go/blob/v0.26.0/metadata/metadata.go#L50-L58).
Add a filter to ensure that any informers for this factory will list _only_ resources that are _not_ labelled with a known 'cert-manager' label.


```go
import (
  ...
  "k8s.io/client-go/metadata"
  ...
)
metadataOnlyClient := metadata.NewForConfigOrDie(restConfig)

metadataLabelSelector, _ := notKnownCertManagerSecretLabelSelector()

metadataSharedInformerFactory := metadatainformer.NewFilteredSharedInformerFactory(metadataOnlyClient, resyncPeriod, opts.Namespace, func(listOptions *metav1.ListOptions) {
  // select only objects that do not have a known cert-manager label
		listOptions.LabelSelector = metadataLabelSelector
})

func notKnownCertManagerSecretLabelSelector() (string, error) {
	r, _ := labels.NewRequirement("controller.cert-manager.io/fao", selection.DoesNotExist, make([]string, 0))
	sel := labels.NewSelector().Add(*r)
	return sel.String(), nil
}
```

Create informer a partial metadata informer that watches events for `Secret` GVK:

```go
  metadataSecretsInformer := metadataSharedInformerFactory.ForResource(corev1.SchemeGroupVersion.WithResource("secrets"))
```

Add a label selector to the existing `Secret`s informer created for [typed informers factory](https://github.com/cert-manager/cert-manager/blob/v1.10.1/pkg/controller/context.go#L264) to ensure that only `Secret` that _do_ have a known cert-manager label are watched:

```go
import (
  ...
  kubeinternalinterfaces "k8s.io/client-go/informers/internalinterfaces"
  coreinformers "k8s.io/client-go/informers/core/v1"
  "k8s.io/client-go/kubernetes"
  ...
)
concreteSecretsInformer := NewFilteredSecretsInformer(factory, kubeClient) // factory is the existing typed informers factory

func NewFilteredSecretsInformer(factory kubeinternalinterfaces.SharedInformerFactory, client kubernetes.Interface) coreinformers.SecretInformer {
	return &filteredSecretsInformer{
		factory:     factory,
		client:      client,
		newInformer: newFilteredSecretsInformer,
	}
}

type filteredSecretsInformer struct {
	factory     kubeinternalinterfaces.SharedInformerFactory
	client      kubernetes.Interface
	newInformer kubeinternalinterfaces.NewInformerFunc
	namespace   string
}

func (f *filteredSecretsInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&corev1.Secret{}, f.newInformer)
}

func (f *filteredSecretsInformer) Lister() corelisters.SecretLister {
	return corelisters.NewSecretLister(f.Informer().GetIndexer())
}

func newFilteredSecretsInformer(client kubernetes.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	secretLabelSelector, _ := knownCertManagerSecretLabelSelector()
	return coreinformers.NewFilteredSecretInformer(client, "", resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, func(listOptions *metav1.ListOptions) {
		listOptions.LabelSelector = secretLabelSelector
	})
}

func knownCertManagerSecretLabelSelector() (string, error) {
	r, _ := labels.NewRequirement("controller.cert-manager.io/fao", selection.Exists, make([]string, 0))
	sel := labels.NewSelector().Add(*r)
	return sel.String(), nil
}
```

Create a new `Secret`s getter function. The function will check for the `Secret` in both typed and `PartialMetadata` cache.
- If the object is found in both caches, it assumes that either cache must be stale and get the `Secret` from kube apiserver[^1]
- If the object is found in `PartialMetadata` cache, it will get it from kube apiserver
- If the object is found in the typed cache, it will get it from there
- If the object is not found, it will return NotFound error

```go
func SecretGetter(ctx context.Context, liveSecretsClient typedcorev1.SecretsGetter, cacheSecretsClient corelisters.SecretLister, partialMetadataClient cache.GenericLister, name string, namespace string) (*corev1.Secret, error) {
	var secretFoundInTypedCache, secretFoundInMetadataCache bool
	secret, err := cacheSecretsClient.Secrets(namespace).Get(name)
	if err == nil {
		secretFoundInTypedCache = true
	}

	if err != nil && !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("error retrieving secret from the typed cache: %w", err)
	}
	_, partialMetadataGetErr := partialMetadataClient.ByNamespace(namespace).Get(name)
	if partialMetadataGetErr == nil {
		secretFoundInMetadataCache = true
	}

	if partialMetadataGetErr != nil && !apierrors.IsNotFound(partialMetadataGetErr) {
		return nil, fmt.Errorf("error retrieving object from partial object metadata cache: %w", err)
	}

	if secretFoundInMetadataCache && secretFoundInTypedCache {
		return liveSecretsClient.Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	}

	if secretFoundInTypedCache {
		return secret, nil
	}

	if secretFoundInMetadataCache {
		return liveSecretsClient.Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	}

	return nil, partialMetadataGetErr
}

```

Use the new `Secret`s getter in all control loops that need to get any `Secret`:

```go
  ...
	// Fetch and parse the 'next private key secret'
	nextPrivateKeySecret, err := SecretGetter(ctx, c.secretLiveClient, c.secretLister, c.metadataSecretLister, *crt.Status.NextPrivateKeySecretName, crt.Namespace)
  ...

```

### Metrics

The following metrics are based on [a prototype implementation of this design](https://github.com/irbekrm/cert-manager/tree/partial_metadata).
The tests were run on a kind cluster.

#### Cluster with large cert-manager unrelated secrets

Test the memory spike caused by the initial LIST-ing of `Secret`s, the size of cache after the initial LIST has been processed and a spike caused by changes to `Secret` resources.

##### cert-manager v1.11

Create 300 cert-manager unrelated `Secret`s of size ~1Mb:

![alt text](/design/images/20221205-memory-management/createsecrets.png)

Install cert-manager from [latest master with client-go metrics enabled](https://github.com/irbekrm/cert-manager/tree/client_go_metrics).

Wait for cert-manager to start and populate the caches.

Apply a label to all `Secret`s to initiate cache resync:

![alt text](/design/images/20221205-memory-management/labelsecret.png)

Observe that memory consumption spikes on controller startup when all `Secret`s are initially listed, there is a second smaller spike around the time the `Secret`s got labelled and that memory consumption remains high:

![alt text](/design/images/20221205-memory-management/latestmastersecrets.png)

##### partial metadata prototype

Create 300 cert-manager unrelated `Secret`s of size ~1Mb:

![alt text](/design/images/20221205-memory-management/createsecrets.png)

Deploy cert-manager from [partial metadata prototype](https://github.com/irbekrm/cert-manager/tree/partial_metadata).

Wait for cert-manager to start and populate the caches.

Apply a label to all `Secret`s to initiate cache resync:

![alt text](/design/images/20221205-memory-management/labelsecret.png)

Observe that the memory consumption is significantly lower:

![alt text](/design/images/20221205-memory-management/partialmetadatasecrets.png)

#### Issuance of a large number of `Certificate`s

This scenario tests issuing 500 certificates from 10 cert-manager [CA issuers](https://cert-manager.io/docs/configuration/ca/).
The CA issuers have been set up with CA certificates that do not have known cert-manager labels.

Here is a script that sets up the issuers, creates the `Certificate`s, waits for them to become ready and outputs the total time taken https://gist.github.com/irbekrm/bc56a917a164b1a3a097bda483def0b8.

##### latest cert-manager

This test was run against a version of cert-manager that corresponds to v1.11.0-alpha.2 with some added client-go metrics https://github.com/irbekrm/cert-manager/tree/client_go_metrics.
Run a script to set up 10 CA issuers, create 500 certificates and observe the time taken for all certs to be issued:
![alt text](/design/images/20221205-memory-management/masterissuanceterminal.png)

Observe resource consumption, request rate and latency for cert-manager controller:
![alt text](/design/images/20221205-memory-management/mastercertmanager.png)

Observe resource consumption and rate of requests for `Secret` resources for kube apiserver:
![alt text](/design/images/20221205-memory-management/masterkubeapiserver.png)

##### partial metadata

Run a script to set up 10 CA issuers, create 500 certificates and observe the time taken for all certs to be issued:
![alt text](/design/images/20221205-memory-management/partialnolabels.png)

Observe resource consumption, request rate and latency for cert-manager controller:
![alt text](/design/images/20221205-memory-management/partialnolabelscertmanager.png)

Observe resource consumption and rate of requests for `Secret` resources for kube apiserver:
![alt text](/design/images/20221205-memory-management/partialnolabelskubeapiserver.png)

The issuance is slightly slowed down because on each issuance cert-manager needs to get the unlabelled CA `Secret` directly from kube apiserver.
Users could mitigate this by adding cert-manager labels to the CA `Secret`s.
Run a modified version of the same script, but [with CA `Secret`s labelled](https://gist.github.com/irbekrm/bc56a917a164b1a3a097bda483def0b8#file-measure-issuance-time-sh-L31-L34):

![alt text](/design/images/20221205-memory-management/partiallabels.png)

For CA issuers, normally a `Secret` will be retrieved once per issuer reconcile and once per certificate request signing. In some cases, two `Secret`s might be retrieved during certificate request signing see [secrets for issuers](#secrets-for-clusterissuers). We could look into improving this, by initializing a client with credentials and sharing with certificate request controllers, similarly to how it's currently done with [ACME clients](https://github.com/cert-manager/cert-manager/blob/v1.11.0/pkg/controller/context.go#L188-L190).

### Pros

- In most setups in majority of cases where a control loop needs a `Secret` it would still be retrieved from cache (as it is certificate secrets that get parsed most frequently and those will be labelled in practically all cases)

- Memory consumption improvements appear quite significant

- Once graduated to GA would work for all installations without needing to discover a flag to set

### Cons

- All cluster `Secret`s are still listed

- Slower issuance in cases where cert-manager needs to retrieve unlabelled `Secret`s
### Test Plan

Unit and e2e tests (largely updating our existing e2e tests and writing unit tests for any new functions).

We do not currently have any automated tests that observe resource consumption/do load testing.

See [Metrics](#metrics) for how to test resource consumption/issuance speed manually.

### Graduation Criteria

Alpha (cert-manager 1.12):

- feature implemented behind a feature flag

- CI tests pass for all supported Kubernetes versions

- this design discussed and merged

Beta:

User feedback:
- does this solve the target use case (memory consumption reduction for clusters with large number of cert-manager unrelated `Secret`s)?
- does this work in cases where large number of `Certificate`s need to be issued around the same time (i.e is the slight slowdown of issuance acceptable)?

GA:

- TODO: define criteria which should be a certain number of working installations

### Upgrade / Downgrade Strategy

Recommend users to upgrade to cert-manager v1.11 first to ensure that all `Certificate` `Secret`s are labelled to avoid spike in apiserver calls on controller startup.

### Supported Versions

This feature will work with all versions of Kubernetes currently supported by cert-manager.

`PartialMetadata` support by kube apiserver has been GA [since Kubernetes 1.15](https://github.com/kubernetes/enhancements/tree/master/keps/sig-api-machinery/2334-graduate-server-side-get-and-partial-objects-to-GA#implementation-history).
[The oldest Kubernetes version supported by cert-manager 1.12 will be 1.22](https://cert-manager.io/docs/installation/supported-releases/#upcoming-releases).

### Notes
#### Current state

This sections lists all `Secret`s that _need_ to be watched by cert-manager controller's reconcile loops.

##### Secrets for Certificates

- `certificate.spec.secretName` `Secret`s (that contain the issued certs). These can be created by cert-manager or pre-created by users or external tools (i.e ingress controller). If created by cert-manager, they [will have a number of `cert-manager.io` annotations](https://github.com/cert-manager/cert-manager/blob/2f24231383173cf8ef66858c24e7d2f01c699219/internal/controller/certificates/secrets.go#L35-L52). Secrets without annotations will cause re-issuance (see https://cert-manager.io/docs/faq/#when-do-certs-get-re-issued) and upon successful issuance cert-manager.io annotations will be added.

- The temporary `Secret`s that get created for each issuance and contain the private key of that the certificate request is signed with. These can only be created by cert-manager controller and are all labelled with `cert-manager.io/next-private-key: true` label.

##### Secrets for [Cluster]Issuers

The issuers and clusterissuers controllers set up watches for all events on all secrets, but have [a filter](https://github.com/cert-manager/cert-manager/blob/2f24231383173cf8ef66858c24e7d2f01c699219/pkg/controller/issuers/controller.go#L100) to determine whether an event should cause a reconcile.

**ACME issuer**

- the secret referenced by  `issuer.spec.acme.privateKeySecretRef`. This can be created by user (for an already existing ACME account) or by cert-manager. Cert-manager does not currently add any labels or annotations to this secret.

A number of optional secrets that will always be created by users with no labelling enforced:


- the secret referenced in `issuer.spec.acme.externalAccountBinding`.

- the secret referenced by `issuer.spec.acme.solvers.dns01.acmeDNS.accountSecretRef`.

- the secret referenced in `issuer.spec.acme.solvers.dns01.akamai.clientSecretSecretRef`

- the secret referenced in `issuer.spec.acme.solvers.dns01.akamai.accessTokenSecretRef`

- the secret referenced in `issuer.spec.acme.solvers.dns01.azureDNS.clientSecretSecretRef`

- the secret referenced in `issuer.spec.acme.solvers.dns01.cloudDNS.serviceAccountSecretRef`

- the secret referenced in `issuer.spec.acme.solvers.dns01.cloudflare.apiTokenSecretRef`

- the secret referenced in `issuer.spec.acme.solvers.dns01.cloudflare.apiKeySecretRef`

- the secret referenced in `issuer.spec.acme.solvers.dns01.digitalocean.tokenSecretRef`

- the secret referenced in `issuer.spec.acme.solvers.dns01.rfc2136.tsigSecretSecretRef`

- the secret referenced in `issuer.spec.acme.solvers.dns01.route53.accessKeyIDSecretRef`

- the secret referenced in `issuer.spec.acme.solvers.dns01.route53.secretAccessKeySecretRef`

The ACME account key secret and, if configured, the secret with EAB key will be returned once per issuer reconcile (on events against issuer or the account key or EAB key secret). The ACME client initialized with the credentials is then stored in a registry shared with orders controller, so the secrets are _not_ retrieved again when a certificate request for the issuer needs to be signed.
For a DNS-01 challenge, one (possibly two in case of AWS) calls for secrets will be made during issuance to retrieve the relevant credentials secret.

**CA**

- the secret referenced by `issuer.spec.ca.secretName`. This will always be created by user. No labelling is currently enforced.

This will be retrieved twice when the issuer is reconciled (when an event occurs against the issuer or its secret) and once when a certificate request for the issuer is being signed.

**Vault**

- the optional secret referenced by `issuers.spec.vault.caBundleSecretRef`. Always created by user with no labelling enforced

One of the following credentials secrets:

  - secret referenced by `issuers.spec.vault.auth.appRole.secretRef`. Always created by user with no labelling enforced

  - secret referenced by `issuers.spec.vault.auth.kubernetes.secretRef`. Always created by user with no labelling enforced

  - secret referenced by `issuers.spec.vault.auth.tokenSecretRef`. Always created by user with no labelling enforced

The configured credentials `Secret`s and, if configured, CA bundle `Secret` will be retrieved every time the issuer is reconciled (on events against the issuer and either of the `Secret`s) and every time a certificate request needs to be signed.

**Venafi**

One of:

- the secret referenced by `issuers.spec.venafi.tpp.secretRef`. Always created by user with no labelling enforced

- the secret referenced by `issuers.spec.venafi.cloud.secretRef`. Always created by user with no labelling enforced

The configured `Secret` will be retrieved when the issuer is reconciled (events against issuer and its secret) and when a certificate request is signed.

#### Upstream mechanisms

There are a number of existing upstream mechanisms how to limit what gets stored in the cache. This section focuses on what is available for client-go informers which we use in cert-manager controllers, but there is a controller-runtime wrapper available for each of these mechanisms that should make it usable in cainjector as well.

 ##### Filtering

Filtering which objects get watched using [label or field selectors](https://github.com/kubernetes/apimachinery/blob/v0.26.0/pkg/apis/meta/v1/types.go#L328-L332). These selectors allow to filter what resources are retrieved during the initial list call and watch calls to kube apiserver by informer's `ListerWatcher` component (and therefore will end up in the cache). client-go informer factory allows configuring individual informers with [list options](https://github.com/kubernetes/client-go/blob/v12.0.0/informers/factory.go#L78-L84) that will be used [for list and watch calls](https://github.com/kubernetes/client-go/blob/v12.0.0/informers/core/v1/secret.go#L59-L72).
This mechanism is used by other projects that use client-go controllers, for example [istio](https://github.com/istio/istio/blob/1.16.0/pilot/pkg/status/distribution/state.go#L100-L103).
The same filtering mechanism is [also available for cert-manager.io resources](https://github.com/cert-manager/cert-manager/blob/v1.10.1/pkg/client/informers/externalversions/factory.go#L63-L69). We shouldn't need to filter what cert-manager.io resources we watch though.
This mechanism seems the most straightforward to use, but currently we don't have a way to identify all resources (secrets) we need to watch using a label or field selector, see [###Secrets].

##### Partial object metadata

Caching only metadata for a given object. This mechanism relies on making list and watch calls against kube apiserver with a `PartialObjectMetadata` header. The apiserver then returns [PartialObjectMetadata](https://github.com/kubernetes/apimachinery/blob/v0.26.0/pkg/apis/meta/v1/types.go#L1425-L1447) instead of an object of a concrete type such as a `Secret`. The `PartialObjectMetadata` only contains the metadata and type information of the object.
To use this mechanism to ensure that metadata only is being cached for a particular resource type that triggers a reconcile, `ListerWatcher` of the informer for that type needs to use a client that knows how to make calls with `PartialObjectMetadata` header. Also if the reconcile loop can only retrieve `PartialObjectMetadata` types from cache.
client-go has a [metadata only client](https://github.com/kubernetes/client-go/blob/v0.25.5/metadata/metadata.go#L85-L99) that can be used to get, list and watch with `PartialObjectMetadata`. client-go also has a [metadata informer](https://github.com/kubernetes/client-go/blob/v0.25.5/metadata/metadatainformer/informer.go#L118-L142) that uses the metadata only client to list and watch resources. This informer implements the same [SharedIndexInformer interface](https://github.com/kubernetes/client-go/blob/v0.26.0/tools/cache/shared_informer.go#L219) as the core and cert-manager.io informers that we use currently, so it would fit our existing controller setup.
The downside to having metadata only in cache is that if the reconcile loop needs the whole object, it needs to make another call to the kube apiserver to get the actual object. We have a number of reconcile loops that retrieve and parse secret data numerous times, for example [readiness controller](https://github.com/cert-manager/cert-manager/blob/v1.10.1/pkg/controller/certificates/readiness/readiness_controller.go) retrieves and parses `spec.SecretName` secret for a `Certificate` on any event associated with the `Certificate`, any of its `CertificateRequest`s or the `spec.secretName` secret.
TODO: add which projects have adopted metadata-only watches, especially with client-go informers

##### Transform functions

Transforming the object before it gets placed into cache. Client-go allows configuring core informers with [transform functions](https://github.com/kubernetes/client-go/blob/v0.25.5/tools/cache/controller.go#L356-L365). These functions will get called with the object as an argument [before the object is placed into cache](https://github.com/kubernetes/client-go/blob/v0.25.5/tools/cache/controller.go#L420-L426). The transformer will need to convert the object to a concrete or metadata type if it wants to retrieve its fields.
This is a lesser used functionality in comparison with metadata only caching.
A couple usage examples:
- support for transform functions was added in controller-runtime [controller-runtime#1805](https://github.com/kubernetes-sigs/controller-runtime/pull/1805) with the goal of allowing users to remove managed fields and annotations
- Istio's pilot controller uses this mechanism to configure their client-go informers to [remove managed fields before putting object into cache](https://github.com/istio/istio/blob/1.16.0/pilot/pkg/config/kube/crdclient/client.go#L179)
I haven't seen any usage examples where non-metadata fields are modified using this mechanism. I cannot see a reason why new fields (i.e a label that signals that a transform was applied could not be _added_) as well as fields being removed.

##### Future changes

There is an open KEP for replacing initial LIST with a WATCH https://github.com/kubernetes/enhancements/pull/3667

Perhaps this would also reduce the memory spike on controller startup.

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

No

### Will enabling / using this feature result in new API calls (i.e to Kubernetes apiserver or external services)?

There will be additional calls to kube apiserver to retrieve unlabelled `Secret`s.

See [Metrics](#metrics) and [Risks and Mitigation](#risks-and-mitigations)

### Will enabling / using this feature result in increasing size or count of the existing API objects?

No new objects will be created

### Will enabling / using this feature result in significant increase of resource usage? (CPU, RAM...)

No, see  [Metrics](#metrics)

## Alternatives

### Use transform functions to remove `data` for non-labelled `Secret`s before adding them to informers cache

Watch all `Secret`s as before. Use client-go's [transform functions mechanism](https://github.com/kubernetes/client-go/blob/v0.25.5/tools/cache/controller.go#L356-L365) to remove the `data` field for a `Secret` that does not have a known cert-manager label before it gets placed in informer's cache. In the same transform function add a custom `cert-manager.io/metadata-only` label to all `Secret`s whose `data` got removed (this label will only exist on the cached object).
In reconcilers, use a custom `Secret`s getter that can get the `Secret` either from kube apiserver or cache, depending on whether it has the `cert-manager.io/metadata-only` label that suggests that the `Secret`'s `data` has been removed.
Additionally, ensure that as many `Secret`s as we can (ACME registry account keys) get labelled.
Users would be encouraged to add a cert-manager label to all `Secret`s they create to reduce extra calls to kube apiserver.

In practice:

- cert-manager would cache the full `Secret` object for all `certificate.spec.secretName` `Secret`s and all `Secret`s containing temporary private keys in almost all cases and would retrieve these `Secret`s from cache in almost all cases (see the section about [Secrets for Certificates](#Secrets-for-Certificates))

- cert-manager would cache the full `Secret` object for all labelled user created `Secret`s (issuer credentials)

- cert-manager would cache metadata only for user created unlabelled `Secret`s that are used by issuers/cluster-issuers and would call kube apiserver directly to retrieve `Secret` data for those `Secret`s

- cert-manager would cache metadata for all other unrelated cluster `Secret`s

This would need to start as an alpha feature and would require alpha/beta testing by actual users for us to be able to measure the gain in memory reduction in concrete cluster setup.

[Here](https://github.com/irbekrm/cert-manager/tree/experimental_transform_funcs) is a prototype of this solution.
In the prototype [`Secrets Transformer` function](https://github.com/irbekrm/cert-manager/blob/d44d4ed2e27fb9b7695a74ae254113f3166aadb4/pkg/controller/util.go#L219-L238)
is the transform that gets applied to all `Secret`s before they are cached. If a `Secret` does not have any known cert-manager labels or annotations it removes `data`, `metadata.managedFields` and `metadata.Annotations` and applies a `cert-manager.io/metadata-only` label.
[`SecretGetter`](https://github.com/irbekrm/cert-manager/blob/d44d4ed2e27fb9b7695a74ae254113f3166aadb4/pkg/controller/util.go#L241-L261) is used by any control loop that needs to GET a `Secret`. It retrieves it from kube apiserver or cache depending on whether `cert-manager.io/metadata-only` label was found.

#### Drawbacks

- All cluster `Secret`s are still listed

- The transform functions only get run before the object is placed into informer's cache. The full object will be in controller's memory for a period of time before that (in DeltaFIFO store (?)). So the users will still see memory spikes when events related to cert-manager unrelated cluster `Secret`s occur.
See performance of the prototype:

Create 300 cert-manager unrelated `Secret`s of size ~1Mb:

![alt text](/design/images/20221205-memory-management/createsecrets.png)

Deploy cert-manager from https://github.com/irbekrm/cert-manager/tree/experimental_transform_funcs

Wait for cert-manager caches to sync, then run a command to label all `Secret`s to make caches resync:

![alt text](/design/images/20221205-memory-management/labelsecret.png)

Observe that although altogether memory consumption remains quite low, there is a spike corresponding to the initial listing of `Secret`s:

![alt text](/design/images/20221205-memory-management/transformfunctionsgrafana.png)

### Use PartialMetadata only

We could cache PartialMetadata only for `Secret` objects. This would mean having
just one, metadata, informer for `Secret`s and always GETting the `Secret`s
directly from kube apiserver.

#### Drawbacks

Large number of additional requests to kube apiserver. For a default cert-manager installation this would mean slow issuance as client-go rate limiting would kick in. The limits can be modified via cert-manager controller flags, however this would then mean less availability of kube apisever to other cluster tenants.
Additionally, the `Secret`s that we actually need to cache are not likely going to be large in size, so there would be less value from memory savings perspective.

Here is a branch that implements a very experimental version of using partial metadata only https://github.com/irbekrm/cert-manager/tree/just_partial.

The following metrics are approximate as the prototype could probably be optimized. Compare with [metrics section of this proposal](#issuance-of-a-large-number-of-certificates) for an approximate idea of the increase in kube apiserver calls during issuance.

Deploy cert-manager from https://github.com/irbekrm/cert-manager/tree/just_partial

Run a script to set up 10 CA issuers, create 500 certificates and observe that the time taken is significantly higher than for latest version of cert-manager:
![alt text](/design/images/20221205-memory-management/partialonly.png)

Observe high request latency for cert-manager:
![alt text](/design/images/20221205-memory-management/partialonlycertmanager.png)

Observe a large number of additional requests to kube apiserver:
![alt text](/design/images/20221205-memory-management/partialonlykubeapiserver.png)

### Use paging to limit the memory spike when controller starts up

LIST calls to kube apiserver can be [paginated](https://kubernetes.io/docs/reference/using-api/api-concepts/#retrieving-large-results-sets-in-chunks).
Perhaps not getting all objects at once on the initial LIST would limit the spike in memory when cert-manager controller starts up.

However, currently it is not possible to paginate the initial LISTs made by client-go informers.
Although it is possible to set [page limit](https://github.com/kubernetes/apimachinery/blob/v0.26.0/pkg/apis/meta/v1/types.go#L371-L387) when creating a client-go informer factory or an individual informer, this will in practice not be used for the initial LIST.
LIST requests can be served either from etcd or [kube apiserver watch cache](https://github.com/kubernetes/apiserver/tree/v0.26.0/pkg/storage/cacher).
Watch cache does not support pagination, so if a request is forwarded to the cache, the response will contain a full list.
Client-go makes the initial LIST request [with resource version 0](https://github.com/kubernetes/client-go/blob/v0.26.0/tools/cache/reflector.go#L592-L596) for performance reasons (to ensure that watch cache is used) and this results in [the response being served from kube apiserver watch cache](https://github.com/kubernetes/apiserver/blob/v0.26.0/pkg/storage/cacher/cacher.go#L621-L635).

There is currently an open PR to implement pagination from watch cache https://github.com/kubernetes/kubernetes/pull/108392.

### Filter the Secrets to watch with a label

Only watch `Secret`s with known `cert-manager.io` labels. Ensure that label gets applied to all `Secret`s we manage (such as `spec.secretName` `Secret` for `Certificate`).
We already ensure that all `spec.secretName` `Secret`s get annotated when synced - we can use the same mechanism to apply a label.
Users will have to ensure that `Secret`s they create are labelled.
We can help them to discover which `Secret`s that are currently deployed to cluster and need labelling with a `cmctl` command.
In terms of resource consumption and calls to apiserver, this would be the most efficient solution (only relevant `Secret`s are being listed/watched/cached and all relevant `Secret`s are cached in full).

#### Drawbacks

- Bad user experience - breaking change to adopt and introduces a potential footgun after adoption as even if users labelled all relevant `Secret`s in cluster at time of adoption, there would likely be no visible warning if an unlabelled `Secret` for an issuer got created at some point in future and things would just silently not work (i.e `Secret` data updates would not trigger issuer reconcile etc).

- This feature would likely need to be opt-in 'forever' as else it would be a major breaking change when adopting and a potential footgun after adoption

- Maintenance cost of the `cmctl` command: if a new user created `Secret` needs to be watched in a reconcile loop, the cmctl command would also need to be updated, which could be easily forgotten

### Allow users to pass a custom filter

Add a flag that allows users to pass a custom selector (a label or field filter)

See an example flag implementation for cainjector in https://github.com/cert-manager/cert-manager/pull/5174 thanks to @aubm for working on this.

It might work well for cases where 'known' selectors need to be passed that we could event document such as `type!=helm.sh/release.v1`.

#### Drawbacks

- bad user experience - no straightforward way to tell if the selector actually does what was expected and an easy footgun especially when users attempt to specify which `Secret`s _should_ (rather than _shouldn't_) be watched

- users should aim to use 'negative' selectors, but that be complicated if there is a large number of random `Secret`s in cluster that don't have a unifying selector

### Use a standalone typed cache populated from different sources

As suggested by @sftim https://kubernetes.slack.com/archives/C0EG7JC6T/p1671478591357519

We could have a standalone cache for typed `Secret`s that gets populated by a standard watch for labelled `Secret`s as well as from `Secret`s that were retrieved in reconciler loops. A metadata only cache would also be maintained.
This should ensure that a `Secret` that our control loop needs, but is not labelled only gets retrieved from kube apiserver once. So it should provide the same memory improvements as the main design, but should avoid additional kube apiserver calls in cases where users have unlabelled cert-manager related `Secret`s in cluster.

#### Drawbacks

- complexity of implementation and maintenance of a custom caching mechanism

[^1]: We thought this might happen when the known cert-manager label gets added to or removed from a `Secret`. There is a mechanism for removing such `Secret` from a cache that should no longer have it, see [this Slack conversation](https://kubernetes.slack.com/archives/C0EG7JC6T/p1671476139766499) and when experimenting with the prototype implementation I have not observed stale cache when adding/removing labels

[^2]: fao = 'for attention of'
