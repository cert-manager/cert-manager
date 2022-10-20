Roadmap
=======

The roadmap items are categorised into themes based on the larger goals we want to achieve with cert-manager.


While this is a summary of the direction we want to go we welcome all PRs, even if they don't fall under any of the roadmap items
listed here. We unfortunately can't merge every change, and if you're looking to contribute a new feature you might want to
check the [contributing guide](https://cert-manager.io/docs/contributing/) on the cert-manager website.


### Integration with other projects in the cloud-native landscape

cert-manager should be able to deliver and manage X.509 certificates to popular
projects in the cloud-native ecosystem.

- Service Mesh Integration: While we have good Istio and Open Service Mesh integration, expand to other projects such as Linkerd, cilium

### Adoption of upstream APIs

Continue to support latest APIs for upstream K8s and related SIGs.

- Kubernetes APIs: keep up to date with Kubernetes API changes and release cadence
- CSR API: support the sig-auth CSR API for certificate requests in kubernetes
- [Trust Anchor Sets](https://github.com/kubernetes/enhancements/pull/3258)
- Gateway API

### Extensibility

Widen the scope of integrations with cert-manager.

- EST support: support a standard for ACME-like issuance within an enterprise
- External DNS plugin: enable ACME DNS01 requests to be completed using external-dns
- Improve external issuer development experience: documentation and examples for people developing external issuers

### PKI lifecycle

Enable best-practice PKI management with cert-manager.

- Handle CA certs being renewed: deal with the cases where the CA cert is renewed and allow for all signed certs to be renewed
- Make cert-manager a viable way to create and manage private PKI deployments at scale
- Trust root distribution: handle distributing all trust roots within a cluster, solving trust for private and public certificates

See also [trust-manager](https://cert-manager.io/docs/projects/trust/) for more on trust distribution.

### End-user experience

- Graduate alpha / beta features in good time:
  - SIG-Auth CSR API support
  - SIG-Network Gateway API support
- Easier diagnosis of problems: improve cert-manager output to make status clearer, and provide tools to aid debugging
- Improve the new contributor experience

### Developer experience

- Better user experience for installation, operation and use with applications
- Zero test flakiness and increased testing confidence
- Improve release process by adding more automation

### Shrinking Core

Minimise the surface area of cert-manager, reducing attack surface, binary size, container size and default deployment complexity

- Move "core" issuers with dependencies (ACME, Vault, Venafi) into external issuers, which might still be bundled by default
- Likewise, change all "core" DNS solvers into external solvers
- Provide a minimal "pick and mix" distribution of cert-manager which allows users to specify exactly which issuer types / DNS solvers they want to install
