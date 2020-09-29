Roadmap
=======

These are the themes that we plan to work on for cert-manager. If you wish
to discuss these topics you can find us in #cert-manager on Kubernetes Slack, or
at our [community meetings](https://cert-manager.io/docs/contributing/#meetings).

The roadmap items are categorized in to themes based on the larger goals we
want to achieve with cert-manager.

While this is a summary of the direction we want to go, we welcome all PRs,
even if they don't fall under any of the roadmap items.

* Beyond Ingress: improve experience of cert-manager for applications beyond just
  ingress certificates
  * Service Mesh Integration: Enable service meshes to issue mTLS certificates
    with cert-manager, getting the integration with external issuers and the
    audit capabilities of cert-manager in their mesh
  * Istio agent certificates issued via cert-manager
  * CSI driver: seamlessly deliver unique certs + keys to workloads. Review the
    prototype that we have for this and do a proper release.
* Adoption of upstream APIs: continue to support latest APIs for k8s upstream
  * k8s APIs: keep up to date with Kubernetes API changes and releases
  * CSR API: support CSR API as a standard for certificate requests in kubernetes
* Policy: allowing granular control over certificate issuance
  * Extensible primitives within cert-manager for defining policy for
    acceptable CertificateRequests
* Extensibility: widen the scope of integrations with cert-manager
  * [EST support](https://tools.ietf.org/html/rfc7030): support a standard for
    ACME-like issuance within an enterprise
  * External DNS plugin: enable ACME DNS01 requests to be completed using external-dns
  * OpenShift Routes support: provide similar capabilities to Ingress for
    issuing certs
  * Improve external issuer development experience: documentation and examples
    for people developing external issuers
* PKI lifecycle: enable best-practice PKI management with cert-manager
  * Handle CA cert being renewed: deal with the cases where the CA cert is
    renewed and allow for all signed certs to be renewed
  * Trust root distribution: handle distributing all trust roots within a
    cluster, allowing for certs to be verified within a cluster
* Improve developer and operator experience: better user experience
  for installation, operation and use with applications
  * Easier installation of cert-manager: improve the installation experience
    through docs and in other ways
        * Tooling to install and upgrade cert-manager (improved operators? CLI tool?)
        * Tooling to verify an installation is correct/secure
  * Easier diagnosis of problems: improve the cert-manager output to make the
    status clearer, and provide tools to aid debugging
  * Improve the new contributor experience
