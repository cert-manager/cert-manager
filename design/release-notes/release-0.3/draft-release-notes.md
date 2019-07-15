# Highlights
This is a big feature filled release of cert-manager, and the first since moving to a
more frequent release model.

There's been a huge uptick in community contributions to the project, and this release
comprises the combined effort of 38 code contributors and hundreds of users reporting
issues, feature requests and bug reports!

There's quite a few big headline points, so we'll get straight in:

## ACMEv2 and Let's Encrypt wildcard certificates
This release of cert-manager brings the long-awaited ACMEv2 support, and with it, Let's Encrypt
wildcard certificates!

This allows you to request certificates for wildcard domains, e.g. \*.example.com, which can be used
to secure many different subdomains of your domain!

The introduction of ACMEv2 is a *breaking change*. Please read the notes below in the *Action Required*
section for details on how to handle your existing ACME Issuers whilst upgrading from v0.2.x.

## Alpha support for Hashicorp Vault
This release introduces initial support for Hashicorp Vault as an Issuer backend! Initially, this includes support for authenticating via AppRole and static token.

The support for this Issuer is classed as 'alpha' - feedback is invaluable at this stage of development, so we are getting it out there in a tagged release to gather usage info.

More information on configuring a Vault Issuer can be found in the Vault Issuer docs.

## readthedocs.io documentation site
Whilst this note applies to the v0.2.x release series also, it is worth noting.

We have now moved to readthedocs.io and reStructuredText for our documentation.
This should hopefully make it easier for external collaborators to make quick edits
to our documentation, and should provide more structure.

We'd like to take the time to thank all those that have opened issues or opened pull requests against
our documentation - it's a difficult thing to get right, but it's imperative our documentation is
clear for new users adopting the project.

## New ACME DNS01 providers
When cert-manager was first released, only CloudDNS and Cloudflare DNS01 providers were
supported when solving ACME challenges.

As new users, each using their own DNS providers, have adopted the project; there has been
a flurry of contributions adding support for the variety of providers out there.

With this release, we support the following DNS providers when solving ACME DNS01 challenges:

- Akamai FastDNS (#322, @twz123)
- Amazon Route53
- Azure DNS (#246, @mwieczorek)
- Cloudflare
- Google CloudDNS
There are pull requests in flight to add support for:
- DNSPod (#486, @hemslo)
- DNSimple (#483, @marc-sensenich)
- DigitalOcean (#345, @dl00)
- INWX (#336, @steigr)
- RFC2136 (#245, @simonfuhrer)

# Changelog
## Action Required
Please check the 'upgrading from 0.2 to 0.3' guide in the Administrative Tasks section of the docs here before upgrading.

- Supporting resources for ClusterIssuer's (e.g. signing CA certificates, or ACME account private keys) will now be stored in the same namespace as cert-manager, instead of kube-system in previous versions (#329, @munnerz):
  *Action required*: you will need to ensure to properly manually migrate these referenced resources across into the deployment namespace of cert-manager, else cert-manager may not be able to find account private keys or signing CA certificates.

- Use ConfigMaps for leader election (#327, @mikebryant):
- *Action required*: Before upgrading, scale the cert-manager Deployment to 0, to avoid two controllers attempting to operate on the same resources

- Remove support for ACMEv1 in favour of ACMEv2 (#309, @munnerz):
  *Action required*: As this release drops support for ACMEv1, all Issuer resources that use ACMEv1 endpoints (e.g. existing Let's Encrypt Issuers) will need updating to use equivalent ACMEv2 endpoints. (TODO: link to docs guide)

- Remove ingress-shim and link it into cert-manager itself (#502, @munnerz)
 *Action required*: You must change your 'helm install' command to use the new --ingressShim.defaultIssuerName, --ingressShim.defaultIssuerKind options when upgrading as --ingressShim.extraArgs has been removed.

- Add certmanager.k8s.io/acme-http01-edit-in-place annotation and change ingress-shim to set 'ingressClass' on ACME Certificate resources by default. (#493, @munnerz)
 *Action required*: This is a potentially breaking change for users of ingress controllers that map a single IP address to a single Ingress resource, such as the GCE ingress controller. These users will need to add the following annotation to their ingress: certmanager.k8s.io/acme-http01-edit-in-place: "true".

## Other notable changes
### ACME Issuer
- Add ACME DNS-01 provider for Akamai FastDNS (#322, @twz123)
- Add a meaningful user agent to the ACME client to help diagnosing abusive traffic patterns (#422, @jsha)
- Issuers using the AWS Route53 solver may attempt to find credentials using the environment, EC2 IAM Role, and other sources available to the cert-manager controller. This behavior is on by default for cluster issuers and off by default for issuers. This behavior may be enabled or disabled for all issuers or cluster issuers using the --issuer-ambient-credentials and --cluster-issuer-ambient-credentials flags on the cert-manager controller. (#363, @euank)
- Add limits to http validation pod (#408, @kragniz)
- The ACME dns01 solver now trims excess whitespace from AWS credentials (#391, @euank)
- ACME DNS-01 challenge mechanism for Azure DNS (#246, @mwieczorek)
- Fix panic when ACME server returns an error other than HTTP Status Conflict during registration (#237, @munnerz)
### CA Issuer
- Add the Key Encipherment purpose to CA Issuer generated certificates (#488, @bradleybluebean)
- Bundle CA certificate with issued certificates (#317, @radhus)
### Vault Issuer
- Add experimental support for Hashicorp Vault issuers (#292, @vdesjardins)
- ingress-shim
- ingress-shim now reconfigures certificates (#386, @kragniz)
- ingress-shim will only sync Ingress resources with kubernetes.io/tls-acme annotation if the value of that annotation is true. (#325, @wmedlar)
### Docs
- Rewrite documentation and publish on readthedocs (#428, @munnerz)
- Document the minimum necessary permissions for using cert-manager with Route53 (#359, @wmedlar)
- Improve deployment documentation (#264, @munnerz)
### Helm
- Add clusterResourceNamespace option to Helm chart (#547, @munnerz)
- Enhance Helm chart in-line with best practices (#229, @unguiculus):
- Add support for node affinity and tolerations in Helm chart (#350, @kiall)
- Add podAnnotations to Helm chart (#387, @etiennetremel)
- Add Certificate CRD shortnames cert and certs. This is configurable in the Helm Chart with certificateResourceShortNames. (#312, @Mikulas)
- Remove default resource requests in Helm chart. Improve post-deployment informational messages. (#290, @munnerz)
- End-to-end testing now covers the helm chart for cert-manager on Kubernetes 1.7-1.9 (#216, @munnerz)
### Other
- Produce a single static manifest instead of a directory when generating deployment manifests (#574, @munnerz)
- Use cert-manager deployment namespace by default for leader election (#548, @munnerz)
- Removed --namespace flag (#433, @kragniz)
- Run cert-manager container as a non root user (#415, @tettaji)
- TLS secrets are now annotated with information about the certificate (#388, @kragniz)
- The static deployment manifests now automatically deploy into the 'cert-manager' namespace by default (#330, @munnerz)
- Rename Event types to be prefixed 'Err' instead of 'Error' for brevity (#332, @munnerz)
- Clearer event logging when issuing a certificate for the first time (#331, @munnerz)
- Provide static deployment manifests as an alternative to a Helm chart based deployment (#276, @munnerz)
- Update existing secrets instead of replacing in order to preserve annotations/labels (#221, @munnerz)
- Update to Go 1.9 (#200, @euank)
### Bugfixes
- Fix a race condition in the package responsible for scheduling renewals (#218, @munnerz)
- Fix a bug that caused ACME certificates to not be automatically renewed (#215, @munnerz)
- Fix a bug in checking certificate validity and improve validation of dnsNames and commonName (#183, @munnerz)
- Fix bugs when checking validity of certificate resources (#184, @munnerz)
