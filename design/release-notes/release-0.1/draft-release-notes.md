This is the first release of cert-manager. It is currently still not in a production ready state, and features are subject to change.

Notable features:

- *Automated certificate renewal*
- *ACME DNS-01 challenge mechanism*
  - CloudDNS
  - Route53
  - Cloudflare
- *ACME HTTP-01 challenge mechanism*
  - Should be compatible with all ingress controllers following ingress spec (GCE & nginx tested)
- *Simple CA based issuance*
  - Create an Issuer that references a Secret resource containing a signing keypair, and issue/renew certificates from that.
- *Cluster-wide issuers (aka ClusterIssuer)*
- *Backed by CRDs*
  - Events logged to the Kubernetes API
  - Status block utilised to store additional state about resources

Please check the [README(https://github.com/jetstack-experimental/cert-manager) for a quick-start guide.

We really value any feedback and contributions to the project. If you'd like to get involved, please open some issues, comment or pick something up and get started!
