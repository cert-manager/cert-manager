# Issuer spec

The full spec for an Issuer can be seen in [types.go](../../..//pkg/apis/certmanager/v1alpha1/types.go).
It contains the most up to date copy of the Issuer specification, and should
be used as the canonical source for the API schema.

Issuers are a representation of some source of signed certificates in the
cert-manager API. Each Issuer is of one, and only one type. The type of an
issuer is denoted by which field it specifies in its spec, such as `spec.acme`
for the ACME issuer, or `spec.ca` for the CA based issuer.

For example, to a basic ACME Issuer can be configured like so:

```yaml
apiVersion: certmanager.k8s.io/v1alpha1
kind: Issuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v01.api.letsencrypt.org/directory
    email: user@example.com
    # Name of a secret used to store the ACME account private key
    privateKeySecretRef:
      name: letsncrypt-prod
```

## ACME configuration

In order to use the ACME provider, there are a number of required fields.
For your ACME issuer to support the various ACME challenge mechanisms, you may
need to provide some additional configuration on your resource, such as
configuring credentials for a DNS provider.

### ACME issuer HTTP01 configuration

In order to allow HTTP01 challenges to be solved, we must enable the HTTP01
challenge provider on our Issuer resource. This can be done through setting the
`http01` field on the `issuer.spec.acme` stanza. Cert-manager will then create
and manage Ingress rules in the Kubernetes API server in order to solve HTTP-01
based challenges.

```yaml
apiVersion: certmanager.k8s.io
kind: Issuer
metadata:
  name: example-issuer
spec:
  acme:
    email: user@example.com
    server: https://acme-staging.api.letsencrypt.org/directory
    privateKeySecretRef:
      name: example-issuer-account-key
    http01: {}
```

### ACME issuer with no configured DNS providers

Below is an ACME issuer that has been configured to only allow issuing
certificates validated with HTTP01 challenges. A new ACME account will be
registered if required, using a private key stored in a Secret in the same
namespace as the Issuer, named `example-issuer-account-key`. It will use the
provided email address on the registration, and register the account with the
listed ACME server (the letsencrypt staging server in this case).

```yaml
apiVersion: certmanager.k8s.io
kind: Issuer
metadata:
  name: example-issuer
spec:
  acme:
    email: user@example.com
    server: https://acme-staging.api.letsencrypt.org/directory
    privateKeySecretRef:
      name: example-issuer-account-key
```

### ACME issuer DNS provider configuration

The ACME issuer can also contain DNS provider configuration, which can be used
by Certificates using this Issuer in order to validate DNS01 challenge
requests:

```yaml
apiVersion: certmanager.k8s.io
kind: Issuer
metadata:
  name: example-issuer
spec:
  acme:
    email: user@example.com
    server: https://acme-staging.api.letsencrypt.org/directory
    privateKeySecretRef:
      name: example-issuer-account-key
    dns01:
      providers:
      - name: prod-clouddns
        clouddns:
          serviceAccountSecretRef:
            name: prod-clouddns-svc-acct-secret
            key: service-account.json
```

Each issuer can specify multiple different DNS01 challenge providers, and
it is also possible to have multiple instances of the same DNS provider on a
single Issuer (e.g. two clouddns accounts could be set, each with their own
name).

#### Supported DNS01 challenge providers

A number of different DNS providers are supported for the ACME issuer. Below is
a listing of them all, with an example block of configuration:

##### Google CloudDNS

```yaml
clouddns:
  serviceAccountSecretRef:
    name: prod-clouddns-svc-acct-secret
    key: service-account.json
```

##### Amazon Route53

```yaml
route53:
  region: eu-west-1

  # optional if ambient credentials are available; see ambient credentials documentation
  accessKeyID: AKIAIOSFODNN7EXAMPLE
  secretAccessKeySecretRef:
    name: prod-route53-credentials-secret
    key: secret-access-key
```

Cert-manager requires the following IAM policy.

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "route53:GetChange",
            "Resource": "arn:aws:route53:::change/*"
        },
        {
            "Effect": "Allow",
            "Action": "route53:ChangeResourceRecordSets",
            "Resource": "arn:aws:route53:::hostedzone/*"
        },
        {
            "Effect": "Allow",
            "Action": "route53:ListHostedZonesByName",
            "Resource": "arn:aws:route53:::hostedzone/*"
        }
    ]
}
```

The `route53:ListHostedZonesByName` statement can be removed if you specify the optional hosted zone ID (`spec.acme.dns01.providers[].hostedZoneID`) on the Issuer resource. You can further tighten this policy by limiting the hosted zone that cert-manager has access to (replace `arn:aws:route53:::hostedzone/*` with `arn:aws:route53:::hostedzone/DIKER8JPL21PSA`, for instance).

##### Cloudflare

```yaml
cloudflare:
  email: my-cloudflare-acc@example.com
  apiKeySecretRef:
    name: cloudflare-api-key-secret
    key: api-key
```

## CA Configuration

CA Issuers issue certificates signed from a X509 signing keypair, stored in a
secret in the Kubernetes API server.
