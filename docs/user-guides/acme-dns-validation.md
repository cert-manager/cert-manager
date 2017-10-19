# Issuing an ACME certificate using DNS validation

`cert-manager` can be used to obtain certificates from a CA using the [ACME][1] protocol. The ACME protocol supports various challenges which are used to prove ownership of a domain so that a valid certificate can be issued for that domain. One such challenge is `dns-01`. With the DNS challenge, you prove you own the DNS records of the domain by creating a TXT record with specific content.

The following `Issuer` defines the necessary information to enable DNS validation. You can read more about the `Issuer` resource [here][5].

```yaml
apiVersion: certmanager.k8s.io/v1alpha1
kind: Issuer
metadata:
  name: letsencrypt-staging
  namespace: default
spec:
  acme:
    # The ACME server URL
    server: https://acme-staging.api.letsencrypt.org/directory
    # Email address used for ACME registration
    email: user@example.com
    # Name of a secret used to store the ACME account private key
    privateKeySecretRef:
      name: letsencrypt-staging
    # ACME dns-01 provider configurations
    dns01:
      # Here we define a list of DNS-01 providers that can solve DNS challenges
      providers:
      - name: prod-dns
        clouddns:
          # A secretKeyRef to a the google cloud json service account
          serviceAccountSecretRef:
            name: clouddns-service-account
            key: service-account.json
          # The project in which to update the DNS zone
          project: gcloud-prod-project
      - name: cf-dns
        cloudflare:
          email: user@example.com
          # A secretKeyRef to a the google cloud json service account
          apiKeySecretRef:
            name: cloudflare-api-key
            key: api-key.txt
```

We have specified the ACME server URL for Let's Encrypt's [staging environment][2]. The staging environment will not issue trusted certificates but is used to ensure that the verification process is working properly before moving to production. Let's Encrypt's production environment imposes much stricter [rate limits][3], so to reduce the chance of you hitting those limits it is highly recommended to start by using the staging environment. To move to production simply change the URL to `https://acme-v01.api.letsencrypt.org/directory`.

The first stage of ACME is for the client to register with the ACME server. This phase includes generating an asymmetric key pair which is then associated with the email address specified in the `Issuer`. Depending on the CA, this could be used to send expiry notices when your certificates are coming up for renewal. The generated private key is stored in a `Secret` called `letsencrypt-staging`.

The `http01` field simply enables the HTTP challenge for this `Issuer`. No further configuration is necessary or possible.

Once we have created the above `Issuer` we can use it to obtain a certificate.

```yaml
apiVersion: certmanager.k8s.io/v1alpha1
kind: Certificate
metadata:
  name: nginx-k8s-io
  namespace: default
spec:
  secretName: nginx-k8s-io-tls
  issuerRef:
    name: letsencrypt-staging
  commonName: nginx.k8s.io
  dnsNames:
  - nginx2.k8s.io
  - nginx3.k8s.io
  acme:
    config:
    - http01:
        ingressClass: nginx
      domains:
      - nginx.k8s.io
    - http01:
        ingress: my-ingress
      domains:
      - nginx2.k8s.io
      - nginx3.k8s.io
```

The `Certificate` resource describes our desired certificate and the possible methods that can be used to obtain it. You can learn more about the `Certificate` resource [here][4]. If the certificate is obtained successfully the resulting key pair will be stored in a secret called `nginx-k8s-io-tls` in the same namespace as the `Certificate`. The certificate will have a common name of `nginx.k8s.io` and the [Subject Alternative Names][6] (SANs) will be `nginx.k8s.io`, `nginx2.k8s.io` and `nginx3.k8s.io`.

In our `Certficate` we have referenced the `letsencrypt-staging` `Issuer` above. The `Issuer` must be in the same namespace as the `Certficate`. If you want to reference a `ClusterIssuer`, which is a cluster-scoped version of an `Issuer`, you must add `kind: ClusterIssuer` to the `issuerRef` stanza.

The `acme` stanza defines the configuration for our ACME challenges. Here we have defined the configuration for our HTTP challenges which will be used to validate our domains. For each domain mentioned in an `http01` stanza, `cert-manager` will create a `Pod` that exposes an HTTP endpoint that satisfies the HTTP challenge. For each `http01` stanza, `cert-manager` will create an `Ingress` resource in the same namespace as the `Certificate` with the correct rules to route incoming challenge requests to the `Pods` corresponding to the domains in that stanza. You can control the name of the `Ingress` resource by setting the `ingress` field. If an `Ingress` resource with that name already exists, `cert-manager` will modify it with the correct rules. 

You can also control the value of the `kubernetes.io/ingress.class` annotation by setting the `ingressClass` field. This will allow you to configure which ingress controller will actually act on these `Ingress` resources. Note that it is your responsibilty to point each domain name at the correct IP address.

Once our certificate has been obtained, `cert-manager` will keep checking its validity and attempt to renew it if it gets close to expiry. `cert-manager` considers certificates to be close to expiry when the 'Not After' field on the certificate is less than the current time plus 30 days.

Once we delete our `Certificate` resource, any `cert-manager` affected resources will be cleaned up or deleted.

  [1]: https://en.wikipedia.org/wiki/Automated_Certificate_Management_Environment
  [2]: https://letsencrypt.org/docs/staging-environment/
  [3]: https://letsencrypt.org/docs/rate-limits/
  [4]: ../api-types/certificate/
  [5]: ../api-types/issuer/
  [6]: https://en.wikipedia.org/wiki/Subject_Alternative_Name