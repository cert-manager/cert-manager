# Issuing an ACME certificate using DNS validation

cert-manager can be used to obtain certificates from a CA using the [ACME][1] protocol. The ACME protocol supports various challenge mechanisms which are used to prove ownership of a domain so that a valid certificate can be issued for that domain. One such challenge mechanism is DNS-01. With a DNS-01 challenge, you prove ownership of a domain by proving you control its DNS records. This is done by creating a TXT record with specific content.

The following `Issuer` defines the necessary information to enable DNS validation. You can read more about the `Issuer` resource [here][2].

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
    # ACME DNS-01 provider configurations
    dns01:
      # Here we define a list of DNS-01 providers that can solve DNS challenges
      providers:
      - name: prod-dns
        clouddns:
          # A secretKeyRef to a google cloud json service account
          serviceAccountSecretRef:
            name: clouddns-service-account
            key: service-account.json
          # The project in which to update the DNS zone
          project: gcloud-prod-project
      - name: cf-dns
        cloudflare:
          email: user@example.com
          # A secretKeyRef to a cloudflare api key
          apiKeySecretRef:
            name: cloudflare-api-key
            key: api-key.txt
```

We have specified the ACME server URL for Let's Encrypt's [staging environment][3]. The staging environment will not issue trusted certificates but is used to ensure that the verification process is working properly before moving to production. Let's Encrypt's production environment imposes much stricter [rate limits][4], so to reduce the chance of you hitting those limits it is highly recommended to start by using the staging environment. To move to production, simply create a new `Issuer` with the URL set to `https://acme-v01.api.letsencrypt.org/directory`.

The first stage of the ACME protocol is for the client to register with the ACME server. This phase includes generating an asymmetric key pair which is then associated with the email address specified in the `Issuer`. Make sure to change this email address to a valid one that you own. It is commonly used to send expiry notices when your certificates are coming up for renewal. The generated private key is stored in a `Secret` called `letsencrypt-staging`.

The `dns01` stanza contains a list of DNS-01 providers that can be used to solve DNS challenges. Our `Issuer` defines two providers. This gives us a choice of which one to use when obtaining certificates. More information about the DNS provider configuration, including a list of currently supported providers, can be found [here][5].

Once we have created the above `Issuer` we can use it to obtain a certificate.

```yaml
apiVersion: certmanager.k8s.io/v1alpha1
kind: Certificate
metadata:
  name: example-com
  namespace: default
spec:
  secretName: example-com-tls
  issuerRef:
    name: letsencrypt-staging
  commonName: example.com
  dnsNames:
  - www.example.com
  acme:
    config:
    - dns01:
        provider: prod-dns
      domains:
      - example.com
    - dns01:
        provider: cf-dns
      domains:
      - www.example.com
```

The `Certificate` resource describes our desired certificate and the possible methods that can be used to obtain it. You can learn more about the `Certificate` resource [here][7]. If the certificate is obtained successfully, the resulting key pair will be stored in a secret called `example-com-tls` in the same namespace as the `Certificate`. The certificate will have a common name of `example.com` and the [Subject Alternative Names][6] (SANs) will be `example.com` and `www.example.com`.

In our `Certficate` we have referenced the `letsencrypt-staging` `Issuer` above. The `Issuer` must be in the same namespace as the `Certficate`. If you want to reference a `ClusterIssuer`, which is a cluster-scoped version of an `Issuer`, you must add `kind: ClusterIssuer` to the `issuerRef` stanza. For more information on `ClusterIssuers`, read the [Creating cluster wide Issuers][8] user guide.

The `acme` stanza defines the configuration for our ACME challenges. Here we have defined the configuration for our DNS challenges which will be used to verify domain ownership. For each domain mentioned in a `dns01` stanza, cert-manager will use the provider's credentials from the referenced `Issuer` to create a TXT record called `_acme-challenge`. This record will then be verified by the ACME server in order to issue the certificate. Once domain ownership has been verified, any cert-manager affected records will be cleaned up. Note that it is your responsibility to ensure the provider is authoritative for your domain. 

After creating the above `Certificate`, we can check whether it has been obtained successfully using `kubectl describe`:

```
$ kubectl describe certificate example-com
Events:
  Type     Reason                 Age              From                     Message
  ----     ------                 ----             ----                     -------
  Warning  ErrorCheckCertificate  33s              cert-manager-controller  Error checking existing TLS certificate: secret "example-com-tls" not found
  Normal   PrepareCertificate     33s              cert-manager-controller  Preparing certificate with issuer
  Normal   PresentChallenge       33s              cert-manager-controller  Presenting dns-01 challenge for domain example.com
  Normal   PresentChallenge       33s              cert-manager-controller  Presenting dns-01 challenge for domain www.example.com
  Normal   SelfCheck              32s              cert-manager-controller  Performing self-check for domain example.com
  Normal   SelfCheck              32s              cert-manager-controller  Performing self-check for domain www.example.com
  Normal   ObtainAuthorization    6s               cert-manager-controller  Obtained authorization for domain example.com
  Normal   ObtainAuthorization    6s               cert-manager-controller  Obtained authorization for domain www.example.com
  Normal   IssueCertificate       6s               cert-manager-controller  Issuing certificate...
  Normal   CeritifcateIssued      5s               cert-manager-controller  Certificated issued successfully
```

You can also check whether issuance was successful with `kubectl get secret example-com-tls -o yaml`. You should see a base64 encoded signed TLS key pair.

Once our certificate has been obtained, cert-manager will periodically check its validity and attempt to renew it if it gets close to expiry. cert-manager considers certificates to be close to expiry when the 'Not After' field on the certificate is less than the current time plus 30 days.

  [1]: https://en.wikipedia.org/wiki/Automated_Certificate_Management_Environment
  [2]: ../api-types/issuer/
  [3]: https://letsencrypt.org/docs/staging-environment/
  [4]: https://letsencrypt.org/docs/rate-limits/
  [5]: ../api-types/issuer/spec.md#user-content-acme-issuer-dns-provider-configuration
  [6]: https://en.wikipedia.org/wiki/Subject_Alternative_Name
  [7]: ../api-types/certificate/
  [8]: cluster-issuers.md
