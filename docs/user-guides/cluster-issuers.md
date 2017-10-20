# Creating cluster wide Issuers

cert-manager has the concept of `ClusterIssuers`. These are a non-namespaced and cluster-scoped version of an `Issuer`. The specification of a `ClusterIssuer` is exactly the same as that of an `Issuer`, but there are a couple of nuances you need to be aware of.

```yaml
apiVersion: certmanager.k8s.io/v1alpha1
kind: ClusterIssuer
metadata:
  name: ca-cluster-issuer
spec:
  ca:
    secretName: ca-key-pair
```

```yaml
apiVersion: certmanager.k8s.io/v1alpha1
kind: ClusterIssuer
metadata:
  name: letsencrypt-staging-cluster-issuer
spec:
  acme:
    server: https://acme-staging.api.letsencrypt.org/directory
    email: user@example.com
    privateKeySecretRef:
      name: letsencrypt-staging
    http01: {}
```

The two manifests above define two `ClusterIssuers`. As `ClusterIssuer` resources do not specify a namespace, we must configure a namespace that cert-manager will use to store supporting resources required for each `ClusterIssuer`. We do this by specifying the `--cluster-resource-namespace` flag on the cert-manager controller. By default, this flag will be set to `kube-system`.

In order to reference a `ClusterIssuer` in a `Certificate` you must specify the `kind` in the `issuerRef` stanza. The following are two examples of `Certificates` that reference our `ClusterIssuers` above.

```yaml
kind: Certificate
metadata:
  name: ca-crt
  namespace: default
spec:
  secretName: ca-crt-secret
  issuerRef:
    name: ca-cluster-issuer
    kind: ClusterIssuer
  dnsNames:
  - cert-manager.k8s.io
```

```yaml
apiVersion: certmanager.k8s.io/v1alpha1
kind: Certificate
metadata:
  name: nginx-k8s-io
  namespace: default
spec:
  secretName: nginx-k8s-io-tls
  issuerRef:
    name: letsencrypt-staging-cluster-issuer
    kind: ClusterIssuer
  commonName: nginx.k8s.io
  acme:
    config:
    - http01: {}
      domains:
      - nginx.k8s.io
```
