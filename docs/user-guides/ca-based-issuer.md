# Creating a simple CA based issuer

cert-manager can be used to obtain certificates using a signing key pair. There are various tools you can use to generate your own key pair including [openssl][1] and [cfssl][2]. For a quick and basic CA, you can generate a signing key pair using openssl with the following commands:

* `openssl genrsa -out ca.key 2048`
* `openssl req -x509 -new -nodes -key ca.key -subj "/CN=${COMMON_NAME}" -days 3650 -out ca.crt`

The output of these commands will be two files, `ca.key` and `ca.crt`, the key and certificate for your signing key pair.

We are going to create an `Issuer` that will use this key pair to generate signed certificates. You can read more about the `Issuer` resource [here][3]. To allow the `Issuer` to reference our key pair we need to put it into a `Secret`. `Issuers` are namespaced resources and can only reference and create `Secrets` in their own namespace, so we will need to make sure to put our key pair `Secret` into the same namespace as our `Issuer`. We could alternatively create a `ClusterIssuer`, a cluster-scoped version of an `Issuer`. For more information on `ClusterIssuers`, read the [Creating cluster wide Issuers][6] user guide.

The following command will create a `Secret` containing our signing key pair in the default namespace.

```bash
$ kubectl create secret tls ca-key-pair --cert=/path/to/ca.crt --key=/path/to/ca.key --namespace default
```

We can now create an `Issuer` referencing our `Secret`.

```yaml
apiVersion: certmanager.k8s.io/v1alpha1
kind: Issuer
metadata:
  name: ca-issuer
  namespace: default
spec:
  ca:
    secretName: ca-key-pair
```

We are now ready to obtain certificates. We can create the following `Certificate` resource which specifies our desired certificate. You can read more about the `Certificate` resource [here][4]. Note that to use our `Issuer` above to obtain our certificate, we must create the `Certificate` resource in the same namespace as our `Issuer`.

```yaml
apiVersion: certmanager.k8s.io/v1alpha1
kind: Certificate
metadata:
  name: example-com
  namespace: default
spec:
  secretName: example-com-tls
  issuerRef:
    name: ca-issuer
    # We can reference ClusterIssuers by changing the kind here.
    # The default value is Issuer (i.e. a locally namespaced Issuer)
    kind: Issuer
  commonName: example.com
  dnsNames:
  - www.example.com
```

Once we have created the `Certificate` resource, cert-manager will attempt to use our `ca-issuer` to obtain a certificate. If successful, the certificate will be stored in a `Secret` called `example-com-tls` in the default namespace. Note that since we have specified the `commonName` then `example.com` will be the common name for our certificate and both the common name and all the elements of the `dnsNames` array will be [Subject Alternative Names][5] (SANs). If we had not specified the common name then the first element of the `dnsNames` array would be used as the common name and all elements of the `dnsNames` array would be SANs.

Note that since we have not specified the `commonName` on the `Certificate`, the first element of the `dnsNames` array will be used as the common name and all elements of the `dnsNames` array will be [Subject Alternative Names][5] (SANs). If we had specified the `commonName`, then the `commonName` and all the elements of the `dnsNames` array would be SANs.

After creating the above `Certificate`, we can check whether it has been obtained successfully using `kubectl describe`:

```
$ kubectl describe certificate example-com
Events:
  Type     Reason                 Age              From                     Message
  ----     ------                 ----             ----                     -------
  Warning  ErrorCheckCertificate  26s              cert-manager-controller  Error checking existing TLS certificate: secret "example-com-tls" not found
  Normal   PrepareCertificate     26s              cert-manager-controller  Preparing certificate with issuer
  Normal   IssueCertificate       26s              cert-manager-controller  Issuing certificate...
  Normal   CeritifcateIssued      25s              cert-manager-controller  Certificated issued successfully
```

You can also check whether issuance was successful with `kubectl get secret example-com-tls -o yaml`. You should see a base64 encoded signed TLS key pair.

Once our certificate has been obtained, cert-manager will keep checking its validity and attempt to renew it if it gets close to expiry. cert-manager considers certificates to be close to expiry when the 'Not After' field on the certificate is less than the current time plus 30 days. For CA based `Issuers`, cert-manager will issue certificates with the 'Not After' field set to the current time plus 365 days.

  [1]: https://github.com/openssl/openssl
  [2]: https://github.com/cloudflare/cfssl
  [3]: ../api-types/issuer/
  [4]: ../api-types/certificate/
  [5]: https://en.wikipedia.org/wiki/Subject_Alternative_Name
  [6]: cluster-issuers.md