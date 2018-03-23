# Ambient Credentials

Some API clients are able to infer credentials to use from the environment they
run within. Notably, this includes cloud instance-metadata stores and
environment variables.
In cert manager, the term 'ambient credentials' refers
to such credentials. They are always drawn from the environment of the 'cert-manager-controller' deployment.

## Example Usage

If cert-manager is deployed in an environment with ambient AWS credentials, such as with a [kube2iam](https://github.com/jtblin/kube2iam) role, the following ClusterIssuer would make use of those credentials to perform the ACME dns challenge with route53.

```yaml
apiVersion: certmanager.k8s.io/v1alpha1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v01.api.letsencrypt.org/directory
    email: user@example.com
    privateKeySecretRef:
      name: letsencrypt-prod
    dns01:
      providers:
      - name: route53
        route53:
          region: us-east-1
```

It is important to note that the `route53` section does not specify any `accessKeyID` or `secretAccessKeySecretRef`. If either of these are specified, ambient credentials will not be used.

## When are Ambient Credentials used

Ambient credentials are supported for the 'route53' ACME dns01 provider.

They will only be used if no credentials are supplied, even if the supplied credentials are incorrect.

By default, they may be used by ClusterIssuers, but not regular issuers. The
`--issuer-ambient-credentials` and
`--cluster-issuer-ambient-credentials=false` flags on the cert-manager may be
used to override this behavior.

Note that ambient credentials are disabled for regular Issuers by default to
ensure unprivileged users who may create issuers cannot issue certificates
using any credentials cert-manager incidentally has access to.
