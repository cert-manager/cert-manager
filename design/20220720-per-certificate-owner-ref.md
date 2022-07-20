# Design: Per-Certificate Secret Owner Reference

> 🌟 This design document was written by Maël Valais on 20 July 2022 in order to facilitate Denis Romanenko's feature request presented in [#5158](https://github.com/cert-manager/cert-manager/pull/5158).

cert-manager has the ability to set the owner reference field in generated Secret resources. The option is global, and takes the form of the flag `--enable-certificate-owner-ref` set in the cert-manager controller Deployment resource.

Let us take an example of Certificate resource:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: cert-1
  namespace: ns-1
  uid: 1e0adf8
spec:
  secretRef: cert-1
```

When `--enable-certificate-owner-ref` is passed to the cert-manager controller, when issuing the X.509 certificate, cert-manager will create a Secret resource that looks like this:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: cert-1
  namespace: ns-1
  ownerReferences:
    - controller: true
      blockOwnerDeletion: false
      uid: 1e0adf8
      name: cert-1
      kind: Certificate
      apiVersion: cert-manager.io/v1
data:
  tls.crt: "..."
  tls.key: "..."
  ca.crt: "..."
```

The proposition is to add a new field `certificateOwnerRef` to the Certificate resource:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
spec:
  secretRef: cert-1
  certificateOwnerRef: true  # ✨
```

It has three possible values:

1. When "empty", the behavior will default to not creating an owner reference on the Secret resource, unless `--enable-certificate-owner-ref` is passed.
2. When `true`, the default behavior as described in the "empty" case is overridden and the owner reference is always created on the Secret resource.
3. When `false`, the default behavior as described in the "empty" case is overridden and the owner reference is never created on the Secret resource.

> **⁉️ Question:** the field name `certificateOwnerRef` does not reflect the behavior that it aims to enable. A more appropriate, less confusing name could be found, e.g., `deleteSecretUponDeletion`.

## Use-cases

Flant manages certificates for users, and has hit a Kubernetes apiserver limitation where too many left-over Secret resources were slowing the apiserver down. This issue has happened because Certificate resources are created using auto-generated names, and Certificate resources are often deleted shortly after being created.

