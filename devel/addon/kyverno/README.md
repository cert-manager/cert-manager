# README

The `policy.yaml` file is generated using `kustomize`.

```sh
kustomize build . > policy.yaml
```

Kustomize is used to adapt the upstream Pod security policy for use in the cert-manager namespace.
We change `ClusterPolicy` resources to namespaced `Policy`.

We can't apply the upstream policy because it installs `ClusterPolicy` resources,
which affect all namespaces.
This breaks almost all of the other E2E addons (bind, pebble, etc) which do not meet the policy requirements.

The compromise is to install `Policy` resources in the cert-manager namespace,
which verifies that the cert-manager Pods adhere to the policy.
This includes ACME HTTP-01 solver Pods, but only those associated with a `ClusterIssuer`,
because these are created in the cert-manager namespace during E2E tests.
