# README

The `policy.yaml` file is generated using `kustomize`.

```sh
kustomize build . > policy.yaml
```

Kustomize is used to adapt the upstream Pod security policy for use in the cert-manager namespace.
We change `ClusterPolicy` resources to namespaced `Policy`.
