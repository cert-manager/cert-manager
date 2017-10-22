# Deploying cert-manager using Helm

To deploy the latest version of cert-manager using Helm, run:

```
$ helm install --name cert-manager --namespace kube-system contrib/charts/cert-manager
```

By default, it will be configured to fulfil `Certificate` resources in all namespaces. There are a number of options you can customise when deploying, as detailed in [the chart itself](../../contrib/charts/cert-manager).