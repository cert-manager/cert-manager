# Deploying cert-manager using Helm

The recommended deployment tool for cert-manager is Helm. We ship a Helm chart
with each release that is end-to-end tested in an RBAC enabled environment.

## Deploying with Helm

### Step 0 - setting up and configuring Helm/Tiller

Before deploying cert-manager, you must ensure [Tiller](https://github.com/kubernetes/helm)
is up and running in your cluster. Tiller is the server side component to Helm.

Your cluster administrator may have already setup and configured Helm for you, in which case you can skip this step.

Full documentation on installing Helm can be found [here](https://github.com/kubernetes/helm/blob/master/docs/install.md).

If your cluster has RBAC (Role Based Access Control) enabled (default in GKE v1.7+), you will need to take
special care when deploying Tiller, to ensure Tiller has permission to create
resources as a cluster administrator. More information on deploying Helm with
RBAC can be found [here](https://github.com/kubernetes/helm/blob/master/docs/rbac.md).

### Step 1 - deploying cert-manager

The latest version of cert-manager can be installed from the official Charts repository for Helm:

```bash
$ helm install \
    --name cert-manager \
    --namespace kube-system \
    stable/cert-manager
```

> **NOTE**: If your cluster does not use RBAC (Role Based Access Control), please see the Addendum on disabling creation of RBAC resources.

The default cert-manager configuration is good for the majority of users, but a
full list of the available options can be found in the [Helm chart README](https://github.com/kubernetes/charts/blob/master/stable/cert-manager/README.md).

Next, you will need to configure cert-manager with Issuers and ClusterIssuers.
These represent a 'source' for x509 certificates and will be used later on to
issue certificates.

## Addendum

* disabling creation of RBAC resources

If your cluster does not use RBAC (Role Based Access Control), you should add the following command line flag to your `helm install` command:

```
--set rbac.create=false
```

For cert-manager versions <=0.2.3, the flag to use is as follows:

```
--set rbac.enabled=false
```

All RBAC related resources will not be created in this instance.

* configuring automatic creation of Certificates

To add support for automatically creating Certificates for Ingress resources
with the `kubernetes.io/tls-acme` annotation (similar to [kube-lego](https://github.com/jetstack/kube-lego)),
you should deploy cert-manager with additional flags in order to specify the
Issuer (or ClusterIssuer) responsible for acquiring these certificates. This
can be done by adding the following additional `--set` flag when running
`helm install` (replacing the values accordingly):

```
--set ingressShim.extraArgs='{--default-issuer-name=letsencrypt-prod,--default-issuer-kind=ClusterIssuer}'
```

In the above example, cert-manager will create Certificate resources that reference the ClusterIssuer `letsencrypt-prod` for all Ingresses that have a `kubernetes.io/tls-acme: "true"` annotation.

You can find more information on the ingress-shim (the component responsible
for this) [here](ingress-shim.md).
