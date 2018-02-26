# Migrating from kube-lego

[kube-lego](https://github.com/jetstack/kube-lego) is an older Jetstack project
for obtaining TLS certificates from Let's Encrypt (or another ACME server).

Since cert-managers release, kube-lego has been gradually deprecated in favour
of this project. There are a number of key differences between the two:

|           | kube-lego | cert-manager |
| --------- | --------- | ------------ |
| Configuration | Annotations on Ingress resources | CRDs |
| CAs | ACME **only** | ACME, signing keypair |
| Kubernetes | v1.2 - v1.8 | v1.7+ (v1.6+ after [#201](https://github.com/jetstack/cert-manager/issues/201)) |
| Debugging | Look at logs | Kubernetes Events API |
| Multi-tenancy | Not supported | Supported |
| Distinct issuance sources per Certificate | Not supported | Supported |
| Ingress controller support (ACME) | GCE, nginx | All |

This guide will walk through how you can safely migrate your kube-lego installation to cert-manager, without service interruption.

By the end of the guide, we should have:

* Scaled down and removed kube-lego
* Installed cert-manager
* Migrated ACME private key to cert-manager
* Created an ACME ClusterIssuer using this private key, to issue certificates
throughout your cluster
* Configured cert-manager's [ingress-shim](ingress-shim.md) to automatically
provision Certificate resources for all Ingress resources with the
`kubernetes.io/tls-acme: "true"` annotation, using the ClusterIssuer we have
created

## Step 1 - scale down kube-lego

Before we begin deploying cert-manager, it is best we scale our kube-lego deployment down to 0 replicas. This will prevent the two controllers potentially 'fighting' each other. If you deployed kube-lego using the official deployment YAMLs, a command like so should do:

```bash
$ kubectl scale \
    --namespace kube-lego \
    --replicas=0 \
    deployment kube-lego
```

You can then verify your kube-lego pod is no longer running with:

```bash
$ kubectl get pods --namespace kube-lego
```

## Step 2 - deploy cert-manager

cert-manager should be deployed using Helm, according to our official
[deploying.md](deploying.md) guide. No special steps are required here. We will
return to this deployment at the end of this guide and perform an upgrade of
some of the CLI flags we deploy cert-manager with however.

Please take extra care to ensure you have configured RBAC correctly when
deploying Helm and cert-manager - there are some nuances described in our
deploying document!

## Step 3 - obtaining your ACME account private key

In order to continue issuing and renewing certificates on your behalf, we need
to migrate the user account private key that kube-lego has created for you over
to cert-manager.

Your ACME user account identity is a private key, stored in a secret resource.
By default, kube-lego will store this key in a secret named `kube-lego-account`
in the same namespace as your kube-lego Deployment. You may have overridden
this value when you deploy kube-lego, in which case the secret name to use will
be the value of the `LEGO_SECRET_NAME` environment variable.

You should download a copy of this secret resource and save it in your local
directory:

```bash
$ kubectl get secret \
    -o yaml \
    --namespace kube-lego \
    --export \
    kube-lego-account > kube-lego-account.yaml
```

Once saved, open up this file and change the `metadata.name` field to something
more relevant to cert-manager. For the rest of this guide, we'll assume you
chose `letsencrypt-private-key`.

Once done, we need to create this new resource in the `kube-system` namespace.
This is where cert-manager looks for supporting resources for ClusterIssuers
by default:

```bash
$ kubectl create \
    --namespace kube-system \
    -f kube-lego-account.yaml
```

## Step 4 - creating an ACME ClusterIssuer using your old ACME account

We need to create a ClusterIssuer which will hold information about the ACME
account previously registered via kube-lego. In order to do so, we need two
more pieces of information from our old kube-lego deployment: the server URL of
the ACME server, and the email address used to register the account.

Both of these bits of information are stored within the kube-lego ConfigMap.

To retrieve them, you should be able to `get` the ConfigMap using `kubectl`:

```bash
$ kubectl get configmap \
    -o yaml \
    --namespace kube-lego \
    --export \
    kube-lego
```

Your email address should be shown under the `.data.lego.email` field, and the
ACME server URL under `.data.lego.url`.

For the purposes of this guide, we will assume the lego email is
`user@example.com` and the URL `https://acme-staging.api.letsencrypt.org/directory`.

Now that we have migrated our private key to the new Secret resource, as well
as obtaining our ACME email address and URL, we can create a ClusterIssuer
resource!

Create a file named cluster-issuer.yaml:

```yaml
apiVersion: certmanager.k8s.io/v1alpha1
kind: ClusterIssuer
metadata:
  # Adjust the name here accordingly
  name: letsencrypt-staging
spec:
  acme:
    # The ACME server URL
    server: https://acme-staging.api.letsencrypt.org/directory
    # Email address used for ACME registration
    email: user@example.com
    # Name of a secret used to store the ACME account private key from step 3
    privateKeySecretRef:
      name: letsencrypt-private-key
    # Enable the HTTP-01 challenge provider
    http01: {}
```

We then submit this file to our Kubernetes cluster:

```bash
$ kubectl create -f cluster-issuer.yaml
```

You should be able to verify the ACME account has been verified successfully:

```bash
$ kubectl describe clusterissuer letsencrypt-staging
Name:         letsencrypt-staging
Namespace:
Labels:       <none>
Annotations:  <none>
API Version:  certmanager.k8s.io/v1alpha1
Kind:         ClusterIssuer
Metadata:
  Cluster Name:
  Creation Timestamp:  2017-11-30T22:33:40Z
  Generation:          0
  Resource Version:    4450170
  Self Link:           /apis/certmanager.k8s.io/v1alpha1/letsencrypt-staging
  UID:                 83d04e6b-d61e-11e7-ac26-42010a840044
Spec:
  Acme:
    Email:  user@example.com
    Http 01:
    Private Key Secret Ref:
      Key:
      Name:  letsencrypt-private-key
    Server:  https://acme-staging.api.letsencrypt.org/directory
Status:
  Acme:
    Uri:  https://acme-staging.api.letsencrypt.org/acme/reg/5160358
  Conditions:
    Last Transition Time:  2017-11-30T22:33:41Z
    Message:               The ACME account was registered with the ACME server
    Reason:                ACMEAccountRegistered
    Status:                True
    Type:                  Ready
```

## Step 5 - configuring ingress-shim to use our new ClusterIssuer by default

Now that our ClusterIssuer is ready to issue certificates, we have one last
thing to do: we must reconfigure ingress-shim (deployed as part of
cert-manager) to automatically create Certificate resources for all Ingress
resources it finds with appropriate annotations.

More information on the role of ingress-shim can be found
[in the docs](ingress-shim.md), but for now we can just run a `helm upgrade`
in order to add a few additional flags. Assuming you've named your
ClusterIssuer `letsencrypt-staging` (as above), run:

```bash
helm upgrade \
    cert-manager \
    stable/cert-manager \
    --namespace kube-system \
    --set ingressShim.extraArgs='{--default-issuer-name=letsencrypt-staging,--default-issuer-kind=ClusterIssuer}'
```

You should see the cert-manager pod be re-created, and once started it should
automatically create Certificate resources for all of your ingresses that
previously had kube-lego enabled.

## Step 6 - verify each ingress now has a corresponding Certificate

Before we finish, we should make sure there is now a Certificate resource for
each ingress resource you previously enabled kube-lego on.

You should be able to check this by running:

```
$ kubectl get certificates --all-namespaces
```

There should be an entry for each ingress in your cluster with the kube-lego
annotation.

We can also verify that cert-manager has 'adopted' the old TLS certificates by
'describing' one of these newly created certificates:

```
$ kubectl describe certificate my-example-certificate
...
Events:
  Type    Reason            Age                 From                     Message
  ----    ------            ----                ----                     -------
  Normal  RenewalScheduled  1m                  cert-manager-controller  Certificate scheduled for renewal in 292 hours
```

Here we can see cert-manager has verified the existing TLS certificate and
scheduled it to be renewed in 292h time.
