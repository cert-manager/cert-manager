# Cert-Manager NGINX Ingress Quick-Start Guide

## Step -1 - Install Helm Client
**Skip this section if you have `helm` installed.**

The easiest way to install `cert-manager` is to use [Helm](https://github.com/kubernetes/helm), a templating and deployment system for Kubernetes resources.

Firstly, ensure you have the Helm client installed by following [its installation instructions](https://github.com/kubernetes/helm/blob/master/docs/install.md).

For example, on Mac OS X:
```bash
$ brew install kubernetes-helm
```


## Step 0 - Installer Tiller
**Skip this section if you have Tiller set-up.**

Tiller is Helm's server-side component, which the `helm` client uses to deploy resources.

Deploying resources is a privileged operation; in the general case requiring arbitrary privileges. As a convenience, we will give Tiller complete control of the cluster. Do not run with this configuration in production.

Create the RBAC resources.

```bash
$ kubectl create serviceaccount tiller --namespace=kube-system
$ kubectl create clusterrolebinding tiller-admin --serviceaccount=kube-system:tiller --clusterrole=cluster-admin
```

Now install the Tiller component.

```bash
$ helm init --service-account=tiller
```

*If you'd like to read more, full documentation is available on [installing Tiller](https://github.com/kubernetes/helm/blob/master/docs/install.md) and [RBAC configuration](https://github.com/kubernetes/helm/blob/master/docs/rbac.md).*


## Step 1 - Deploy the NGINX Ingress Controller
### Create a namespace
```bash
$ kubectl apply -f nginx/00-namespace.yaml
```

### Create a default backend
Used for all requests that don't match any Ingress resource

```bash
$ kubectl apply -f nginx/default-deployment.yaml
$ kubectl apply -f nginx/default-service.yaml
```

### Create the NGINX ingress controller
```bash
$ kubectl apply -f nginx/rbac.yaml
$ kubectl apply -f nginx/configmap.yaml
$ kubectl apply -f nginx/service.yaml
$ kubectl apply -f nginx/deployment.yaml
```

The `nginx` ingress controller service is the only one which is made available outside the cluster, as it handles all incoming traffic. It does this via a load balancer in your cloud provider. A few minutes after you've created the `nginx` Service, get its public IP or domain name via `kubectl`.

```bash
$ kubectl describe svc nginx --namespace nginx-ingress
[...]
LoadBalancer Ingress:   1.2.3.4
[...]
```

This is the IP to which all incoming traffic should be routed, so add it to a DNS zone you control, e.g. as `echo.example.com`. AWS will give a domain name instead; in this case CNAME your name to that name.


## Step 2 - Deploy an Example Service (Echoserver)
```bash
$ kubectl apply -f echoserver/00-namespace.yaml
$ kubectl apply -f echoserver/deployment.yaml
$ kubectl apply -f echoserver/service.yaml
```

We will first create an Ingress resource that listens on plain HTTP.

```bash
$ kubectl apply -f echoserver/ingress-notls.yaml
```

Now make sure the echo service is reachable at the domain name you added above, e.g. http://echo.example.com.


## Step 3 - Deploy Cert Manager
```bash
$ helm install --name cert-manager --namespace kube-system stable/cert-manager
```

## Step 4 - Configure Letsentrypt Issuer

With cert manager running, we must tell it about a service it can use to issue certificates for us. In this case we will configure letsencrypt. NB: the following code sets up letsencrypt "production". This will issue valid certificates but has a strict rate limit. If you are having difficulty and failing to get certificates, [switch this for letsencrypt's "staging" issuer](https://github.com/jetstack/cert-manager/blob/master/docs/user-guides/acme-http-validation.md) while you debug, otherwise you will hit the rolling 7 day rate limit.

Substitute your own email address in the definition below and apply to your cluster.

```yaml
apiVersion: certmanager.k8s.io/v1alpha1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    # The ACME server URL
    server: https://acme-v01.api.letsencrypt.org/directory
    # Email address used for ACME registration
    email: user@example.com
    # Name of a secret used to store the ACME account private key
    privateKeySecretRef:
      name: letsencrypt-prod-key
    # Enable the HTTP-01 challenge provider
    http01: {}
```

## Step 5 - Deploy a TLS Ingress Resource for the Echoserver
We will now update the Ingress resource to listen on HTTPS and use a TLS certificate stored in a named secret. Cert manager will notice this change to the Ingress resource and generate the certificate for us automatically.

Edit `echoserver/ingress-tls.yaml` to replace `echo.example.com` with your DNS name. While the previous, non-TLS, Ingress resource definition was simply configured to accept requests with any `host` header, TLS Ingress resources need to know which SNI header values to match, and `cert-manager` uses the same field as the CN in the issued certificate.

Note how this updated Ingress resource uses an annotation to tell `cert-manager` to use the issuer previously defined to get a TLS certificate for this Ingress resource. The mere presence of this annotation key tells `cert-manager` to generate a certificate for this Ingress. It is generated for the domain name specified in the `tls` part of the Ingress spec, and stored in the secret named there.

```bash
$ kubectl apply -f echoserver/ingress-tls.yaml
```

The echo server should now be available over TLS at e.g. https://echo.example.com.

*This example could have been done manually using cert manager's `Issuer` and `Certificate` resources. However, issuing Ingress TLS certificates is such a common use-case that cert manager comes with an "ingress shim" which spots Ingress objects requesting TLS certificates and automatically issues them using the specified provider. The ingress shim is what powered this example. Cert manager is a flexible, general-purpose certificate manager, and this is only a fraction of its potential.*
