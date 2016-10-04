# kube-lego

*kube-lego* automatically requests certificates for Kubernetes Ingress resources from Let's Encrypt

[![Build Status](https://travis-ci.org/jetstack/kube-lego.svg?branch=master)](https://travis-ci.org/jetstack/kube-lego)
[![](https://images.microbadger.com/badges/version/jetstack/kube-lego.svg)](http://microbadger.com/#/images/jetstack/kube-lego "Get your own version badge on microbadger.com")

## Screencast

[![Kube Lego screencast](https://asciinema.org/a/47444.png)](https://asciinema.org/a/47444)

## Features

- Recognizes the need of a new certificate for this cases:
  - No certificate existing
  - Existing certificate is not containing all domain names
  - Existing certificate is expired or near to it's expiry date (cf. option `LEGO_MINIMUM_VALIDITY`)
  - Existing certificate is unparseable, invalid or not matching the secret key
- Creates a user account (incl. private key) for Let's Encrypt and stores it in Kubernetes secrets (secret name is configurable via `LEGO_SECRET_NAME`)
- Obtains the missing certificates from Let's Encrypt and authorizes the request with the `HTTP-01` challenge
- Makes sure that the specific Kubernetes objects (Services, Ingress) contain the rights configuration for the `HTTP-01` challenge to succeed

## Requirements

- Kubernetes 1.2+
- Compatible ingress controller (nginx or GCE see [here](#ingress))
- Non-production use case :laughing:

## Usage

### run kube-lego

- [deployment](examples/gce/50-kube-lego-deployment.yaml) for *kube-lego*
  - don't forget to configure
     - `LEGO_EMAIL` with your mail address
     - `LEGO_POD_IP` with the pod IP address using the downward API
  - the default value of `LEGO_URL` is the Let's Encrypt **staging environment**. If you want to get "real" certificates you have to configure their production env.

### how kube-lego works

As soon as the kube-lego daemon is running, it will look for ingress resources that have this annotations:

```yaml
metadata:
  annotations:
    kubernetes.io/tls-acme: "true"
```

Every ingress resource that has this annotations will be monitored by *kube-lego* (cluster-wide in all namespaces). The only part that is watched is the list `spec.tls`. Every element will get their own certificate through Let's encrypt.

Let's take a look at this ingress resource:

```yaml
spec:
  tls:
  - secretName: mysql-tls
    hosts:
    - phpmyadmin.example.com
    - mysql.example.com
  - secretName: postgres-tls
    hosts:
    - postgres.example.com
```

*kube-lego* will obtain two certificates (one with phpmyadmin.example.com and mysql.example.com, the other with postgers.example.com). Please note:

- The `secretName` statements have to be unique per namespace
- `secretName` is required (even if no secret exists with that name, as it will be created by *kube-lego*)


##<a name="ingress"></a>Ingress controllers

### [Nginx Ingress Controller](https://github.com/kubernetes/contrib/tree/master/ingress/controllers/nginx)

- available through image `gcr.io/google_containers/nginx-ingress-controller`
- fully supports kube-lego from version 0.8 onwards

### [GCE Loadbalancers](https://github.com/kubernetes/contrib/tree/master/ingress/controllers/gce)

- you don't have to maintain the ingress controller yourself, you pay GCE to do that for you
- every ingress resource creates one GCE load balancer
- all service that you want to expose, have to be `Type=NodePort`

## Environment variables

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `LEGO_EMAIL` | y | `-` | E-Mail address for the ACME account, used to recover from lost secrets |
| `LEGO_POD_IP` | y | `-` | Pod IP address (use the [downward API](http://kubernetes.io/docs/user-guide/downward-api/))|
| `LEGO_NAMESPACE` | n | `default` | Namespace where kube-lego is running in |
| `LEGO_URL` | n | `https://acme-staging.api.letsencrypt.org/directory` | URL for the ACME server |
| `LEGO_SECRET_NAME` | n | `kube-lego-account` | Name of the secret in the same namespace that contains ACME account secret |
| `LEGO_SERVICE_NAME_NGINX` | n | `kube-lego-nginx` | Service name for NGINX ingress |
| `LEGO_SERVICE_NAME_GCE` | n | `kube-lego-gce` | Service name for GCE ingress |
| `LEGO_INGRESS_NAME_NGINX` | n | `kube-lego-nginx` | Ingress name which contains the routing for HTTP verification for nginx ingress |
| `LEGO_PORT` | n | `8080` | Port where this daemon is listening for verifcation calls (HTTP method)|
| `LEGO_CHECK_INTERVAL` | n | `8h` | Interval for periodically certificate checks (to find expired certs)|
| `LEGO_MINIMUM_VALIDITY` | n | `720h` (30 days) | Request a renewal when the remaining certificate validitiy falls below that value|
| `LEGO_DEFAULT_INGRESS_CLASS` | n | `nginx` | Default ingress class for resources without specification|
| `LEGO_KUBE_API_URL` | n | `http://127.0.0.1:8080` | API server URL |
| `LEGO_LOG_LEVEL` | n | `info` | Set log level (`debug|info|warn|error`) |


## Full deployment examples

- [Nginx Ingress Controller](examples/nginx/README.md)
- [GCE Load Balancers](examples/gce/README.md)

## Authors

Christian Simon for [Jetstack Ltd](http://www.jetstack.io)
