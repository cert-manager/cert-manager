# kube-lego

*kube-lego* automatically requests certificates for Kubernetes Ingress resources from Let's Encrypt

[![Build Status](https://travis-ci.org/jetstack/kube-lego.svg?branch=master)](https://travis-ci.org/jetstack/kube-lego)

## Screencast

[![Kube Lego screencast](https://asciinema.org/a/47444.png)](https://asciinema.org/a/47444)

## Features

- Recognizes the need of new certificates for this cases
  - domain name missing
  - certificate expired
  - certificate unparseable
- Obtains certificates per TLS object in ingress resources and stores it in Kubernetes secrets using `HTTP-01` challenge
- Creates a user account (incl. private key) for Let's Encrypt and stores it in Kubernetes secrets (secret name is configurable via `LEGO_SECRET_NAME`)
- Watches changes of ingress resources and reevaluate certificates
- Configures endpoints for `HTTP-01` challenge in a separate ingress resource (ingress name is configurable in `LEGO_INGRESS_NAME`)

## Requirements

- Kubernetes 1.2+
- Compatible ingress controller (cf. [here](#ingress))
- Non-production use case :laughing:

## Usage

### run kube-lego

- [deployment](examples/kube-lego-deployment.yaml) for *kube-lego*
  - don't forget to configure `LEGO_EMAIL` with your mail address
  - the default value of `LEGO_URL` is the Let's Encrypt staging environment. If you want to get "real" certificates you have to configure their production env.
- [service](examples/kube-lego-svc.yaml) pointing to *kube-lego* pods

### how kube-lego works

As soon as the kube-lego daemon is running, it will look for ingress resources that have this annotations:

```yaml
metadata:
  annotations:
    kubernetes.io/tls-acme: "true"
```

Every ingress resource that has this annotations will be monitored by *kube-lego* (cluster-wide in all namespaces). The only part that is watched is the list `spec.tls`. Every element will get their own certificate through Let's encrypt.

Let's take a look at this ingress controller:

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

###

##<a name="ingress"></a>Ingress controllers

### [Nginx Ingress Controller](https://github.com/kubernetes/contrib/tree/master/ingress/controllers/nginx)

- available through image `gcr.io/google_containers/nginx-ingress-controller`
- fully supports kube-lego from version 0.8

## Environment variables

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `LEGO_EMAIL` | y | `-` | E-Mail address for the ACME account, used to recover from lost secrets |
| `LEGO_NAMESPACE` | n | `default` | Namespace where kube-lego is running in |
| `LEGO_URL` | n | `https://acme-staging.api.letsencrypt.org/directory` | URL for the ACME server |
| `LEGO_SECRET_NAME` | n | `kube-lego-account` | Name of the secret in the same namespace that contains ACME account secret |
| `LEGO_SERVICE_NAME` | n | `kube-lego` | Service name that connects to this pod |
| `LEGO_INGRESS_NAME` | n | `kube-lego` | Ingress name which contains the routing for HTTP verification |
| `LEGO_PORT` | n | `8080` | Port where this daemon is listening for verifcation calls (HTTP method)|
| `LEGO_CHECK_INTERVAL` | n | `8h` | Interval for periodically certificate checks (to find expired certs)|


## Full example

See the [examples](examples/README.md) directory.

## Authors

Christian Simon for [Jetstack Ltd](http://www.jetstack.io)
