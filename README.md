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
  - Existing certificate is expired or near to its expiry date (cf. option `LEGO_MINIMUM_VALIDITY`)
  - Existing certificate is unparseable, invalid or not matching the secret key
- Creates a user account (incl. private key) for Let's Encrypt and stores it in Kubernetes secrets (secret name is configurable via `LEGO_SECRET_NAME`)
- Obtains the missing certificates from Let's Encrypt and authorizes the request with the `HTTP-01` challenge
- Makes sure that the specific Kubernetes objects (Services, Ingress) contain the rights configuration for the `HTTP-01` challenge to succeed
- Official Kubernetes Helm [chart](https://github.com/kubernetes/charts/tree/master/stable/kube-lego) for simplistic deployment.

## Requirements

- Kubernetes 1.2+
- Compatible ingress controller (nginx or GCE see [here](#ingress-controllers))
- Non-production use case :laughing:

## Usage

### run kube-lego

* [GCE](examples/gce/README.md)
* [nginx controller](examples/nginx/README.md)

The default value of `LEGO_URL` is the Let's Encrypt **staging environment**. If you want to get "real" certificates you have to configure their production env.

If you change the `LEGO_URL`, it is required that you delete the existing secret `kube-lego-account` and all certificates you want to request from the new URL.

### how kube-lego works

As soon as the kube-lego daemon is running, it will create a user account with LetsEncrypt, make a service resource, and look for ingress resources that have this annotation:

```yaml
metadata:
  annotations:
    kubernetes.io/tls-acme: "true"
```

Every ingress resource that has this annotation will be monitored by *kube-lego* (cluster-wide in all namespaces). The only part that is watched is the list `spec.tls`. Every element will get its own certificate through Let's Encrypt.

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

On finding the above resource, the following happens:

1. An ingress resource is created coordinating where to send acme challenges for the said domains.

2. *kube-lego* will then perform its own check for i.e. `http://mysql.example.com/.well-known/acme-challenge/_selftest` to ensure all is well before reaching out to letsencrypt.

3. *kube-lego* will obtain two certificates (one with phpmyadmin.example.com and mysql.example.com, the other with postgres.example.com).


Please note:

- The `secretName` statements have to be unique per namespace
- `secretName` is required (even if no secret exists with that name, as it will be created by *kube-lego*)
- Setups which utilize 1:1 NAT need to ensure internal resources can reach gateway controlled public addresses.
- Additionally, your domain must point to your externally available Load Balancer (either directly or via 1:1 NAT)


## Ingress controllers

### [Nginx Ingress Controller](https://github.com/kubernetes/ingress/tree/master/controllers/nginx)

- available through image `gcr.io/google_containers/nginx-ingress-controller`
- fully supports kube-lego from version 0.8 onwards

### [GCE Loadbalancers](https://github.com/kubernetes/ingress/tree/master/controllers/gce)

- you don't have to maintain the ingress controller yourself, you pay GCE to do that for you
- every ingress resource creates one GCE load balancer
- all service that you want to expose, have to be `Type=NodePort`

## Environment variables

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `LEGO_EMAIL` | y | `-` | E-Mail address for the ACME account, used to recover from lost secrets |
| `LEGO_POD_IP` | y | `-` | Pod IP address (use the [downward API](https://kubernetes.io/docs/tasks/configure-pod-container/environment-variable-expose-pod-information/#the-downward-api))|
| `LEGO_NAMESPACE` | n | `default` | Namespace where kube-lego is running in |
| `LEGO_URL` | n | `https://acme-staging.api.letsencrypt.org/directory` | URL for the ACME server. To get "real" certificates set to the production API of Let's Encrypt: `https://acme-v01.api.letsencrypt.org/directory` |
| `LEGO_SECRET_NAME` | n | `kube-lego-account` | Name of the secret in the same namespace that contains ACME account secret |
| `LEGO_SERVICE_NAME_NGINX` | n | `kube-lego-nginx` | Service name for NGINX ingress |
| `LEGO_SERVICE_NAME_GCE` | n | `kube-lego-gce` | Service name for GCE ingress |
| `LEGO_SUPPORTED_INGRESS_CLASS` | n | `nginx,gce` | Specify the supported ingress class |
| `LEGO_INGRESS_NAME_NGINX` | n | `kube-lego-nginx` | Ingress name which contains the routing for HTTP verification for nginx ingress |
| `LEGO_PORT` | n | `8080` | Port where this daemon is listening for verifcation calls (HTTP method)|
| `LEGO_CHECK_INTERVAL` | n | `8h` | Interval for periodically certificate checks (to find expired certs)|
| `LEGO_MINIMUM_VALIDITY` | n | `720h` (30 days) | Request a renewal when the remaining certificate validity falls below that value|
| `LEGO_DEFAULT_INGRESS_CLASS` | n | `nginx` | Default ingress class for resources without specification|
| `LEGO_KUBE_API_URL` | n | `http://127.0.0.1:8080` | API server URL |
| `LEGO_LOG_LEVEL` | n | `info` | Set log level (`debug`, `info`, `warn` or `error`) |
| `LEGO_KUBE_ANNOTATION` | n | `kubernetes.io/tls-acme` | Set the ingress annotation used by this instance of kube-lego to get certificate for from Let's Encrypt. Allows you to run kube-lego against staging and production LE |
| `LEGO_WATCH_NAMESPACE` | n | `` | Namespace that kube-lego should watch for ingresses and services |

## Full deployment examples

- [Nginx Ingress Controller](examples/nginx/)
- [GCE Load Balancers](examples/gce/)

## Troubleshooting

When interacting with *kube-lego*, its a good idea to run with `LEGO_LOG_LEVEL=debug` for more verbose details.
Additionally, be aware of the automatically created resources (see environment variables) when cleaning up or testing.

Possible resources for *help*:

* The official channel `#kube-lego` on `kubernetes.slack.com`

> There is also a good chance to get some support on non-official support
> channels for *kube-lego*, but be aware that these are rather general
> kubernetes discussion channels.

* `#coreos` on freenode
* Slack channels like `#kubernetes-users` or `#kubernetes-novice` on `kubernetes.slack.com`
* If you absolutely just can't figure out your problem, file an issue.


### Enable the pprof tool

To enable the [pprof tool](https://golang.org/pkg/net/http/pprof/) run kube-lego with environment `LEGO_LOG_LEVEL=debug`.

Capture 20 seconds of the execution trace:

`$ wget http://localhost:8080/debug/pprof/trace?seconds=20 -O kube-lego.trace`

You can inspect the trace sample running 

`$ go tool trace kube-lego.trace`


## Authors

* Christian Simon for [Jetstack Ltd](http://www.jetstack.io)
* [PR contributors](https://github.com/jetstack/kube-lego/graphs/contributors)
