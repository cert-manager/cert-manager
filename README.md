# kube-lego

Kube-Lego automatically requests certificates for Kubernetes Ingress resources from Let's Encrypt

## Environment variables

```
# Specify the admin email address to recover a lost key
export LEGO_EMAIL=mail@example.com

# Name of the kubernetes secret where to store the Let's Encrypt account information
export LEGO_SECRET_NAME=
```

## Usage

* Currently not really usable

* Listens to port 8080
* Connects to Kubernetes kluster an looks for ingress resources with the right annotation
  (`kubernetes.io/lego-enabled: "true"`)
* Creates an Let's encrypt account and stores it's private key in kubernetes secrets
* Tries to create a certificate for all ingress resources found (no storing it anywhere)
