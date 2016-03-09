# kube-lego

Kube-Lego automatically requests certificates for Kubernetes Ingress resources from Let's Encrypt

## Environment variables

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `LEGO_EMAIL` | y | `-` | E-Mail address for the ACME account, used to recover from lost secrets |
| `LEGO_SECRET_NAME` | n | `kube-lego-account` | Name of the secret in the same namespace that contains ACME account secret |
| `LEGO_SERVICE_NAME` | n | `kube-lego` | Service name that connects to this pod
| `LEGO_PORT` | n | `8080` | Port where this daemon is listening for verifcation calls (HTTP method)|


## Usage

* Currently not really usable

* Listens to port 8080
* Connects to Kubernetes kluster an looks for ingress resources with the right annotation
  (`kubernetes.io/lego-enabled: "true"`)
* Creates an Let's encrypt account and stores it's private key in kubernetes secrets
* Tries to create a certificate for all ingress resources found (no storing it anywhere)
