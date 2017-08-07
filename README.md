# cert-manager

cert-manager is a Kubernetes addon to automate the management and issuance of
certificates from an aribitrary issuing source.

It is loosely based upon the work of [kube-lego](https://github.com/jetstack/kube-lego)
and has borrowed some wisdom from other similar projects eg.
[kube-cert-manager](https://github.com/PalmStoneGames/kube-cert-manager).

## Current status

This project is still heavily under development and is not ready for use
**yet**. However, if you want to experiment, please do try running the current
development build and reporting any issues you run into.

## Deploying

To deploy the latest development version, run:

```
$ kubectl create -f docs/cert-manager.yaml
```

## Getting started

To get started, I've created two example issuers in `docs/acme-issuer.yaml`.
These are configured to support the clouddns challenge provider for ACME, but
if you do not intend to test this functionality then feel free to remove the
configuration for it.

Go ahead and create the issuer(s) with:

```
$ kubectl create -f docs/acme-issuer.yaml
```

This will register your account with the ACME server, and generate you an
account private key if required in the process.

There are then three example Certificate resources in `docs/acme-cert.yaml`.
One of these uses the ACME HTTP01 challenge solver, targetting an existing
ingress with `ingressName`. This configuration is best chosen when using an
ingress controller that behaves like the GCLB controller (ie. one ingress<>IP
mapping). The other example uses the `ingressClass` field, which is best used
for ingress controllers like `nginx` where Ingress resources are 'merged'.

The third certificate is configured to use the clouddns DNS01 challenge
provider.

You can mix and match challenge mechanisms within a single certificate for
different domains. Please test this out and report any issues on the repo.
