# cert-manager

cert-manager is a Kubernetes addon to automate the management and issuance of
certificates from an aribitrary issuing source.

It is loosely based upon the work of [kube-lego](https://github.com/jetstack/kube-lego)
and has borrowed some wisdome from other similar projects eg.
[kube-cert-manager](https://github.com/PalmStoneGames/kube-cert-manager).

## Current status

This project is still heavily under development and is not ready for use
**yet**. However, if you want to experiment, please do try running the current
development build and reporting any issues you run into.

## Future plans

Soon, I'd like to see cert-manager expose it's own API server, to be used by
the apiserver-aggregator. This will allow us to perform verification of
resources as they are submitted, and consequently reject 'bad' manifests.

## Deploying

To deploy the latest development version, run:

```
$ kubectl create -f docs/cert-manager.yaml
```

There is an example Certificate resource in `docs/acme-cert.yaml`, however
requesting certificates via Ingress is not currently supported - instead, you
must point your domain at the service created for cert-manager manually. This
will naturally change over the coming days and weeks!

```
$ kubectl create -f docs/acme-cert.yaml
```
