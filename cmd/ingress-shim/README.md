# ingress-shim

This is a small binary that can be run alongside any cert-manager deployment
in order to automatically create Certificate resources for Ingresses when a
particular annotation is found on an ingress resource.

This allows users to consume certificates from cert-manager without having to
manually create Certificate resources, i.e. in a similar fashion to [kube-lego](https://github.com/jetstack/kube-lego).

It has been developed outside of the core of cert-manager as it is an
experiment to assess the best way to implement this sort of functionality.

## Project status

This project is experimental, and thus should not be relied upon in a
production environment. This tool may change in backwards incompatible ways.

In the future, the functionality of this tool may be merged into cert-manager
itself to provide a more seamless experience for users.
