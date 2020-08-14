# cert-manager Mixin

The cert-manager mixin is a collection of reusable and configurable [Prometheus](https://prometheus.io/) alerts, and a [Grafana](https://grafana.com) dashboard to help with operating cert-manager.

To generate these resources, you need to have `jsonnet` (v0.16+) and `jb` installed. If you have a Go development environment setup you can use these commands:

```shell
go get github.com/google/go-jsonnet/cmd/jsonnet
go get github.com/google/go-jsonnet/cmd/jsonnetfmt
go get github.com/jsonnet-bundler/jsonnet-bundler/cmd/jb
```

## Config Tweaks

There are some configurable options you may want to override in your usage of this mixin, as they will be specific to your deployment of cert-manager. They can be found in [config.libsonnet](config.libsonnet).

## Using the mixin with kube-prometheus

See the [kube-prometheus](https://github.com/coreos/kube-prometheus#kube-prometheus)
project documentation for examples on importing mixins.

## Using the mixin as raw files

If you don't use the jsonnet based `kube-prometheus` project then you will need to
generate the raw yaml files for inclusion in your Prometheus installation.

Install the `jsonnet` dependencies:
```
$ go get github.com/google/go-jsonnet/cmd/jsonnet
$ go get github.com/google/go-jsonnet/cmd/jsonnetfmt
```

Generate yaml:
```
$ make
```

To use the dashboard, it can be imported or provisioned for Grafana by grabbig the [cert-manager.json](dashboards/cert-manager.json) file as is.
