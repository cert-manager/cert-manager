# build tool

The build tool can be used to develop and test cert-manager.

## Arguments



## Imports/dependencies

This package is not coupled to any testing, CLI or UI framework.
It should be entirely configurable as a Go library to ensure it is agnostic and
easily testable.

## Packages

* `cluster`: used to build clusters that can be used for local development or
  end-to-end testing

* `images`: used for building cert-manager image targets, e.g. the controller,
  webhook, etc

* `testmanifest`: used to build a config file that can be used to run the
  end-to-end test binary
