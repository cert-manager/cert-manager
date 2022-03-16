# Development tooling

This directory contains tools and scripts used to create development and
testing environments for cert-manager.

## Tool dependencies

The scripts in this directory commonly require additional tooling, such as
access to `kubectl`, `helm`, `kind` and a bunch of other things.

If you already have these tools available on your host system, the scripts
should just work, so long as the versions you have installed are roughly
compatible.

If you are running into issues with your host-installed tools, you can
have them downloaded in `bin/tools` with the command:

```sh
# With "-j", the tools are downloaded in parallel.
make -j tools
```

To setup your shell to use the tools, run the following from the root of
the repository:

```sh
export PATH="$PWD/bin/tools:$PATH"
```

> **Tip:** this change of PATH won't persist between shell sessions. To get
> this command executed automatically when you enter the cert-manager
> folder, put this command in an `.envrc` file in the cert-manager folder
> and install [`direnv`](https://direnv.net/docs/installation.html).

## Common usages

This section describes common usage patterns for development and testing.

### Installing a development build of cert-manager

Once you have a kind cluster running, you can install a development version of
cert-manager by running:

```sh
make -j e2e-setup-certmanager
```

This will create a kind cluster, build, load and install cert-manager from
source into your kind development cluster.

Further invocations of this command will rebuild and upgrade the installed
version of cert-manager, making it possible to iteratively work on the
codebase and test changes.

### Running end-to-end tests

Before running the end-to-end tests, you must install some additional
components used during the tests into your kind cluster.

Run the following to setup cert-manager, Pebble, ingress-nginx, the sample
DNS01 webhook and all the other components required for the end-to-end
tests:

```sh
make -j e2e-setup
```

You only need to run this command once for the lifetime of your test cluster.

Finally, run the end-to-test tests using:

```console
make e2e
```

You can run this command multiple times against the same cluster without
adverse effects.

A common use-case is to run a single test case from the end-to-end tests.
This is explained in the `--help`:

```sh
./make/e2e.sh --help
```

### Deleting the test cluster

Once you have finished with your testing environment, or if you have
encountered a strange state you cannot recover from, you can tear down the
testing environment by using `kind` directly:

```sh
kind delete cluster [--name=$KIND_CLUSTER_NAME]
```
