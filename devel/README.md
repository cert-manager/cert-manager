# Development tooling

This directory contains tools and scripts used to create development and
testing environments for cert-manager.

## Tool dependencies

The scripts in this directory commonly require additional tooling, such as
access to `kubectl`, `helm`, `kind` and a bunch of other things.

If you already have these tools available on your host system, the scripts
should just work, so long as the versions you have installed are roughly
compatible.

If you are running into issues with your host-installed tools, Bazel provides
versioned access to all of the required tools for the e3e scripts.

To setup your shell to use the Bazel provided versions of these tools, run the
following from the **root of the repository**:

```console
export PATH="$(pwd)/devel/bin:$PATH"
```

## Common usages

This section describes common usage patterns for development and testing.

### Creating a kind cluster

To create a kind cluster that can be used for both development and testing, run
`./devel/cluster/create.sh` from the root of the cert-manager repository:

```console
./devel/cluster/create.sh
```

You can change the name of the kind cluster created by setting:

```console
export KIND_CLUSTER_NAME=custom-cluster-name
```

If a cluster with the same name already exists, it will **not** be recreated
and instead will be reused.

### Installing a development build of cert-manager

Once you have a kind cluster running, you can install a development version of
cert-manager by running:

```console
./devel/addon/certmanager/install.sh
```

This will build, load and install cert-manager from source into your kind
development cluster.

Further invocations of the `install.sh` script will rebuild and upgrade the
installed version of cert-manager, making it possible to iteratively work on
the codebase and test changes.

### Running end-to-end tests

Before running the end-to-end tests, you must install some additional
components used during the tests into your kind cluster.

Run the following to setup persistent test instances of Pebble, ingress-nginx,
and a sample DNS01 webhook:

```console
./devel/setup-e2e-deps.sh
```

You only need to run this command once for the lifetime of your test cluster.

If you haven't already, deploy a new test build of cert-manager:

```console
./devel/addon/certmanager/install.sh
```

Finally, run the end-to-test tests using:

```console
./devel/run-e2e.sh
```

You can run this command multiple times against the same cluster without
adverse effects.

### Deleting the test cluster

Once you have finished with your testing environment, or if you have
encountered a strange state you cannot recover from, you can tear down the
testing environment by using `kind` directly:

```console
kind delete cluster [--name=$KIND_CLUSTER_NAME]
```
