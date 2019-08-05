========================
Running end-to-end tests
========================

cert-manager has an end-to-end test suite that verifies functionality against a
real Kubernetes cluster.

This document explains how you can run the end-to-end tests yourself.
This is useful when you have added or changed functionality in cert-manager and
want to verify the software still works as expected.

Requirements
============

Currently, a number of tools **must** be installed on your machine in order to
run the tests:

* ``bazel`` - As with all other development, Bazel is required to actually
  build the project as well as end-to-end test framework. Bazel will also
  retrieve appropriate versions of any other dependencies depending on what
  'target' you choose to run.

* ``docker`` - We provision a whole Kubernetes cluster within Docker, and so
  an up to date version of Docker must be installed. The oldest Docker version
  we have tested is 17.09.

* An internet connection - tests require access to DNS, and optionally
  Cloudflare APIs (if a Cloudflare API token is provided).

Bazel and Docker should be installed through your preferred means.

Run end-to-end tests
====================

You can run the end-to-end tests by executing the following:

.. code-block:: shell

   ./hack/ci/run-e2e-kind.sh

The full suite may take up to 15 minutes to run.
You can monitor output of this command to track progress.

Iterating locally on end-to-end tests
=====================================

The ``run-e2e-kind.sh`` script above performs a number of steps automatically
for you:

1. Creates a `suitably configured`_ kind_ cluster to run tests in
2. Builds the `docker images required for the tests`_: ``bazel run //hack/build -- addon load``
2. Builds the `cert-manager images under test`_: ``bazel run //hack/build -- certmanager load``
3. Builds the `//test/e2e`_ binary:
4. Sets the `required flags`_ and runs the tests

The actual e2e test binary:

5. Deploys `global addons`_ such as Tiller, ingress-nginx, and cert-manager itself
6. Runs each e2e test case
  * Each test case may also deploy additional addons, e.g. Pebble_ when running ACME tests
  * Test-scoped addons will be 'deprovisioned' after each test
7. Cleans up/uninstalls global addons

Finally, the ``run-e2e-kind.sh`` script:

8. Destroys the kind_ test cluster

This process can take a little while, and it can be beneficial to break the
process apart when iterating on the test suite locally.

For that reason, the process is roughly split into 3 scripts:

* ``bazel run //hack/build -- cluster create``: step (1)
* ``bazel run //hack/build -- addon load``: step (2)
* ``bazel run //hack/build -- certmanager load``: step (3)
* `make e2e_test`_: steps (3, 4, 5, 6, 7)
* ``bazel run //hack/build -- cluster delete``: step (8)

The `make e2e_test`_ target can be configured with a number of different
options that are passed to the test suite. You can see the available options
by reading the e2e_test target in the Makefile.

.. _docker images required for the tests: https://github.com/jetstack/cert-manager/blob/8941df043758b3be62bbefe00381244d0f567b9f/test/e2e/BUILD.bazel#L4-L20
.. _suitably configured: https://github.com/jetstack/cert-manager/blob/8941df043758b3be62bbefe00381244d0f567b9f/test/fixtures/kind/config-v1beta2.yaml
.. _kind: https://kind.sigs.k8s.io/
.. _//test/e2e: https://github.com/jetstack/cert-manager/tree/8941df043758b3be62bbefe00381244d0f567b9f/test/e2e
.. _required flags: https://github.com/jetstack/cert-manager/blob/8941df043758b3be62bbefe00381244d0f567b9f/Makefile#L114-L124
.. _global addons: https://github.com/jetstack/cert-manager/blob/8941df043758b3be62bbefe00381244d0f567b9f/test/e2e/framework/addon/globals.go#L64-L97
.. _Pebble: https://github.com/letsencrypt/pebble/
.. _make e2e_test: https://github.com/jetstack/cert-manager/blob/8941df043758b3be62bbefe00381244d0f567b9f/Makefile#L109-L124
