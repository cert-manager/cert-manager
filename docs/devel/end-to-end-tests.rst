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

* ``kubectl`` - If you are running the tests on Linux, this step is
  technically not required. For non-Linux hosts (i.e. OSX), you will need to
  ensure you have a relatively new version of kubectl available on your PATH.

* An internet connection - tests require access to DNS, and optionally
  Cloudflare APIs (if a Cloudflare API token is provided).

Bazel, Docker and Kubectl should be installed through your preferred means.

Run end-to-end tests
====================

You can run the end-to-end tests by executing the following:

.. code-block:: shell

   ./hack/ci/run-e2e-kind.sh

The full suite may take up to 10 minutes to run.
You can monitor output of this command to track progress.
