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

* ``docker`` - We provision a whole Kubernetes cluster within Docker, and so
  an up to date version of Docker must be installed. The oldest Docker version
  we have tested is 17.09.

* kind_ - This
  tool is responsible for actually building and starting the Kubernetes cluster
  used during tests.

* helm_ - A minimum version 2.10 is required.

* ``kubectl`` - If you are running the tests on Linux, this step is
  technically not required. For non-Linux hosts (i.e. OSX), you will need to
  ensure you have a relatively new version of kubectl available on your PATH.

* ``golang`` - We require golang to build cert-manager and various test
  related components. You should use at least go version 1.9, although we
  currently build with go 1.11 in our own CI.

* An internet connection - tests require access to DNS, and optionally
  Cloudflare APIs (if a Cloudflare API token is provided).

Docker, helm and kubectl should be installed through your preferred means.

``kind`` can be installed like so:

.. code-block:: shell

   go install k8s.io/test-infra/kind

Run end-to-end tests
====================

You can run the end-to-end tests by executing the following:

.. code-block:: shell

   ./hack/ci/run-e2e-kind.sh

The full suite may take up to 20 minutes to run.
You can monitor output of this command to track progress.

.. _kind: https://github.com/kubernetes/test-infra/tree/master/kind
.. _helm: https://github.com/helm/helm
