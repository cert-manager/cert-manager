=====================
Develop with minikube
=====================

Minikube is a tool to quickly provision a local Kubernetes cluster on many
platforms. It can be used to test and develop cert-manager. This guide will
walk you through getting started using Minikube for development.

Start minikube
==============

First, run minikube, and configure your local kubectl command to work with minikube; minikube typically does this automatically.

.. code-block:: shell

   # Check your locally installed minikube version
   $ minikube version
   minikube version: v0.25.0

   # Start a local cluster
   $ minikube start --extra-config=apiserver.Authorization.Mode=RBAC

   # Verify it works. This should output a local apiserver IP
   $ kubectl cluster-info

   # Create a cluster role binding so Tiller has cluster-admin access rights
   $ kubectl create clusterrolebinding default-admin --clusterrole=cluster-admin --serviceaccount=kube-system:default

   # Install helm
   $ helm init


Install local development tools
===============================

You will need the following tools to build cert-manager:

* Bazel_
* Docker_ (and enable for non-root user)

These instructions have only been tested on Linux; Windows and MacOS may
require further changes.

If you need to add dependencies, you will additionally need:

* Git_
* Mercurial_

You can then run ``bazel run //hack:update-deps`` to regenerate any
dependencies, and ``bazel build :images`` to build the docker images.

Build a dev version of cert-manager
===================================

.. code-block:: shell

   # Configure your local docker client to use the minikube docker daemon
   $ eval "$(minikube docker-env)"

   # Build cert-manager binaries and docker images. Full output omitted for brevity
   $ make build
   Successfully tagged quay.io/jetstack/cert-manager-controller:build


Deploy that version with helm
=============================

.. code-block:: shell

   # Install our freshly built cert-manager image
   $ helm install \
        --set image.tag=build \
        --set image.pullPolicy=Never \
        --name cert-manager \
        ./contrib/charts/cert-manager

From here, you should be able to do whatever manual testing or development you wish to.

Deploy a new version
====================

In general, upgrading can be done simply by running `make build`, and then deleting the deployed pod using `kubectl delete pod`.

However, if you make changes to the helm chart or wish to change the controller's arguments, such as to change the logging level, you may also update it with the following:

.. code-block:: shell

   helm upgrade  \
        cert-manager \
        --reuse-values \
        --set extraArgs="{-v=5}"
        --set image.tag=build
        ./contrib/charts/cert-manager


.. _Bazel: https://docs.bazel.build/versions/master/install.html
.. _Docker: https://store.docker.com/search?type=edition&offering=community
.. _Git: https://git-scm.com/downloads
.. _Mercurial: https://www.mercurial-scm.org/