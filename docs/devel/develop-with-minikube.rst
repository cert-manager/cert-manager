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
