========================
Installing on Kubernetes
========================

cert-manager runs within your Kubernetes cluster as a series of deployment
resources. It utilises `CustomResourceDefinitions`_ to configure Certificate
Authorities and request certificates.

It is deployed using regular YAML manifests, like any other applications on
Kubernetes.

Once cert-manager has been deployed, you must configure Issuer or ClusterIssuer
resources which represent certificate authorities.
More information on configuring different Issuer types can be found in the
:doc:`respective setup guides </tasks/issuers/index>`.


Installing with regular manifests
=================================

In order to install cert-manager, we must first create a namespace to run it
within. This guide will install cert-manager into the ``cert-manager``
namespace. It is possible to run cert-manager in a different namespace,
although you will need to make modifications to the deployment manifests.

.. code-block:: shell

   # Create a namespace to run cert-manager in
   kubectl create namespace cert-manager

As part of the installation, cert-manager also deploys a
`ValidatingWebhookConfiguration`_ resource in order to validate that the
Issuer, ClusterIssuer and Certificate resources we will create after
installation are valid.

In order to deploy the ValidatingWebhookConfiguration, cert-manager creates
a number of 'internal' Issuer and Certificate resources in its own namespace.

This creates a chicken-and-egg problem, where cert-manager requires the
webhook in order to create the resources, and the webhook requires cert-manager
in order to run.

We avoid this problem by disabling resource validation on the namespace that
cert-manager runs in:

.. code-block:: shell

   # Disable resource validation on the cert-manager namespace
   kubectl label namespace cert-manager certmanager.k8s.io/disable-validation=true

You can read more about the webhook on the :doc:`webhook document <../webhook>`.

We can now go ahead and install cert-manager. All resources
(the CustomResourceDefinitions, cert-manager, and the webhook component)
are included in a single YAML manifest file:

.. code-block:: shell

   # Install the CustomResourceDefinitions and cert-manager itself
   kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/v0.8.0/cert-manager.yaml

.. note::
   If you are running kubectl v1.12 or below, you will need to add the
   ``--validate=false`` flag to your ``kubectl apply`` command above else you
   will receive a validation error relating to the ``caBundle`` field of the
   ``ValidatingWebhookConfiguration`` resource.
   This issue is resolved in Kubernetes 1.13 onwards. More details can be found
   in `kubernetes/kubernetes#69590`_.

.. note::
   When running on GKE (Google Kubernetes Engine), you may encounter a
   'permission denied' error when creating some of these resources. This is a
   nuance of the way GKE handles RBAC and IAM permissions, and as such you
   should 'elevate' your own privileges to that of a 'cluster-admin' **before**
   running the above command. If you have already run the above command, you
   should run them again after elevating your permissions::

       kubectl create clusterrolebinding cluster-admin-binding \
         --clusterrole=cluster-admin \
         --user=$(gcloud config get-value core/account)

Installing with Helm
====================

As an alternative to the YAML manifests referenced above, we also provide an
official Helm chart for installing cert-manager.

Pre-requisites
--------------

* Helm_ and Tiller installed (or alternatively, use `Tillerless Helm v2`_)
* `cluster-admin privileges bound to the Tiller pod`_

Foreword
--------

Before deploying cert-manager with Helm, you must ensure Tiller_ is up and
running in your cluster. Tiller is the server side component to Helm.

Your cluster administrator may have already setup and configured Helm for you,
in which case you can skip this step.

Full documentation on installing Helm can be found in the `Installing helm docs`_.

If your cluster has RBAC (Role Based Access Control) enabled (default in GKE
v1.7+), you will need to take special care when deploying Tiller, to ensure
Tiller has permission to create resources as a cluster administrator. More
information on deploying Helm with RBAC can be found in the `Helm RBAC docs`_.

Steps
-----

In order to install the Helm chart, you must run:

.. code-block:: shell

   # Install the CustomResourceDefinition resources separately
   kubectl apply -f https://raw.githubusercontent.com/jetstack/cert-manager/release-0.8/deploy/manifests/00-crds.yaml

   # Create the namespace for cert-manager
   kubectl create namespace cert-manager

   # Label the cert-manager namespace to disable resource validation
   kubectl label namespace cert-manager certmanager.k8s.io/disable-validation=true

   # Add the Jetstack Helm repository
   helm repo add jetstack https://charts.jetstack.io

   # Update your local Helm chart repository cache
   helm repo update

   # Install the cert-manager Helm chart
   helm install \
     --name cert-manager \
     --namespace cert-manager \
     --version v0.8.0 \
     jetstack/cert-manager

The default cert-manager configuration is good for the majority of users, but a
full list of the available options can be found in the `Helm chart README`_.

Verifying the installation
==========================

Once you've installed cert-manager, you can verify it is deployed correctly by
checking the ``cert-manager`` namespace for running pods:

.. code-block:: shell

   kubectl get pods --namespace cert-manager

   NAME                               READY   STATUS      RESTARTS   AGE
   cert-manager-5c6866597-zw7kh       1/1     Running     0          2m
   webhook-78fb756679-9bsmf           1/1     Running     0          2m
   webhook-ca-sync-1543708620-n82gj   0/1     Completed   0          1m

You should see both the ``cert-manager`` and ``webhook`` component in a Running
state, and the ``ca-sync`` pod is Completed. If the webhook has not Completed
but the ``cert-manager`` pod has recently started, wait a few minutes for the
``ca-sync`` pod to be retried.
If you experience problems, please check the
:doc:`troubleshooting guide <../troubleshooting>`.

The following steps will confirm that cert-manager is set up correctly and able
to issue basic certificate types:

.. code-block:: shell

   # Create a ClusterIssuer to test the webhook works okay
   cat <<EOF > test-resources.yaml
   apiVersion: v1
   kind: Namespace
   metadata:
     name: cert-manager-test
   ---
   apiVersion: certmanager.k8s.io/v1alpha1
   kind: Issuer
   metadata:
     name: test-selfsigned
     namespace: cert-manager-test
   spec:
     selfSigned: {}
   ---
   apiVersion: certmanager.k8s.io/v1alpha1
   kind: Certificate
   metadata:
     name: selfsigned-cert
     namespace: cert-manager-test
   spec:
     commonName: example.com
     secretName: selfsigned-cert-tls
     issuerRef:
       name: test-selfsigned
   EOF

   # Create the test resources
   kubectl apply -f test-resources.yaml

   # Check the status of the newly created certificate
   # You may need to wait a few seconds before cert-manager processes the
   # certificate request
   kubectl describe certificate -n cert-manager-test
   ...
   Spec:
     Common Name:  example.com
     Issuer Ref:
       Name:       test-selfsigned
     Secret Name:  selfsigned-cert-tls
   Status:
     Conditions:
       Last Transition Time:  2019-01-29T17:34:30Z
       Message:               Certificate is up to date and has not expired
       Reason:                Ready
       Status:                True
       Type:                  Ready
     Not After:               2019-04-29T17:34:29Z
   Events:
     Type    Reason      Age   From          Message
     ----    ------      ----  ----          -------
     Normal  CertIssued  4s    cert-manager  Certificate issued successfully

   # Clean up the test resources
   kubectl delete -f test-resources.yaml

If all the above steps have completed without error, you are good to go!

If you experience problems, please check the
:doc:`troubleshooting guide <../troubleshooting>`.

Configuring your first Issuer
=============================

Before you can begin issuing certificates, you must configure at least one
Issuer or ClusterIssuer resource in your cluster.

You should read the :doc:`Setting up Issuers </tasks/issuers/index>` guide to
learn how to configure cert-manager to issue certificates from one of the
supported backends.

Alternative installation methods
================================

kubeprod
--------

`Bitnami Kubernetes Production Runtime`_ (BKPR, ``kubeprod``) is a curated
collection of the services you would need to deploy on top of your Kubernetes
cluster to enable logging, monitoring, certificate management, automatic
discovery of Kubernetes resources via public DNS servers and other common
infrastructure needs.

It depends on ``cert-manager`` for certificate management, and it is `regularly
tested`_ so the components are known to work together for GKE and AKS clusters
(EKS to be added soon). For its ingress stack it creates a DNS entry in the
configured DNS zone and requests a TLS certificate from the Let's Encrypt
staging server.

BKPR can be deployed using the ``kubeprod install`` command, which will deploy
``cert-manager`` as part of it. Details available in the `BKPR installation guide`_.


Debugging installation issues
=============================

If you have any issues with your installation, please refer to the
:doc:`troubleshooting guide <../troubleshooting>`.

.. _`CustomResourceDefinitions`: https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/
.. _`Helm chart README`: https://github.com/jetstack/cert-manager/blob/release-0.8/deploy/charts/cert-manager/README.md
.. _`kubernetes/kubernetes#69590`: https://github.com/kubernetes/kubernetes/issues/69590
.. _`ValidatingWebhookConfiguration`: https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/
.. _`Helm`: https://helm.sh/
.. _`cluster-admin privileges bound to the Tiller pod`: https://github.com/helm/helm/blob/240e539cec44e2b746b3541529d41f4ba01e77df/docs/rbac.md#Example-Service-account-with-cluster-admin-role
.. _`helm RBAC docs`: https://github.com/helm/helm/blob/master/docs/rbac.md
.. _`installing helm docs`: https://github.com/kubernetes/helm/blob/master/docs/install.md
.. _Tiller: https://github.com/helm/helm
.. _`Tillerless Helm v2`: https://rimusz.net/tillerless-helm/
.. _`Bitnami Kubernetes Production Runtime`: https://github.com/bitnami/kube-prod-runtime/
.. _`regularly tested`: https://github.com/bitnami/kube-prod-runtime/blob/master/Jenkinsfile
.. _`BKPR installation guide`: https://github.com/bitnami/kube-prod-runtime/blob/master/docs/install.md
