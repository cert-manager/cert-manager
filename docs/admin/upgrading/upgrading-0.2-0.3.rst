===========================
Upgrading from v0.2 to v0.3
===========================

During the v0.3 release, a number of breaking changes were made that require you
to update either deployment configuration and runtime configuration (e.g. Certificate,
Issuer and ClusterIssuer resources).

After reading these instructions, you should then proceed to upgrade cert-manager
according to your deployment configuration (e.g. using ``helm upgrade`` if installing
via Helm chart, or ``kubectl apply`` if installing with raw manifests).

A brief summary:

* Supporting resources for ClusterIssuers (e.g. signing CA certificates, or
  ACME account private keys) will now be stored in the same namespace as
  cert-manager, instead of kube-system in previous versions (#329, @munnerz)

* Switch to ConfigMaps instead of Endpoints for leader election (#327, @mikebryant)

* Removing support for ACMEv1 in favour of ACMEv2 (#309, @munnerz)

* Removing ingress-shim and compiling it into cert-manager itself (#502, @munnerz)

* Change to the default behaviour of ingress-shim. It now generates Certificates
  with the ``ingressClass`` field set instead of the ``ingress`` field. This will
  mean users of ingress controllers that assign a single IP to a single Ingress (e.g.
  the GCE ingress controller) will no longer work without adding a new annotation
  to your ingress resource.

Supporting resources for ClusterIssuers moving into the cert-manager namespace
==============================================================================

In the past, the cert-manager controller was hard coded to look for supplemental
resources, such as Secrets containing DNS provider credentials, in the kube-system
namespace.

We now store these resources in the same namespace as the cert-manager pod itself
runs within.

When upgrading, you should make sure to move any of these supplemental resources into
the cert-manager deployment namespace, or otherwise deploy cert-manager into kube-system
itself.

You can also change the 'cluster resource namespace' when deploying cert-manager:

With the helm chart: ``--set clusterResourceNamespace=kube-system``.

Or if using the static deployment manifests, by adding the ``--cluster-resource-namespace``
flag to the ``args`` field of the cert-manager container.

Switch to ConfigMaps instead of Endpoints for leader election
=============================================================

cert-manager-controller performs leader election to allow you to run 'hot standby'
replicas of cert-manager.

In the past, we used Endpoint resources to perform this election.
The new best practice is to use ConfigMap resources in order to reduce API overhead
in large clusters.

As such, v0.3 switches us to use ConfigMap resources for leader election.

During the upgrade, you should first scale your cert-manager-controller deployment
to 0 to ensure no other replicas of cert-manager are running when the new v0.3
deployment starts:

.. code-block:: shell

   kubectl scale --namespace <deployment-namespace> --replicas=0 deployment <cert-manager-deployment-name>

Removing support for ACMEv1 in favour of ACMEv2
===============================================

The ACME v2 specification is now in production with Let's Encrypt.
In order to support this new spec, which includes support for wildcard certificates,
we have removed support for the v1 protocol altogether.

If you have any ACME Issuer or ClusterIssuer resources, you should update the
server fields of these to the new ACMEv2 endpoints.

For example, if you have a Let's Encrypt production issuer, you should update the
server URL:

.. code-block:: yaml

   apiVersion: certmanager.k8s.io/v1alpha1
   kind: Issuer
   ...
   spec:
     acme:
       # server: https://acme-v01.api.letsencrypt.org/directory
       server: https://acme-v02.api.letsencrypt.org/directory # we switch 'v01' to 'v02'

Removing ingress-shim and compiling it into cert-manager itself
===============================================================

In v0.3 we removed the ingress-shim component and instead now compile in its
functionality into the main cert-manager binary.

This change also introduces a change to the way you configure default Issuers
and ClusterIssuers at deployment time.

The deployment documentation has been updated accordingly, but instead of setting
``ingressShim.extraArgs={--default-issuer-name=letsencrypt-pod}`` there are
now dedicated Helm chart fields:

.. code-block:: shell

   --set ingressShim.defaultIssuerName=letsencrypt-prod \
   --set ingressShim.defaultIssuerKind=ClusterIssuer

Change to the default behaviour of ingress-shim
===============================================

In the past, when using ingress-shim, we set the ``ingress`` field on the Certificate
resource to trigger cert-manager to edit the specified Ingress resource to solve
the challenge.

The alternate option is to set the ``ingressClass`` field, which causes cert-manager
to create temporary Ingress resources to solve the challenge. This behaviour provides
better compatibility with ingress controllers like nginx-ingress_.

In v0.3 we have changed the default behaviour of ingress-shim to set the ``ingressClass``
field instead of ``ingress``.

This will cause validations for ingress controllers like ingress-gce_ to fail without
additional configuration in your Ingress resources annotations.

Add the follow annotation to your Ingress resources if you are using the GCE ingress
controller, in addition to the usual ingress-shim annotation(s):

.. code-block:: yaml

   certmanager.k8s.io/acme-http01-edit-in-place: "true"

.. _nginx-ingress: https://github.com/kubernetes/ingress-nginx
.. _ingress-gce: https://github.com/kubernetes/ingress-gce