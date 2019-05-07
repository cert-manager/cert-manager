=========================================================
Automatically creating Certificates for Ingress resources
=========================================================

cert-manager can be configured to automatically provision TLS certificates for
Ingress resources via annotations on your Ingresses.

A small sub-component of cert-manager, ingress-shim, is responsible for this.

How it works
============

ingress-shim watches Ingress resources across your cluster. If it observes an
Ingress with *any* of the annotations described in the 'Usage' section, it will
ensure a Certificate resource with the same name as the Ingress, and configured
as described on the Ingress exists. For example:

.. code-block:: yaml

  apiVersion: extensions/v1beta1
  kind: Ingress
  metadata:
    annotations:
      # add an annotation indicating the issuer to use.
      certmanager.k8s.io/cluster-issuer: nameOfClusterIssuer
    name: myIngress
    namespace: myIngress
  spec:
    rules:
    - host: myingress.com
      http:
        paths:
        - backend:
            serviceName: myservice
            servicePort: 80
          path: /
    tls: # < placing a host in the TLS config will indicate a cert should be created
    - hosts:
      - myingress.com
      secretName: myingress-cert # < cert-manager will store the created certificate in this secret.


Configuration
=============

Since cert-manager v0.2.2, ingress-shim is deployed automatically as part of a
Helm chart installation.

If you would also like to use the old kube-lego_ ``kubernetes.io/tls-acme: "true"``
annotation for fully automated TLS, you will need to configure a default Issuer
when deploying cert-manager. This can be done by adding the following ``--set``
when deploying using Helm:

.. code-block:: shell

   --set ingressShim.defaultIssuerName=letsencrypt-prod \
   --set ingressShim.defaultIssuerKind=ClusterIssuer


In the above example, cert-manager will create Certificate resources that reference the ClusterIssuer `letsencrypt-prod` for all Ingresses that have a ``kubernetes.io/tls-acme: "true"`` annotation.

For more information on deploying cert-manager, read the :doc:`deployment guide </getting-started/index>`.

Supported annotations
=====================

You can specify the following annotations on ingresses in order to trigger
Certificate resources to be automatically created:

* ``certmanager.k8s.io/issuer`` - the name of an Issuer to acquire the
  certificate required for this ingress from. The Issuer **must** be in the same
  namespace as the Ingress resource.

* ``certmanager.k8s.io/cluster-issuer`` - the name of a ClusterIssuer to acquire
  the certificate required for this ingress from. It does not matter which
  namespace your Ingress resides, as ClusterIssuers are non-namespaced resources.

* ``kubernetes.io/tls-acme: "true"`` - this annotation requires additional
  configuration of the ingress-shim (see above). Namely, a default issuer must be
  specified as arguments to the ingress-shim container.

* ``certmanager.k8s.io/acme-challenge-type`` - (**DEPRECATED**)
  by default, if the Issuer specified is an ACME issuer (either through
  ingress-shim's defaults, or with one of the above annotations), the
  ingress-shim will set the ACME challenge mechanism on the Certificate
  resource it creates to 'http01'. This annotation can be used to alter
  this behaviour. Must be one of 'http01' or 'dns01'.

* ``certmanager.k8s.io/acme-dns01-provider`` - (**DEPRECATED**)
  if the ACME challenge type has been set to dns01, this annotation **must**
  be specified to instruct cert-manager which DNS provider (as configured on
  the specified Issuer resource) should be used. This field is required if the
  challenge type is set to DNS01.

* ``certmanager.k8s.io/acme-http01-ingress-class`` - (**DEPRECATED**)
  if the ACME challenge type has been set to http01, this annotation allows you
  to configure ingress class that will be used to solve challenges for this
  ingress. Customising this is useful when you are trying to secure internal
  services, and need to solve challenges using different ingress class to that
  of the ingress. If not specified and the 'acme-http01-edit-in-place'
  annotation is not set, this defaults to the ingress class of the ingress
  resource.

* ``certmanager.k8s.io/acme-http01-edit-in-place: "true"`` - (**DEPRECATED**)
  if the ACME challenge type has been set to http01, and the ingress has the
  'kubernetes.io/tls-acme: true' annotation, this controls whether the ingress
  is modified 'in-place', or a new one created specifically for the http01
  challenge. If present, and set to "true" the existing ingress will be
  modified. Any other value, or the absence of the annotation assumes "false".

.. _kube-lego: https://github.com/jetstack/kube-lego
