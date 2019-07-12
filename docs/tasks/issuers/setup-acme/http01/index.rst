===================================
Configuring HTTP01 Ingress Provider
===================================

This page contains details on the different options available on the ``Issuer``
resource's HTTP01 challenge solver configuration.

For more information on configuring ACME issuers and their API format, read the
:doc:`Setting up ACME Issuers <../index>` documentation.

How HTTP01 validations work
===========================

You can read about how the HTTP01 challenge type works on the
`Let's Encrypt challenge types page`_.

.. _`Let's Encrypt challenge types page`: https://letsencrypt.org/docs/challenge-types/#http-01-challenge

Options
=======

The HTTP01 Issuer supports a number of additional options.
For full details on the range of options available, read the
`reference documentation`_.

.. _`reference documentation`: https://docs.cert-manager.io/en/latest/reference/api-docs/index.html#acmeissuerhttp01config-v1alpha1

ingressClass
------------

If the ``ingressClass`` field is specified, cert-manager will create new
Ingress resources in order to route traffic to the 'acmesolver' pods, which
are responsible for responding to ACME challenge validation requests.

If this field is not specified, and ``ingressName`` is also not specified,
cert-manager will default to create **new** ingress resources but will **not**
set the ingress class on these resources, meaning **all** ingress controllers
installed in your cluster will server traffic for the challenge solver,
potentially occurring additional cost.

ingressName
-----------

If the 'ingressName' field is specified, cert-manager will edit the named
ingress resource in order to solve HTTP01 challenges.

This is useful for compatibility with ingress controllers such as ingress-gce_,
which utilise a unique IP address for each Ingress resource created.

This mode should be avoided when using ingress controllers that expose a single
IP for all ingress resources, as it can create compatibility problems with
certain ingress-controller specific annotations.

servicePort
-----------

In rare cases it might be not possible/desired to use NodePort as type for the
http01 challenge response service, e.g. because of Kubernetes limit
restrictions. To define which Kubernetes service type to use during challenge
response specify the following http01 config:

.. code-block:: yaml

       http01:
         # Valid values are ClusterIP and NodePort
         serviceType: ClusterIP

By default type NodePort will be used when you don't set http01 or when you set
serviceType to an empty string. Normally there's no need to change this.

podTemplate
-----------

You may wish to change or add to the labels and annotations of solver pods.
These can be configured under the ``metadata`` field under ``podTemplate``. 

Similarly, you can set the nodeSelector, tolerations and affinity of solver
pods by configuring under the ``spec`` field of the ``podTemplate``. No other
spec fields can be edited.

An example of how you could configure the template is as so:

.. code-block:: yaml
   :linenos:
   :emphasize-lines: 13-20

   apiVersion: certmanager.k8s.io/v1alpha1
   kind: Issuer
   metadata:
     name: ...
   spec:
     acme:
       server: ...
       privateKeySecretRef:
         name: ...
       solvers:
       - http01:
           ingress:
             podTemplate:
               metadata:
                 labels:
                   foo: "bar"
                   env: "prod"
               spec:
                 nodeSelector:
                   bar: baz

The added labels and annotations will merge on top of the cert-manager defaults,
overriding entries with the same key.

No other fields can be edited. 