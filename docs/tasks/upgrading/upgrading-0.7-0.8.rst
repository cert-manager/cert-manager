===========================
Upgrading from v0.7 to v0.8
===========================

Upgrading from v0.7 to v0.8 is possible using the regular :doc:`upgrade guide <./index>`.

All resources should continue to operate as before.

As part of v0.8, a new format **for configure ACME Certificate resources** has
been introduced. Notably, challenge solver configuration has moved **from**
the Certificate resource (under ``certificate.spec.acme``) and now resides on
your configure **Issuer** resource, under ``issuer.spec.acme.solvers``.

This allows Certificate resources to be portable between different Issuer types.

Both the old and the new format of configuration are supported in the v0.8
release, so it is possible to **incrementally upgrade your resources** if you
have a large, multi-team deployment of cert-manager that makes it complex to
upgrade all manifests at once in place.

After upgrading, it is **strongly recommended** that you update your ACME
Issuer and Certificate resources to the :doc:`new format </tasks/issuers/setup-acme/index>`.

We will be removing support for the old format ahead of the 1.0 release.

The documentation has been updated to reflect configuring using the new format,
and as such, exhaustive information can be found in the :doc:`/tasks/issuers/setup-acme/index`
document.

Performing an incremental switch to the new format
==================================================

The following guide assumes you have 2 'solver types' currently in use across
your cert-manager deployment - one for DNS01 and another for HTTP01 using an
ingress class of ``nginx``. The nginx based HTTP01 solver will be configured as
the default solver type for Certificate resources that reference our issuer.

You can adjust the instructions below to fit your own configuration, either
with more or less solvers as appropriate.

First, we will modify our ACME Issuer to add the new HTTP01 and DNS01 solvers.
This operation **will not** effect any existing Certificates that already
explicitly set a ``certificate.spec.acme`` field:

.. code-block:: yaml
   :linenos:
   :emphasize-lines: 12-17, 28-52

   apiVersion: certmanager.k8s.io/v1alpha1
   kind: ClusterIssuer
   metadata:
     name: letsencrypt-staging
   spec:
     acme:
       email: user@example.com
       server: https://acme-staging-v02.api.letsencrypt.org/directory
       privateKeySecretRef:
         name: example-issuer-account-key

       # The HTTP01 and DNS01 fields are now **deprecated**.
       # We leave them in place here so that any Certificates that still
       # specify a ``certificate.spec.acme`` stanza will continue to operate
       # correctly.
       # cert-manager will decide which configuration to use based on whether
       # the Certificate contains a ``certificate.spec.acme`` stanza.
       http01: {}
       dns01:
         providers:
         - name: cloudflare
           cloudflare:
             email: my-cloudflare-acc@example.com
             apiKeySecretRef:
               name: cloudflare-api-key-secret
               key: api-key

       # Configure the challenge solvers.
       solvers:
       # An empty selector will 'match' all Certificate resources that
       # reference this Issuer.
       - selector: {}
         http01:
           ingress:
             class: nginx
       - selector:
           # Any Certificate resources, or Ingress resources that use
           # ingress-shim and match the below label selector will use this
           # configured solver type instead of the default nginx based HTTP01
           # solver above.
           # You can continue to add new solver types if needed.
           # The most specific 'match' will be used.
           matchLabels:
             use-cloudflare-solver: "true"
         dns01:
           # Adjust the configuration below according to your environment.
           # You can view more example configurations for different DNS01
           # providers in the documentation: https://docs.cert-manager.io/en/latest/tasks/issuers/setup-acme/dns01/index.html
           cloudflare:
             email: my-cloudflare-acc@example.com
             apiKeySecretRef:
               name: cloudflare-api-key-secret
               key: api-key


By retaining both the old and the new configuration format on the Issuer
resource, we can begin the process of incrementally upgrading our Certificate
resources.

Any Certificate resources that you have manually created (i.e. not managed by
ingress-shim) must then be updated to remove the ``certificate.spec.acme``
stanza.

Given the above configuration, certificates will use the HTTP01 solver with the
``nginx`` ingress class in order to solve ACME challenges.

If a particular certificate requires a wildcard, or you simply want to use
DNS01 for that certificate instead of HTTP01, you can add the ``use-cloudflare-solver: "true"``
label to your Certificate resources and the appropriate ACME challenge solver
will be used.

Upgrading ingress-shim managed certificates to the new format
=============================================================

When using ingress-shim, cert-manager itself will create and manage your
Certificate resource for you.

In order to support both the old and the new format simultaneously,
ingress-shim will continue to set the ``certificate.spec.acme`` field on
Certificate resources it manages.

In order to force ingress-shim to also use the new format, you must **remove**
the old format configuration from your Issuer resources (i.e. ``issuer.spec.acme.http01``
and ``issuer.spec.acme.dns01``).

When ingress-shim detects that these fields are not specified, it will
clear/not set the ``certificate.spec.acme`` field.

If you are managing a certificate using ingress-shim that requires an
alternative solver type (other than the default solver configured on the issuer
which in this instance is the HTTP01 nginx solver), you can add labels to the
Ingress resource which will be automatically copied across to the Certificate
resource:

.. code-block:: yaml
   :linenos:
   :emphasize-lines: 6

   apiVersion: extensions/v1beta1
   kind: Ingress
   metadata:
     name: my-test-ingress
     labels:
       use-cloudflare-solver: "true"

Confirming all Certificate resources are upgraded
=================================================

In order to check if any of your Certificate resources still have the old
configuration format, you can run the following command:

.. code-block:: shell

   kubectl get certificate --all-namespaces \
     -o custom-columns="NAMESPACE:.metadata.namespace,NAME:.metadata.name,OWNER:.metadata.ownerReferences[0].kind,OLD FORMAT:.spec.acme"

   NAMESPACE   NAME    OWNER    OLD FORMAT
   default     test    <none>   <none>
   default     test2   Ingress  map[config:[map[domains:[abc.com] http01:map[ingressClass:nginx]]]]

In the above example, we can see there are two Certificate resources.

The ``test`` resource has been updated to no longer include the
``certificate.spec.acme`` field.

The ``test2`` resource still specifies the old configuration format, however it
**also** has an OwnerReference linking it to an **Ingress** resource.
This is because the ``test2`` Certificate resource is managed by ingress-shim.

As mentioned in the previous section, ingress-shim managed certificates will
only switch to the new format once the **old format** configuration on the
**Issuer** resource has been removed. This means we need to continue to the
next section in order to remove the old format configuration altogether from
**Issuer** resource in order for ingress-shim to automatically migrate the
``test2`` Certificate resource.

Removing old configuration altogether
=====================================

Once we've verified that all non-ingress-shim managed Certificate resources
have been updated to not specify the ``certificate.spec.acme`` stanza using the
command above, we can proceed to remove the ``issuer.spec.acme.http01`` and
``issuer.spec.acme.dns01`` stanzas from our Issuer resources.
Once completed, the Issuer resource from the previous section should look like
the following:

.. code-block:: yaml
   :linenos:

   apiVersion: certmanager.k8s.io/v1alpha1
   kind: ClusterIssuer
   metadata:
     name: letsencrypt-staging
   spec:
     acme:
       email: user@example.com
       server: https://acme-staging-v02.api.letsencrypt.org/directory
       privateKeySecretRef:
         name: example-issuer-account-key

       # Configure the challenge solvers.
       solvers:
       # An empty selector will 'match' all Certificate resources that
       # reference this Issuer.
       - selector: {}
         http01:
           ingress:
             class: nginx
       - selector:
           # Any Certificate resources, or Ingress resources that use
           # ingress-shim and match the below label selector will use this
           # configured solver type instead of the default nginx based HTTP01
           # solver above.
           # You can continue to add new solver types if needed.
           # The most specific 'match' will be used.
           matchLabels:
             use-cloudflare-solver: "true"
         dns01:
           # Adjust the configuration below according to your environment.
           # You can view more example configurations for different DNS01
           # providers in the documentation: https://docs.cert-manager.io/en/latest/tasks/issuers/setup-acme/dns01/index.html
           cloudflare:
             email: my-cloudflare-acc@example.com
             apiKeySecretRef:
               name: cloudflare-api-key-secret
               key: api-key

After applying the above Issuer resource, you should re-run the command from
the last section to verify that the remaining ingress-shim managed Certificate
resources have also been updated to the new format:

.. code-block:: shell

   kubectl get certificate --all-namespaces \
     -o custom-columns="NAMESPACE:.metadata.namespace,NAME:.metadata.name,OWNER:.metadata.ownerReferences[0].kind,OLD FORMAT:.spec.acme"

   NAMESPACE   NAME    OWNER    OLD FORMAT
   default     test    <none>   <none>
   default     test2   Ingress  <none>

Manually triggering a Certificate to be issued to validate the full config
==========================================================================

To be certain that you've correctly configured your new Issuer/Certificate
resources, it is advised you attempt to issue a new Certificate after removing
the old configuration format.

To do so, you can either:

* update the ``secretName`` field of an existing Certificate resource
* add an additional ``dnsName`` to one of your existing Certificate resources
* create a new Certificate resource

You should ensure that your Certificates are still be issued correctly to avoid
any potential issues at renewal time.

Special notes for ingress-gce users
===================================

Users of the ``ingress-gce`` ingress controller may find that their experience
configuring cert-manager to solve challenges using HTTP01 validation is
slightly more painful using the new format, as it requires the ``ingressName``
field to be specified as a distinct ``solver`` on the Issuer resource (as
opposed to in the past where the ingressName could be specified as a field on
the ``Certificate`` resource).

This is a `known issue`_, and a workaround is scheduled to be completed for
v0.9.

In the meantime, ingress-gce users can either choose to manually create a
new solver entry per Ingress resource they want to use to solve challenges, or
otherwise continue to use the **old format** until a suitable alternative
appears in v0.9.

.. _known issue: https://github.com/jetstack/cert-manager/issues/1666
