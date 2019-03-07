=========================
DigitalOcean
=========================

This provider uses a Kubernetes ``Secret`` Resource to work. In the
following example, the secret will have to be named ``digitalocean-dns``
and have a subkey ``access-token`` with the token in it.

To create a Personnal Access Token, see `DigitalOcean documentation <https://www.digitalocean.com/docs/api/create-personal-access-token/>`_. 
Handy direct link: https://cloud.digitalocean.com/account/api/tokens/new


.. code-block:: yaml
   :emphasize-lines: 10-13

   apiVersion: certmanager.k8s.io/v1alpha1
   kind: Issuer
   metadata:
     name: example-issuer
   spec:
     acme:
       ...
       solvers:
       - dns01:
           digitalocean:
             tokenSecretRef:
               name: digitalocean-dns
               key: access-token
