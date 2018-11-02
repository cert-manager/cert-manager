=========================
Infoblox
=========================

This provider uses the fields mentioned in the following example in
order to work. Also it uses a Kubernetes ``Secret`` Resource. In the
following example, the secret will have to be named ``infoblox``
and have a subkey ``password`` with the password in it.


.. code-block:: yaml

   infoblox:
     gridHost: "infoblox.example.com"
     wapiUsername: "infoblox_user"
     wapiPort: 443
     wapiVersion: "2.7.3"
     sslVerify: true
     wapiPasswordSecret:
       name: infoblox
       key: password

