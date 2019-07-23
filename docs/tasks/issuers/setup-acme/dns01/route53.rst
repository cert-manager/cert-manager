=========================
Amazon Route53
=========================

This guide explains how to set up an Issuer, or ClusterIssuer, to use Amazon Route53 to solve DNS01 ACME challenges. It's advised you read the :doc:`DNS01 Challenge Provider <./index>` page first for a more general understanding of how cert-manager handles DNS01 challenges.

.. note::
   This guide assumes that your cluster is hosted on Amazon Web Services (AWS) and that you already have a hosted zone in Route53.

Set up a IAM Role
========================

Cert-manager needs to be able to add records to Route53 in order to solve the DNS01 challenge. To enable this, create a IAM policy with the following permissions:

.. code-block:: json

   {
       "Version": "2012-10-17",
       "Statement": [
           {
               "Effect": "Allow",
               "Action": "route53:GetChange",
               "Resource": "arn:aws:route53:::change/*"
           },
           {
               "Effect": "Allow",
               "Action": "route53:ChangeResourceRecordSets",
               "Resource": "arn:aws:route53:::hostedzone/*"
           },
           {
               "Effect": "Allow",
               "Action": "route53:ListHostedZonesByName",
               "Resource": "*"
           }
       ]
   }

.. note::
  The ``route53:ListHostedZonesByName`` statement can be removed if you specify
  the (optional) ``hostedZoneID``. You can further tighten the policy by limiting the hosted
  zone that cert-manager has access to (e.g. ``arn:aws:route53:::hostedzone/DIKER8JEXAMPLE``).

Credentials
========================

You have two options for the set up: Either create a user or a role and attach that policy from above.
Using a role is considered best practice because you do not have to store permanent credentials in a secret.

Cert-manager supports two ways of specifying credentials:

* explicit by providing a ``accessKeyID`` and ``secretAccessKey``
* or implicit (using `metadata service <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html>`_  or `env vars or credentials file <https://docs.aws.amazon.com/sdk-for-go/v1/developer-guide/configuring-sdk.html#specifying-credentials>`_)

Cert-manager also supports specifying a ``role`` to enable cross-account access and/or to limit the access for the cert-manager. Integration with `kiam <https://github.com/uswitch/kiam>`_ and `kube2iam <https://github.com/jtblin/kube2iam>`_ should work out of the box.


Cross account access
_____________________

Example: Account A manages a Route53 DNS Zone. Now you want account X to be able to manage records in that zone.

First, create a role with the policy above (let's call the role ``dns-manager``) and attach a trust relationship like the one below. Make sure role ``cert-manager`` in account X exists:

.. code-block:: json

   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Principal": {
           "AWS": "arn:aws:iam::XXXXXXXXXXX:role/cert-manager"
         },
         "Action": "sts:AssumeRole"
       }
     ]
   }

This allows the role ``cert-manager`` in account X to manage the Route53 DNS Zone in account A.
For more information visit the `official documentation <https://docs.aws.amazon.com/IAM/latest/UserGuide/tutorial_cross-account-with-roles.html>`_.


Creating a Issuer (or ClusterIssuer)
====================================

Here is an example configuration for a ClusterIssuer:

.. code:: yaml

   apiVersion: certmanager.k8s.io/v1alpha1
   kind: ClusterIssuer
   metadata:
     name: letsencrypt-prod
   spec:
     acme:
       ...
       solvers:

       # example: cross-account zone management for example.com
       # this solver uses ambient credentials (i.e. inferred from the environment or EC2 Metadata Service)
       # to assume a role in a different account
       - selector:
           dnsZones:
             - "example.com"
         dns01:
           route53:
             region: us-east-1
             hostedZoneID: DIKER8JEXAMPLE # optional, see bpolicy above
             role: arn:aws:iam::XXXXXXXXXXXX:role/dns-manager

       # this solver handles foobar.cloud challenges
       # and uses explicit credentials
       - selector:
           dnsZones:
             - "foobar.cloud"
         dns01:
           route53:
             region: eu-central-1
             accessKeyID: AKIAIOSFODNN7EXAMPLE
             secretAccessKeySecretRef:
               name: prod-route53-credentials-secret
               key: secret-access-key
             # you can also assume a role with these credentials
             role: arn:aws:iam::XXXXXXXXXXXX:role/dns-manager
