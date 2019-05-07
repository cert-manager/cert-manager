=========================
Amazon Route53
=========================


.. code:: yaml
   :emphasize-lines: 10-16

   apiVersion: certmanager.k8s.io/v1alpha1
   kind: Issuer
   metadata:
     name: example-issuer
   spec:
     acme:
       ...
       solvers:
       - dns01:
           route53:
             region: eu-west-1
             # optional if ambient credentials are available; see ambient credentials documentation
             accessKeyID: AKIAIOSFODNN7EXAMPLE
             secretAccessKeySecretRef:
               name: prod-route53-credentials-secret
               key: secret-access-key

Cert-manager requires the following IAM policy.

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

The ``route53:ListHostedZonesByName`` statement can be removed if you specify
the optional hosted zone ID (``spec.acme.dns01.providers[].hostedZoneID``) on
the Issuer resource. You can further tighten this policy by limiting the hosted
zone that cert-manager has access to (replace ``arn:aws:route53:::hostedzone/*``
with ``arn:aws:route53:::hostedzone/DIKER8JPL21PSA``, for instance).