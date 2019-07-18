===================
CertificateRequests
===================

A 'CertificateRequest' is a resource in cert-manager that is used to request
x509 certificates from an issuer. The resource contains a base64 encoded string
of a PEM encoded certificate request which is sent to the referenced issuer. A
successful issuance will return a signed certificate, based on the certificate
signing request. 'CertificateRequets' are typically consumed and managed by
controllers or other systems and should not be used by humans - unless
specifically needed.

.. note::
   To enable cert-manager's internal CertificateRequest controllers, supply the
   following feature gate:
   `--feature-gates=CertificateRequestControllers=true`

A simple CertificateRequest looks like the following:

.. code-block:: yaml
   :linenos:

   apiVersion: certmanager.k8s.io/v1alpha1
   kind: CertificateRequest
   metadata:
     name: my-ca-cr
   spec:
     csr: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQzNqQ0NBY1lDQVFBd2daZ3hDekFKQmdOVkJBWVRBbHBhTVE4d0RRWURWUVFJREFaQmNHOXNiRzh4RFRBTApCZ05WQkFjTUJFMXZiMjR4RVRBUEJnTlZCQW9NQ0VwbGRITjBZV05yTVJVd0V3WURWUVFMREF4alpYSjBMVzFoCmJtRm5aWEl4RVRBUEJnTlZCQU1NQ0dwdmMyaDJZVzVzTVN3d0tnWUpLb1pJaHZjTkFRa0JGaDFxYjNOb2RXRXUKZG1GdWJHVmxkWGRsYmtCcVpYUnpkR0ZqYXk1cGJ6Q0NBU0l3RFFZSktvWklodmNOQVFFQkJRQURnZ0VQQURDQwpBUW9DZ2dFQkFLd01tTFhuQkNiRStZdTIvMlFtRGsxalRWQ3BvbHU3TlZmQlVFUWl1bDhFMHI2NFBLcDRZQ0c5Cmx2N2kwOHdFMEdJQUgydnJRQmxVd3p6ZW1SUWZ4YmQvYVNybzRHNUFBYTJsY2NMaFpqUlh2NEVMaER0aVg4N3IKaTQ0MWJ2Y01OM0ZPTlRuczJhRkJYcllLWGxpNG4rc0RzTEVuZmpWdXRiV01Zeis3M3ptaGZzclRJUjRzTXo3cQpmSzM2WFM4UkRjNW5oVVcyYU9BZ3lnbFZSOVVXRkxXNjNXYXVhcHg2QUpBR1RoZnJYdVVHZXlZUUVBSENxZmZmCjhyOEt3YTFYK1NwYm9YK1ppSVE0Nk5jQ043OFZnL2dQVHNLZmphZURoNWcyNlk1dEVidHd3MWdRbWlhK0MyRHIKWHpYNU13RzJGNHN0cG5kUnRQckZrU1VnMW1zd0xuc0NBd0VBQWFBQU1BMEdDU3FHU0liM0RRRUJDd1VBQTRJQgpBUUFXR0JuRnhaZ0gzd0N3TG5IQ0xjb0l5RHJrMUVvYkRjN3BJK1VVWEJIS2JBWk9IWEFhaGJ5RFFLL2RuTHN3CjJkZ0J3bmlJR3kxNElwQlNxaDBJUE03eHk5WjI4VW9oR3piN0FVakRJWHlNdmkvYTJyTVhjWjI1d1NVQmxGc28Kd005dE1QU2JwcEVvRERsa3NsOUIwT1BPdkFyQ0NKNnZGaU1UbS9wMUJIUWJSOExNQW53U0lUYVVNSFByRzJVMgpjTjEvRGNMWjZ2enEyeENjYVoxemh2bzBpY1VIUm9UWmV1ZEp6MkxmR0VHM1VOb2ppbXpBNUZHd0RhS3BySWp3ClVkd1JmZWZ1T29MT1dNVnFNbGRBcTlyT24wNHJaT3Jnak1HSE9tTWxleVdPS1AySllhaDNrVDdKU01zTHhYcFYKV0ExQjRsLzFFQkhWeGlKQi9Zby9JQWVsCi0tLS0tRU5EIENFUlRJRklDQVRFIFJFUVVFU1QtLS0tLQo=
     isCA: false
     duraton: 90d
     issuerRef:
       name: ca-issuer
       # We can reference ClusterIssuers by changing the kind here.
       # The default value is Issuer (i.e. a locally namespaced Issuer)
       kind: Issuer
       group: certmanager.k8s.io

This CertificateRequest will make cert-manager attempt to make the Issuer
``letsencrypt-prod`` in the default issuer pool ``certmanager.k8s.io``, return a
certificate based upon the certificate signing request. Other groups can be
specified inside the ``issuerRef`` which will change the targeted issuers to other
external, third party issuers you may have installed.

The resource also exposes the option for stating the certificate as CA and
requested validity duration.

A successful issuance of the certificate signing request will cause an update to
the resource, setting the status with the signed certificate, the CA of the
certificate (if available), and setting the `Ready` condition to `True`.

Whether issuance of the controller was successful or not, a retry of the
issuance will _not_ happen. It is the responsibility of some other controller to
manage the logic and life cycle of CertificateRequets.

----------
Conditions
----------

CertificateRequests have a set of strongly defined conditions that should be
used and relied upon by controllers or services to make decisions on what
actions to take next on the resource. Each condition consists of the pair
`Ready` - a boolean value, and `Reason` - a string. The set of values and
meanings are as follows:

+---------+-----------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| *Ready* | *Reason*        | Condition Meaning                                                                                                                                                                                                                             |
+=========+=================+===============================================================================================================================================================================================================================================+
| False   | Pending         | The CertificateRequest is currently pending, waiting for some other operation to take place. This could be that the Issuer does not exist yet or the Issuer is in the process of issuing a certificate.                                       |
+---------+-----------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| False   | Failed          | The certificate has failed to be issued - either the returned certificate failed to be decoded or an instance of the referenced issuer used for signing failed. No further action will be taken on the CertificateRequest by it's controller. |
+---------+-----------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| True    | Issued          | A signed certificate has been successfully issued by the referenced Issuer.                                                                                                                                                                   |
+---------+-----------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
