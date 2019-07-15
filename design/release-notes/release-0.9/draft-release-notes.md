## New CertificateRequest Resource
A new resource has been introduced - `CertificateRequest` - that is used to
request certificates using a raw x509 certificate signing request. This resource
is not typically used by humans but rather by other controllers or services. For
example, the `Certificate` controller will now create a `CertificateRequest`
resource to resolve its own Spec.

Controllers to resolve `CertificateRequest`s are currently disabled by default
and enabled via the feature gate `CertificateRequestControllers`. This feature
is currently in Alpha and only the CA issuer has been implemented.

This resource is going to enable out of tree, external issuer controllers to
resolve requests. Other issuer implementations and details on how to develop an
out of tree issuer will follow in later releases. You can read more on the
motivations and road map in the [enhancement
proposal](https://github.com/jetstack/cert-manager/blob/master/design/20190708.certificate-request-crd.md)
or how this resource is used in the
[docs](https://docs.cert-manager.io/en/release-0.9/reference/certificaterequests.html).
