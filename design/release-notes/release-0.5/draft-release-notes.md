# Highlights
## Resource validation webhook
Following the v0.4.0 release, we have now added a 'validating webhook' for our API resources. This will help prevent invalid configurations being submitted to the API server.

This feature is disabled by default.

Information on enabling the new webhook component can be found in the Resource Validation Webhook document.

## New Certificate options
A number of new fields have been added to the Certificate resource type:

- keyAlgorithm - support alternative private key algorithms (e.g. rsa or ecdsa) for generated certificates.
- keySize - allow specifying an alternative key bit size
- isCA - allows generating certificates with the 'signing' usage set
- organization - allows specifying values for the 'O' field of Certificates (for supported providers)
New fields like this make cert-manager more useful for applications beyond just securing Ingress, as well as allowing users to continue meeting their security requirements for x509 certificates.

## New ACME DNS providers
This release includes two new DNS provides for the ACME Issuer:

- acme-dns
- RFC2136
These additions should help more users begin using cert-manager with their chosen DNS provider, without having to delegate to an alternate provider that is supported tada

# Changelog
## General
- Add renew-before-expiry-duration option to configure how long before expiration a certificate should be attempted to be renewed (#801, @munnerz)
- Add validation webhooks for API types (#478, @munnerz)
- Add extended issuer-specific validation to certificates at runtime (#761, @kragniz)
## API changes
- Adds new fields: "keyAlgorithm", "keySize" onto CertificateSpec to allow specifying algorithm (rsa, ecdsa) and key size to use when generating TLS keys (#722, @badie)
- Add isCA field to Certificates (#658, @munnerz)
- Add "organization" field to certificate objects (#838, @Queuecumber)
## CA Issuer
- Don't bundle the CA certificate when using the self signed issuer (#811, @munnerz)
## ACME
- Fix issue that could cause Certificates to fail renewal (#800, @munnerz)
- Add acme-dns as a dns01 provider (#787, @Queuecumber)
- [jjo] fix panic from acmedns.go constructor failure (#858, @jjo)
- Fix cloudflare provider failing on cleanup if no record is found (#849, @frankh)
- Fixed Route53 cleanup errors for already deleted records. (#746, @euank)
- Add support for delegating DNS-01 challenges using CNAME records. (#670, @gurvindersingh)
- Fix a race that could cause ACME orders to fail despite them being in a 'valid' state (#764, @munnerz)
- Fix cleanup of Google Cloud DNS hosted zone for dns-01 challenge records (#754, @kragniz)
- Fix issue causing existing Ingresses to not be cleaned up properly after HTTP01 challenges in some cases (#831, @munnerz)
- Allow metadata server authentication for Google Cloud DNS (#664, @rpahli)
- Add RFC2136 DNS Provider (#661, @splashx)
