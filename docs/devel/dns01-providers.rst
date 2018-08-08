============================
Contributing DNS01 providers
============================

Steps to add a ``FooDNS`` DNS-01 provider:

1. Create a new package under ``pkg/issuer/acme/dns/foodns``.
   This is where all the code to interact with the DNS providers API will live.
2. Implement functions to match the solver interface (``Present``, ``CleanUp`` and ``Timeout``).
   Use an existing provider for reference.
   Most of the cert-manager providers are based off
   https://github.com/xenolf/lego, so if lego supports the DNS provider you
   want to add, it's fairly easy to copy it over and make modifications to fit
   with the cert-manager codebase. Examples of the changes required:

   - replace uses of ``github.com/xenolf/lego/acme`` with ``github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util``.
   - replace uses of ``github.com/xenolf/lego/log`` with ``github.com/golang/glog``.
   - remove references to ``github.com/xenolf/lego/platform/config/env``.
     cert-manager does not use environment variables for internal configuration, so calls to this package should not be required.

3. Add unit test coverage for this package.
4. Add your provider configuration types to the API (located in ``pkg/apis/certmanager/v1alpha1/types.go``) and regenerate code (run ``./hack/update-codegen.sh``).
   New API types should have an associated short documentation string,
   which is added to the reference API documentation (run ``./hack/update-reference-docs-dockerized.sh`` to update the API documentation).
5. Register the provider in ``pkg/issuer/acme/dns``:

   - The constructor for the provider needs adding to ``dnsProviderConstructors``,
   - ``solverForIssuerProvider`` must be updated to handle retrieving any information for the new provider (for example, fetching credentials from a secret)
     and constructing a new instance of the provider.

6. Add coverage for the provider to ``pkg/issuer/acme/dns/dns_test.go``.
7. Add example configuration for the new provider to ``docs/reference/issuers/acme/dns01.rst``.
   The more information here the better,
   this example and corresponding documentation should inform users how to use and configure this backend,
   as well as mentioning any nuances with using this particular provider.
8. Test your provider out against a real account, and make sure you can issue a Certificate.
9. Submit your new provider to cert-manager!

Things to watch out for:

- Assume that at any point the cert-manager process may restart.
  Make sure values required for operations like ``CleanUp`` are not solely stored in memory.
