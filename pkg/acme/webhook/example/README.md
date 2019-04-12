# ACME webhook example

The ACME issuer type supports an optional 'webhook' solver, which can be used
to implement custom DNS01 challenge solving logic.

This is useful if you need to use cert-manager with a DNS provider that is not
officially supported in cert-manager core.

## Why not in core?

As the project & adoption has grown, there has been an influx of DNS provider
pull requests to our core codebase. As this number has grown, the test matrix
has become un-maintainable and so, it's not possible for us to certify that
providers work to a sufficient level.

By creating this 'interface' between cert-manager and DNS providers, we allow
users to quickly iterate and test out new integrations, and then packaging
those up themselves as 'extensions' to cert-manager.

We can also then provide a standardised 'testing framework', or set of
conformance tests, which allow us to validate the a DNS provider works as
expected.

## Creating your own webhook

Webhook's themselves are deployed as Kubernetes API services, in order to allow
administrators to restrict access to webhooks with Kubernetes RBAC.

This is important, as otherwise it'd be possible for anyone with access to your
webhook to complete ACME challenge validations and obtain certificates.

To make the set up of these webhook's easier, we provide a template repository
that can be used to get started quickly.

### Creating your own repository

### Running the test suite

All DNS providers **must** run the DNS01 provider conformance testing suite,
else they will have undetermined behaviour when used with cert-manager.

**It is essential that you configure and run the test suite when creating a
DNS01 webhook.**

An example Go test file has been provided in [main_test.go]().

You can run the test suite with:

```bash
$ TEST_ZONE_NAME=example.com go test .
```

The example file has a number of areas you must fill in and replace with your
own options in order for tests to pass.
