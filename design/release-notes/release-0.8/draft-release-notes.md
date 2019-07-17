Following on from the v0.7.x releases and a series of pre-release candidates,
cert-manager v0.8.0 is available at last!

This release packs in a tonne of stability improvements, as well as a whole load
of new features grinning

As part of this release, we're updating our API format in order to better
support the 1.0 release, which we hope to reach within the next few months.
This has been accomplished in a backwards-compatible for now, to make the
upgrade process easier, especially for users that manage large numbers of
certificate resources.

As well as the new release, we've also finally created a project logo!
For those of you who are attending KubeCon EU, we'll be handing out stickers
at the Jetstack booth from tomorrow onwards!

## Action required
The deployment manifests have now moved from being a part of our GitHub
repository and are now published alongside each image tag. Please double
check the installation guide for more information on where the manifests
can now be found. This change does not affect the Helm chart!

## New ACME configuration format
As part of stabilising our API surface, we've made a change to the way
you configure your ACME based certificates.

Instead of Certificate resources containing an extra certificate.spec.acme
field, which is only relevant for ACME certificates, the configuration has now
moved over to the Issuer resource instead. More details on this change can be
found in the upgrade notes.

## OpenShift installation instructions
In order to make it easier for users to run cert-manager on platforms other
than Kubernetes, we've improved our OpenShift support, including an official
installation guide for users of OpenShift.

If you use OpenShift in your organisation, check out the getting started section
for more information on how to get up and running!

## Webhook based ACME DNS01 solver
Over the last year and a half, we've had more than 15 pull requests to add new
ACME DNS01 providers to our codebase. It's been brilliant to see such vibrant
community involvement, however it's become infeasible for us to continue to
accept, test and maintain such a rapidly growing matrix of providers.

As a result, we've put together a new 'webhook' DNS01 solver type.
This allows you to create and install your own DNS01 providers without having
to make changes in cert-manager itself.

You can see an example repository to get started building your own over in the
cert-manager-webhook-example repo on GitHub.

This is a new and experimental feature, however we're excited to see the community
move to this new model of extending cert-manager.

## Switch to structured logging
As the project has grown, we've also increased the verbosity and frequency of our log messages.
Over time, this has become difficult to manage and work with, and so with the v0.8 release
we have begun the process of switching over our codebase to structured logging.

This should make it far easier to index, search and grep through log messages that cert-manager
emits.

Your feedback here is really valuable, so please open issues and comment on Slack if you
have any issues!

## Changelog
- make email address an optional field in ACME issuers (#1483, @DanielMorsing)
- Fix bug when handling resources that have lastTransitionTime set to null (#1628, @munnerz)
- Allow Openshift to install cert-manager chart (#1395, @JGodin-C2C)
- Update documentation for new 'solvers' field (#1623, @munnerz)
- Fix issue where ingress-shim would not clear old configuration when migrating to the new 'solvers' field (#1620, @munnerz)
- Add new issuer.spec.acme.solvers field that replaces certificate.spec.acme'in order to make all certificate resources portable between issuer types. The previously syntax is still supported to allow easy migration to the new configuration format. (#1450, @munnerz)
- Fixes additionalPrinterColumn formatting for Certificate resources (#1616, @munnerz)
- Fix update loop in certificates controller and add additional debug logging (#1602, @munnerz)
- Automatically retry expired Challenge resources (#1603, @munnerz)
- Build under MacOS. (#1601, @michaelfig)
- Disable the CAA check by default, and introduce a new --feature-gates=ValidateCAA=true option to enable it (#1585, @munnerz)
- Improve error handling when ACME challenges fail to Present or CleanUp (#1597, @munnerz)
- Add static label for solver identification to allow usage of custom service (#1575, @christianhuening)
- Fix issues running the cainjector controller on Kubernetes 1.9 (#1579, @munnerz)
- Fix upgrade bug where lastTransitionTime may be set to nil, rendering cert-manager inoperable without manual intervention (#1576, @munnerz)
- Add webhook based DNS01 provider (#1563, @munnerz)
- Add DNS01 provider conformance test suite (#1562, @munnerz)
- fix typo in the deployment template (#1546, @cpanato)
- Automatically generate LICENSES file (#1549, @munnerz)
- Switch to go modules for dependency management (#1523, @munnerz)
- Bump to use Go 1.12 (#1429, @munnerz)
- use authoritative nameservers for CAA checks (#1521, @DanielMorsing)
- Update certificate if issuer changes (#1512, @lentzi90)
- also whitelist ipv6 (#1497, @mdonoughe)
- Set default acmesolver image based on arch (#1494, @lentzi90)
- Improve logging in ACME HTTP01 solver (#1474, @munnerz)
- Run metrics server on cert-manager instances that have not been elected as leader (#1482, @kragniz)
- Switch to structured logging using logr (#1409, @munnerz)
- fixing the quickstart documentation to use the new helm chart repo charts.jetstack.io (#1468, @BradErz)
- Removes need for hostedZoneName to be specified. Uses discovered DNS zone name instead. (#1466, @logicfox)
