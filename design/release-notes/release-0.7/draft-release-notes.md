## Action Required
The Helm chart rbac.create option has moved to be global.rbac.create.
Users of the Helm chart will need to update their install overrides to use
the new format.

The Helm chart has now moved to be hosted on charts.jetstack.io, and
exposed via the Helm Hub. This allows us to make
and test changes to the Helm chart more easily, and better manage versioning.

## Highlights
### Venafi Issuer type
This release introduces a new issuer type for Venafi Cloud and Venafi Trust
Protection Platform.

The Venafi adapter will be built out over the coming months to improve the
integration and expose more of the Venafi platform's advanced functionality.

### New cainjector controller
This release introduces support for injecting CA bundles into Kubernetes
{Validating,Mutating}WebhookConfiguration & APIService resources.

You can utilise the new controller by adding the certmanager.k8s.io/inject-ca-from
annotation to your webhook and APIService resources.

This was needed in order to improve our own deployment of the 'webhook'
component as part of this release.

### Improved webhook deployment
The v0.6 release utilised an additional ca-sync CronJob resource that allowed
us to secure the webhook component automatically using cert-manager itself.

Thanks to the new cainjector controller described above, we have now removed
this CronJob altogether in favour of using the far more reliable controller.

### Experimental ARM support
Support for ARM was adding as part of this release (#1212). We do not currently
have automated testing using ARM platforms, so this feature is still marked
experimental.

To utilise the new ARM support, you'll need to update your manifests and append
the architecture to the image name (i.e. quay.io/jetstack/cert-manager-controller-arm64:v0.7.0).

### Easier debugging of failing ACME challenges
The introduction of the Challenge resource in the last release has allowed us
to provide better means for debugging failures.

In the v0.7.0 release, if a self check or ACME validation is failing for some
reason, this information will be displayed when running kubectl get and
kubectl describe.

### Changelog since v0.6.0
- Add Venafi Cloud & TPP issuer type (#1250, @munnerz)
- cainjector: add support for injecting apiserver CA (#1420, @munnerz)
- Generate temporary self signed certificate whilst waiting for issuer to issue certificate (#1392, @munnerz)
- Added kubeprod as an alternative way to deploy cert-manager to the documentation (#1421, @arapulido)
- Use new cainjector controller for webhook APIService resource (#1415, @munnerz)
- Adds a controller for injecting CA data into webhooks and APIServices (#1398, @DirectXMan12)
- Bump Kubernetes dependencies to v1.13 (#1268, @munnerz)
- Use charts.jetstack.io instead of the helm/charts repository to publish Helm chart (#1377, @munnerz)
- Recreate dead solver pods during self-check (#1388, @DanielMorsing)
- Improve RFC2136 DNS01 provider documentation (#944, @briantopping)
- Add more information to Google CloudDNS guide (#1295, @wwwil)
- Add validation schema to CRD resources (#1322, @munnerz)
- Fire additional events when syncing ACME certificates fails (#1327, @munnerz)
- Publish arm32 and arm64 images for all cert-manager components (#1212, @munnerz)
- Extend ACME self check to check CAA records (#1325, @DanielMorsing)
- Bump Kubernetes apimachinery dependencies to v1.10.12 (#1344, @munnerz)
- Increase acmesolver default cpu resource limit to 100m (#1335, @munnerz)
- Fix potential race when updating secret resource (#1318, @munnerz)
- Fix bug causing certficates to be re-issued endlessly in certain edge cases (#1280, @munnerz)
- Fix bug when specify certificate keyAlgorithm without an explicit keySize (#1309, @munnerz)
- Bump Go version to 1.11.5 (#1304, @munnerz)
- Fix typo in SelfSigned Issuer in webhook deployment manifests (#1294, @munnerz)
- Add IP Address in CSR (#1128, @lrolaz)
- Allow to use PKCS#8 encoded private keys in CA issuers. (#1191, @chr-fritz)
- Add webhook troubleshooting guide (#1288, @munnerz)
- Overhaul documentation and add additional content (#1279, @munnerz)
- Increase x509 certificate duration from 90d to 1y for webhook component certificates (#1276, @munnerz)
- Fix bug where --dns01-recursive-nameservers flag was not respected when looking up the zone to update for a DNS01 challenge (#1266, @munnerz)
- Reuse acme clients to limit use of nonce/directory/accounts endpoints (#1265, @DanielMorsing)
- Surface self-check errors in challenge resource (#1244, @DanielMorsing)
