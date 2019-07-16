## Changelog since v0.1.0
### Action Required
- Move to 'jetstack' organisation. Action required: this will require updating your existing deployments to point to the new image repository, as new tags will not be pushed to the old 'jetstackexperimental/cert-manager-controllerrepository. Ahelm upgrade` should take care of this. (#145, @munnerz)
- Set the Kubernetes secret type to TLS. Action required: this will cause renewals of existing certificates to fail. You must delete certificates that have been previously produced by cert-manager else cert-manager may enter a renewal loop when saving the new certificates. Alternatively, you may specify a new secret to store your certificate in and manually update your ingress resource/applications to reference the new secret. (#172, @munnerz)

### Other notable changes
- No longer support ClusterIssuer resources when cert-manager is running with --namespace flag set (#179, @munnerz)
- Overcome 'registration already exists for provider key' errors in ACME provider by auto-detecting lost ACME registration URIs (#171, @munnerz)
- Fix checking for invalid data in issuer secrets (#170, @munnerz)
- Fix bug in ACME HTTP01 solver causing self-check to return true before paths have propagated (#166, @munnerz)
- Fix panic if the secret named in an ACME issuer exists but contains invalid data (or no data) (#165, @munnerz)
- Ensure 5 consecutive HTTP01 self-checks pass before issuing ACME certificate (#156, @munnerz)
- Fix race condition in ACME HTTP01 solver when validating multiple domains (#155, @munnerz)
- Consistently use glog throughout (#126, @munnerz)
