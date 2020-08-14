{
  prometheusAlerts+:: {
    groups+: [{
      name: 'cert-manager',
      rules: [
        {
          alert: 'certmanager_absent',
          expr: 'absent(up{job="%(certManagerJobLabel)s"})' % $._config,
          'for': '10m',
          labels: {
            severity: 'critical',
          },
          annotations: {
            message: 'Cert Manager has dissapeared from Prometheus service discovery',
            impact: "New certificates will not be able to be minted, and existing ones can't be renewed until cert-manager is back.",
            action: 'Investigate why Cert Manager has stopped running, and fix. It could also be an issue with the PodMonitor CRD.',
          },
        },
        {
          alert: 'certmanager_cert_expiry_soon',
          expr: |||
            avg by (exported_namespace, name) (
              certmanager_certificate_expiration_timestamp_seconds - time()
            ) < (21 * 24 * 3600) # 21 days in seconds
          |||,
          'for': '1h',
          labels: {
            severity: 'critical',
          },
          annotations: {
            message: 'The cert `{{ $labels.name }}` is {{ $value | humanizeDuration }} from expiry, it should have renewed over a week ago',
            impact: 'The domain that this cert covers will be unavailable after {{ $value | humanizeDuration }}',
            action: 'Ensure cert-manager is configured correctly, no lets-encrypt rate limits are being hit. To break glass, buy a cert.',
            dashboard: $._config.grafanaExternalUrl + '/d/TvuRo2iMk/cert-manager',
          },
        },
        {
          alert: 'certmanager_cert_not_ready',
          expr: |||
            max by (name, exported_namespace, condition) (
              certmanager_certificate_ready_status{condition!="True"} == 1
            )
          |||,
          'for': '10m',
          labels: {
            severity: 'critical',
          },
          annotations: {
            message: 'The cert `{{ $labels.name }}` is not ready to serve traffic.',
            impact: 'This certificate has not been ready to serve traffic for at least 10m. If the cert is being renewed or there is another valid cert, nginx _may_ be able to serve that instead.',
            action: 'Ensure cert-manager is configured correctly, no lets-encrypt rate limits are being hit. To break glass, buy a cert.',
            dashboard: $._config.grafanaExternalUrl + '/d/TvuRo2iMk/cert-manager',
          },
        },
        {
          alert: 'certmanager_cert_expiry_metric_missing',
          expr: 'absent(certmanager_certificate_expiration_timestamp_seconds)',
          'for': '10m',
          labels: {
            severity: 'critical',
          },
          annotations: {
            message: 'The metric used to observe cert-manager cert expiry is missing',
            impact: 'We are blind as to whether or not we can alert on certificates expiring',
            action: 'Assuming cert-manager is running, this is likely due to cert-manager not having permission to see certificate CRDs, a breaking change in metrics exposed, or some other misconfiguration.',
            dashboard: $._config.grafanaExternalUrl + '/d/TvuRo2iMk/cert-manager',
          },
        },
        {
          alert: 'certmanager_hitting_rate_limits',
          expr: |||
            sum by (host) (
              rate(certmanager_http_acme_client_request_count{status="429"}[5m])
            ) > 0
          |||,
          'for': '5m',
          labels: {
            severity: 'critical',
          },
          annotations: {
            message: 'Cert manager hitting LetsEncrypt rate limits',
            impact: 'Depending on the rate limit, cert-manager may be unable to generate certificates for up to a week.',
            action: 'Nothing we can really do in the short term. We can apply for a rate limit adjustment for the future, but it can take weeks to approve. Thoughts and prayers.',
            dashboard: $._config.grafanaExternalUrl + '/d/TvuRo2iMk/cert-manager',
            link_url: 'https://docs.google.com/forms/d/e/1FAIpQLSetFLqcyPrnnrom2Kw802ZjukDVex67dOM2g4O8jEbfWFs3dA/viewform',
            link_text: 'LetsEncrypt Rate Limit Request Form',
          },
        },
      ],
    }],
  },
}
