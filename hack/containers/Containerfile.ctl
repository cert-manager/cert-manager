ARG BASE_IMAGE

FROM $BASE_IMAGE

USER 1000

COPY ctl /app/cmd/ctl/ctl
COPY cert-manager.license /licenses/LICENSE
COPY cert-manager.licenses_notice /licenses/LICENSES

ENTRYPOINT ["/app/cmd/ctl/ctl"]

# vim: syntax=dockerfile
