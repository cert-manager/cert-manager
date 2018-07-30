FROM alpine:3.6

ARG ARCH

RUN apk add --no-cache ca-certificates && \
  addgroup -S certmanager && adduser -S -G certmanager certmanager

ADD cert-manager-ingress-shim_linux_$ARCH /usr/bin/ingress-shim

USER certmanager

ENTRYPOINT ["/usr/bin/ingress-shim"]
ARG VCS_REF
LABEL org.label-schema.vcs-ref=$VCS_REF \
      org.label-schema.vcs-url="https://github.com/jetstack/cert-manager" \
      org.label-schema.license="Apache-2.0"
