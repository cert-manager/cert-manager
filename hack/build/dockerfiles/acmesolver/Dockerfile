FROM alpine:3.6

ARG ARCH

RUN apk add --no-cache ca-certificates && \
    adduser -S -u 100 acmesolver

ADD cert-manager-acmesolver_linux_$ARCH /usr/bin/acmesolver

USER 100
ENTRYPOINT ["/usr/bin/acmesolver"]
ARG VCS_REF
LABEL org.label-schema.vcs-ref=$VCS_REF \
      org.label-schema.vcs-url="https://github.com/jetstack/cert-manager" \
      org.label-schema.license="Apache-2.0"
