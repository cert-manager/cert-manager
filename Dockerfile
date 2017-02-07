FROM alpine:3.5
RUN apk --update add ca-certificates && rm -rf /var/cache/apk/*
COPY _build/kube-lego /kube-lego
COPY README.md /README.md
CMD ["/kube-lego"]
ARG VCS_REF
LABEL org.label-schema.vcs-ref=$VCS_REF \
      org.label-schema.vcs-url="https://github.com/jetstack/kube-lego" \
      org.label-schema.license="Apache-2.0"
