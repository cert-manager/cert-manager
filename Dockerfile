FROM alpine:3.6

RUN apk add --no-cache ca-certificates

ADD _build/cert-manager-linux-amd64 /usr/bin/cert-manager

CMD ["/usr/bin/cert-manager"]
