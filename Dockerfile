FROM scratch
ADD dist/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY _build/kube-lego /kube-lego
COPY README.md /README.md
CMD ["/kube-lego"]
