FROM scratch
ADD dist/ca-certificates.tar.xz /usr/share/ca-certificates
COPY _build/kube-lego /kube-lego
CMD ["/kube-lego"]
