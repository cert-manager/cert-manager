FROM scratch
COPY _build/kube-lego /kube-lego
CMD ["/kube-lego"]
