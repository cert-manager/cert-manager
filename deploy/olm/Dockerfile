FROM alpine:3.11 as chart-get

RUN apk add wget tar
RUN wget https://charts.jetstack.io/charts/cert-manager-v0.15.0-alpha.0.tgz
# TODO: add some kind of verification
RUN tar xzf cert-manager-v0.15.0-alpha.0.tgz

FROM quay.io/operator-framework/helm-operator:v0.15.1

### Required OpenShift Labels
LABEL name="cert-manager Operator" \
      vendor="Jetstack" \
      version="v0.15.0" \
      release="1" \
      summary="This is the cert-manager operator." \
      description="This operator will deploy cert-manager to the cluster."

# Required Licenses
ADD https://raw.githubusercontent.com/jetstack/cert-manager/master/LICENSES /licenses

COPY --from=chart-get /cert-manager/ ${HOME}/helm-charts/cert-manager
COPY watches.yaml ${HOME}/watches.yaml