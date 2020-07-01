# builder image
FROM oraclelinux:7.8 as cert_base

RUN yum update -y \
    && yum-config-manager --save --setopt=ol7_ociyum_config.skip_if_unavailable=true \
    && yum install -y oracle-golang-release-el7 \
    && yum-config-manager --enable ol7_developer_golang113 \
    && yum-config-manager --add-repo http://yum.oracle.com/repo/OracleLinux/OL7/developer/golang113/x86_64 \
    && yum install -y git gcc make golang-1.13.3-1.el7.x86_64 \
    && yum -y install yum-utils unzip \
    && yum -y install which patch \
    && yum -y install java-11-openjdk-devel \
    && yum -y install gcc-c++ \
    && yum clean all \
    && go version

# Compile to /usr/bin
ENV GOBIN=/usr/bin

# Set go path
ENV GOPATH=/go

# Bazel
RUN curl -LO https://github.com/bazelbuild/bazel/releases/download/3.3.0/bazel-3.3.0-installer-linux-x86_64.sh \
    && chmod +x bazel-3.3.0-installer-linux-x86_64.sh
RUN ./bazel-3.3.0-installer-linux-x86_64.sh

WORKDIR /root/src/webhook

RUN mkdir -p /root/src/webhook
COPY . /root/src/webhook/.

RUN make webhook

FROM oraclelinux:7-slim

COPY --from=cert_base /root/src/webhook/bazel-bin/cmd/webhook/linux_amd64_pure_stripped/webhook.runfiles/com_github_jetstack_cert_manager/cmd/webhook/linux_amd64_pure_stripped/webhook /usr/bin/webhook

RUN ls -la /usr/bin/webhook

USER nobody

ENTRYPOINT ["/usr/bin/webhook"]
