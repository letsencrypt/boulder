FROM buildpack-deps:focal-scm

# Provided automatically by docker buildx.
ARG TARGETPLATFORM
ARG BUILDPLATFORM

ENV TARGETPLATFORM=$TARGETPLATFORM
ENV PATH /usr/local/go/bin:/usr/local/protoc/bin:$PATH

COPY requirements.txt /tmp/requirements.txt
COPY boulder.rsyslog.conf /etc/rsyslog.d/
COPY build.sh /tmp/build.sh
RUN /tmp/build.sh
# Note: This arg and env variable should only be set _after_ build.sh installs
# necessary apt packages. Otherwise, we will reinstall those apt packages for
# each Go version, rather than reusing a cached layer.
ARG GO_VERSION
ENV GO_VERSION=$GO_VERSION
COPY install-go.sh /tmp/install-go.sh
RUN /tmp/install-go.sh
RUN sed -i '/imklog/s/^/#/' /etc/rsyslog.conf
RUN sed -i '/$ActionFileDefaultTemplate/s/^/#/' /etc/rsyslog.conf
RUN sed -i '/$RepeatedMsgReduction on/s/^/#/' /etc/rsyslog.conf
