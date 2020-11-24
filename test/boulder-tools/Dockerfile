FROM buildpack-deps:buster-scm
ARG GO_VERSION

# Copied from https://github.com/docker-library/golang/blob/master/Dockerfile-debian.template
ENV GOPATH /go
ENV PATH $GOPATH/bin:/usr/local/go/bin:/usr/local/protoc/bin:$PATH
RUN mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH"
WORKDIR $GOPATH

RUN wget -O go.tgz "https://dl.google.com/go/go${GO_VERSION}.linux-amd64.tar.gz" && tar -C /usr/local -xzf go.tgz && rm go.tgz;
COPY requirements.txt /tmp/requirements.txt
COPY boulder.rsyslog.conf /etc/rsyslog.d/
COPY build.sh /tmp/build.sh
RUN /tmp/build.sh
