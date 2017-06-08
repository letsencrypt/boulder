# To minimize the fetching of various layers this image and tag should
# be used as the base of the bhsm container in boulder/docker-compose.yml
FROM letsencrypt/boulder-tools:2017-05-25

# Boulder exposes its web application at port TCP 4000
EXPOSE 4000 4002 4003 4430 8053 8055

ENV PATH /usr/local/go/bin:/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin/
ENV GOPATH /go

RUN adduser --disabled-password --gecos "" --home /go/src/github.com/letsencrypt/boulder -q buser
RUN chown -R buser /go/

WORKDIR /go/src/github.com/letsencrypt/boulder

RUN mkdir bin

RUN chown -R buser /go/

ENTRYPOINT [ "./test/entrypoint.sh" ]
