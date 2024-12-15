FROM golang:1.23.4 AS build

WORKDIR /app

COPY go.mod go.sum vendor ./

COPY . .

RUN go build -o /bin/ct-test-srv ./test/ct-test-srv/main.go

FROM ubuntu:24.04

COPY --from=build /bin/ct-test-srv /bin/ct-test-srv

COPY test/ct-test-srv/ct-test-srv.json /etc/ct-test-srv.json

ENTRYPOINT ["/bin/ct-test-srv"]

CMD ["-config", "/etc/ct-test-srv.json"]
