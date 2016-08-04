#!/bin/bash
#
# Fetch dependencies of Boulder that are necessary for development or testing,
# and configure database and RabbitMQ.
#

set -ev

go get \
  bitbucket.org/liamstask/goose/cmd/goose \
  github.com/golang/lint/golint \
  github.com/golang/mock/mockgen \
  github.com/golang/protobuf/proto \
  github.com/golang/protobuf/protoc-gen-go \
  github.com/jsha/listenbuddy \
  github.com/kisielk/errcheck \
  github.com/mattn/goveralls \
  github.com/modocache/gover \
  github.com/tools/godep \
  golang.org/x/tools/cover \
  golang.org/x/tools/cmd/stringer &

# Create the database and roles
./test/create_db.sh &

(curl -sL https://github.com/google/protobuf/releases/download/v2.6.1/protobuf-2.6.1.tar.gz | \
 tar -xzv &&
 cd protobuf-2.6.1 && ./configure --prefix=$HOME && make && make install) &

# Set up rabbitmq exchange
go run cmd/rabbitmq-setup/main.go -server amqp://boulder-rabbitmq &

# Wait for all the background commands to finish.
wait
