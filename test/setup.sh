#!/bin/bash
#
# Fetch dependencies of Boulderthat are necessary for development or testing,
# and configure database and RabbitMQ.
#

go get \
  golang.org/x/tools/cmd/vet \
  golang.org/x/tools/cmd/cover \
  github.com/golang/lint/golint \
  github.com/mattn/goveralls \
  github.com/modocache/gover \
  github.com/jcjones/github-pr-status \
  github.com/jsha/listenbuddy &

if [ $(uname) == "Darwin" ]; then
  UNZIP="gunzip -c"
else
  UNZIP="zcat"
fi

(wget https://github.com/jsha/boulder-tools/raw/master/goose.gz &&
 mkdir -p $GOPATH/bin &&
 $UNZIP goose.gz > $GOPATH/bin/goose &&
 chmod +x $GOPATH/bin/goose &&
 ./test/create_db.sh) &

# Set up rabbitmq exchange and activity monitor queue
go run cmd/rabbitmq-setup/main.go -server amqp://localhost &

# Wait for all the background commands to finish.
wait
