
.PHONY: test examples clean test_full pebble pebble_setup pebble_start pebble_wait pebble_stop boulder boulder_setup boulder_start boulder_stop


GOPATH ?= $(HOME)/go
BOULDER_PATH ?= $(GOPATH)/src/github.com/letsencrypt/boulder
PEBBLE_PATH ?= $(GOPATH)/src/github.com/letsencrypt/pebble
TEST_PATH ?= github.com/eggsampler/acme/v3


# tests the code against a running ca instance
test:
	-go clean -testcache
	go test -v -race -coverprofile=coverage.out -covermode=atomic $(TEST_PATH)

examples:
	go build -o /dev/null examples/certbot/certbot.go
	go build -o /dev/null examples/autocert/autocert.go
	go build -o /dev/null examples/zerossl/zerossl.go

clean:
	rm -f coverage.out

test_full: clean examples pebble pebble_stop boulder boulder_stop


pebble: pebble_setup pebble_start pebble_wait test pebble_stop

pebble_setup:
	mkdir -p $(PEBBLE_PATH)
	-git clone --depth 1 https://github.com/letsencrypt/pebble.git $(PEBBLE_PATH)
	(cd $(PEBBLE_PATH); git checkout -f master && git reset --hard HEAD && git pull -q)
	make pebble_stop

# runs an instance of pebble using docker
pebble_start:
	docker-compose -f $(PEBBLE_PATH)/docker-compose.yml up -d

# waits until pebble responds
pebble_wait:
	while ! wget --delete-after -q --no-check-certificate "https://localhost:14000/dir" ; do sleep 1 ; done

# stops the running pebble instance
pebble_stop:
	docker-compose -f $(PEBBLE_PATH)/docker-compose.yml down


boulder: boulder_setup boulder_start boulder_wait test boulder_stop

# NB: this edits docker-compose.yml
boulder_setup:
	mkdir -p $(BOULDER_PATH)
	-git clone --depth 1 https://github.com/letsencrypt/boulder.git $(BOULDER_PATH)
	(cd $(BOULDER_PATH); git checkout -f main && git reset --hard HEAD && git pull -q)
	make boulder_stop
	rm -rf $(BOULDER_PATH)/temp

# runs an instance of boulder
boulder_start:
	docker-compose -f $(BOULDER_PATH)/docker-compose.yml -f $(BOULDER_PATH)/docker-compose.next.yml -f docker-compose.boulder-temp.yml up -d

# waits until boulder responds
boulder_wait:
	while ! wget --delete-after -q --no-check-certificate "http://localhost:4001/directory" ; do sleep 1 ; done

# stops the running docker instance
boulder_stop:
	docker-compose -f $(BOULDER_PATH)/docker-compose.yml -f $(BOULDER_PATH)/docker-compose.next.yml -f docker-compose.boulder-temp.yml down
