
.PHONY: test examples clean test_full pebble pebble_setup pebble_start pebble_wait pebble_stop boulder boulder_setup boulder_start boulder_stop

# some variables for path injection, if already set will not override
GOPATH ?= $(HOME)/go
BOULDER_PATH ?= $(GOPATH)/src/github.com/letsencrypt/boulder
PEBBLE_PATH ?= $(GOPATH)/src/github.com/letsencrypt/pebble
TEST_PATH ?= github.com/eggsampler/acme/v3
CLIENT ?= unknown
DOCKER_COMPOSE ?= docker compose

# boulder-tools:latest isn't published, so use the tags boulder's own CI pins
# Shell-expanded per recipe: the checkout doesn't exist when make parses this
BOULDER_CI_YML = $(BOULDER_PATH)/.github/workflows/boulder-ci.yml
BOULDER_TAGS = \
	BOULDER_TOOLS_TAG=$$(awk '/^ *BOULDER_TOOLS_TAG: *$$/{getline; sub(/^ *- */,""); print; exit}' $(BOULDER_CI_YML)) \
	BOULDER_VTCOMBOSERVER_TAG=$$(awk '/^ *BOULDER_VTCOMBOSERVER_TAG: *[^ ]/{sub(/^[^:]*: */,""); print; exit}' $(BOULDER_CI_YML))


# tests the code against an already running ca instance
# to actually do a test against pebble or boulder, including , see the 'pebble' or 'boulder' targets
test:
	-go clean -testcache
	CGO_ENABLED=1 go test -v -race -coverprofile=coverage-$(CLIENT).out -covermode=atomic $(TEST_PATH)

examples:
	go build -o /dev/null examples/certbot/certbot.go
	go build -o /dev/null examples/autocert/autocert.go
	go build -o /dev/null examples/zerossl/zerossl.go
	go build -o /dev/null examples/ari/renewalinfo.go

clean:
	rm -f coverage*.out

test_full: clean examples pebble pebble_stop boulder boulder_stop


# sets up & runs pebble (in docker), tests, then stops pebble
pebble: CLIENT = pebble
pebble: pebble_setup pebble_start pebble_wait test pebble_stop

pebble_setup:
	CLIENT=pebble
	mkdir -p $(PEBBLE_PATH)
	-git clone --depth 1 https://github.com/letsencrypt/pebble.git $(PEBBLE_PATH)
	(cd $(PEBBLE_PATH); git checkout -f main && git reset --hard HEAD && git pull -q)
	make pebble_stop

# runs an instance of pebble using docker
pebble_start:
	$(DOCKER_COMPOSE) -f $(PEBBLE_PATH)/docker-compose.yml up -d

# waits until pebble responds
pebble_wait:
	while ! wget --delete-after -q --no-check-certificate "https://localhost:14000/dir" ; do sleep 1 ; done

# stops the running pebble instance
pebble_stop:
	$(DOCKER_COMPOSE) -f $(PEBBLE_PATH)/docker-compose.yml down


# sets up & runs boulder (in docker), tests, then stops boulder
boulder: CLIENT = boulder
boulder: boulder_setup boulder_start boulder_wait test boulder_stop

# NB: this edits docker-compose.yml
# The test/certs wipe is needed because generate.sh skips certs that already
# exist, so stale state from an older boulder revision starves new services.
boulder_setup:
	mkdir -p $(BOULDER_PATH)
	-git clone --depth 1 https://github.com/letsencrypt/boulder.git $(BOULDER_PATH)
	(cd $(BOULDER_PATH); git checkout -f main && git reset --hard HEAD && git pull -q && git clean -qfdx test/certs/)
	make boulder_stop
	(cd $(BOULDER_PATH); $(BOULDER_TAGS) docker compose run --rm bsetup)

# runs an instance of boulder
boulder_start:
	$(BOULDER_TAGS) $(DOCKER_COMPOSE) -f $(BOULDER_PATH)/docker-compose.yml -f $(BOULDER_PATH)/docker-compose.next.yml -f docker-compose.boulder-temp.yml up -d

# waits until boulder responds
boulder_wait:
	while ! wget --delete-after -q --no-check-certificate "http://localhost:4001/directory" ; do sleep 1 ; done

# stops the running docker instance
boulder_stop:
	$(BOULDER_TAGS) $(DOCKER_COMPOSE) -f $(BOULDER_PATH)/docker-compose.yml -f $(BOULDER_PATH)/docker-compose.next.yml -f docker-compose.boulder-temp.yml down
