# This Makefile also tricks Travis into not running 'go get' for our
# build. See http://docs.travis-ci.com/user/languages/go/

OBJDIR = ./bin

OBJECTS = activity-monitor \
	boulder \
	boulder-ca \
	boulder-ra \
	boulder-sa \
	boulder-va \
	boulder-wfe \
	ocsp-updater

REVID = $(shell git symbolic-ref --short HEAD):$(shell git rev-parse --short HEAD)
BUILD_ID_VAR = github.com/letsencrypt/boulder/core.BuildID

.PHONY: all build
all: build

build: $(OBJECTS)

pre:
	mkdir -p $(OBJDIR)
	go install ./Godeps/_workspace/src/github.com/mattn/go-sqlite3

# Compile each of the binaries
$(OBJECTS): pre
	go build -o ./bin/$@ -ldflags "-X $(BUILD_ID_VAR) $(REVID)" cmd/$@/main.go

clean:
	rm -f $(OBJDIR)/*
	rmdir $(OBJDIR)
