# This Makefile also tricks Travis into not running 'go get' for our
# build. See http://docs.travis-ci.com/user/languages/go/

OBJDIR = ./bin

OBJECTS = activity-monitor \
	admin-revoker \
	boulder \
	boulder-ca \
	boulder-ra \
	boulder-sa \
	boulder-va \
	boulder-wfe \
	ocsp-updater \
	ocsp-responder

# Build environment variables (referencing core/util.go)
BUILD_ID = $(shell git symbolic-ref --short HEAD 2>/dev/null) +$(shell git rev-parse --short HEAD)
BUILD_ID_VAR = github.com/letsencrypt/boulder/core.BuildID

BUILD_HOST = $(shell whoami)@$(shell hostname)
BUILD_HOST_VAR = github.com/letsencrypt/boulder/core.BuildHost

BUILD_TIME = $(shell date -u)
BUILD_TIME_VAR = github.com/letsencrypt/boulder/core.BuildTime

.PHONY: all build
all: build

build: $(OBJECTS)

pre:
	@mkdir -p $(OBJDIR)
	@echo [go] lib/github.com/mattn/go-sqlite3
	@go install ./Godeps/_workspace/src/github.com/mattn/go-sqlite3

# Compile each of the binaries
$(OBJECTS): pre
	@echo [go] bin/$@
	@go build -tags pkcs11 -o ./bin/$@ -ldflags \
		"-X $(BUILD_ID_VAR) '$(BUILD_ID)' -X $(BUILD_TIME_VAR) '$(BUILD_TIME)' \
		 -X $(BUILD_HOST_VAR) '$(BUILD_HOST)'" \
		cmd/$@/main.go

clean:
	rm -f $(OBJDIR)/*
	rmdir $(OBJDIR)
