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

.PHONY: all build
all: build

build: $(OBJECTS)

pre:
	mkdir -p $(OBJDIR)
	go install ./Godeps/_workspace/src/github.com/mattn/go-sqlite3

# Compile each of the binaries
$(OBJECTS): pre
	go build -o ./bin/$@ cmd/$@/main.go

clean:
	rm -f $(OBJDIR)/*
	rmdir $(OBJDIR)