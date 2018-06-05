all: zlint

zlint: cmd/zlint/zlint
	cp cmd/zlint/zlint zlint

cmd/zlint/zlint:
	cd cmd/zlint && go build

clean:
	rm -f cmd/cmd/zlint zlint

test:
	GORACE=halt_on_error=1 go test -race ./...

.PHONY: clean cmd/zlint/zlint zlint test
