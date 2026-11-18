.PHONY: build test lint run clean

build:
	go build -o bin/dockyard ./cmd/dockyard

test:
	go vet ./...
	go test -race -v ./...

run: build
	./bin/dockyard

clean:
	rm -rf bin/ coverage.out
