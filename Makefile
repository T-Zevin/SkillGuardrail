.PHONY: build test check clean

build:
	mkdir -p bin
	go build -trimpath -o bin/skillguardrail ./cmd/skillguardrail

test:
	go test ./...

check:
	test -z "$$(gofmt -l cmd internal)"
	go vet ./...
	go test -race ./...

clean:
	go clean
	rm -rf bin dist coverage.out
