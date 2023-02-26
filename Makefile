build:
	go build -o ./cmd/server/main ./cmd/server && ./cmd/server/main

lint:
	golangci-lint run

test:
	go test ./...

.PHONY: lint, test, build