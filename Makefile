build:
	cd cmd/server | go build -o ./main . | ./main

lint:
	golangci-lint run

test:
	go test ./...

.PHONY: lint, build