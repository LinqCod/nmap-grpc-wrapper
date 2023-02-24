build:
	cd cmd/server | go build -o ./main . | ./main

lint:
	golangci-lint run

.PHONY: lint, build