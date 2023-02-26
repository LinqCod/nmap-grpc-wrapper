proto:
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative ./pb/*.proto

build:
	 make proto && go mod tidy && go build -o ./cmd/server/main ./cmd/server && ./cmd/server/main

lint:
	golangci-lint run

test:
	go test ./...

.PHONY: lint, test, build, proto