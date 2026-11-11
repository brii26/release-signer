VERSION ?= dev
BIN := bin/release-signer

.PHONY: build test vet fmt-check scenarios interop bench docker

build:
	go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o $(BIN) ./cmd/release-signer

test:
	go test -race ./...

vet:
	go vet ./...

fmt-check:
	@test -z "$$(gofmt -l .)" || (gofmt -l .; exit 1)

scenarios:
	RESULTS_DIR=results/scenarios go test ./test/e2e -run TestScenarios -v

interop:
	sh test/interop/run.sh

bench:
	go run ./bench

docker:
	docker build --platform linux/amd64 --build-arg VERSION=$(VERSION) -t release-signer:$(VERSION) .
