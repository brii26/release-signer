VERSION ?= dev
BIN := bin/release-signer

.PHONY: build test vet fmt-check scenarios sbom-test docs-api docs interop bench docker

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

sbom-test:
	RESULTS_DIR=results/sbom go test ./test/sbom -count=1 -v

docs-api:
	go run github.com/princjef/gomarkdoc/cmd/gomarkdoc@v1.1.0 --output 'docs/api/{{.Dir}}.md' ./pkg/...

docs: docs-api
	mkdocs build --strict

interop:
	sh test/interop/run.sh

bench:
	sh bench/gen.sh
	go run ./bench

docker:
	docker build --platform linux/amd64 --build-arg VERSION=$(VERSION) -t release-signer:$(VERSION) .
