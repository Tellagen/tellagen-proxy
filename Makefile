VERSION ?= dev
IMAGE   ?= tellagen-proxy

.PHONY: build test lint fmt vet docker integration tidy check

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o bin/tellagen-proxy ./cmd/tellagen-proxy

test:
	go test -race ./...

vet:
	go vet ./...

lint:
	golangci-lint run ./...

fmt:
	gofmt -w .

# Needs Docker: the contract tests start Grafana, Prometheus and Loki.
integration:
	go test -tags integration -timeout 20m ./internal/executor/...

tidy:
	go mod tidy

docker:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION) .

check: vet lint test
