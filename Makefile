VERSION       ?= 0.0.0-dev
# public release key from `limdm-server keygen`; empty disables agent self update
UPDATE_PUBKEY ?=
PKG           := github.com/maltekiefer/limdm
LDFLAGS       := -s -w -X $(PKG)/internal/agent.Version=$(VERSION) -X $(PKG)/internal/agent.UpdatePubKey=$(UPDATE_PUBKEY)
export CGO_ENABLED=0

.PHONY: build test lint integration snapshot clean

build:
	for arch in amd64 arm64; do \
		GOOS=linux GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" -o dist/limdm-agent-linux-$$arch ./cmd/limdm-agent; \
		GOOS=linux GOARCH=$$arch go build -trimpath -ldflags "-s -w -X github.com/maltekiefer/limdm/internal/server.Version=$(VERSION) -X github.com/maltekiefer/limdm/internal/server.ReleasePubKey=$(UPDATE_PUBKEY)" -o dist/limdm-server-linux-$$arch ./cmd/limdm-server; \
	done

test:
	go vet ./...
	go test ./...

lint:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0 run ./...

# needs a disposable PostgreSQL, the public schema is wiped
integration:
	LIMDM_TEST_DATABASE_URL=$(DB) go test -count=1 -run TestIntegration ./internal/server

# local deb/rpm/tar.gz build without publishing
snapshot:
	go run github.com/goreleaser/goreleaser/v2@v2.20.3 release --snapshot --clean --skip=sbom

clean:
	rm -rf dist
