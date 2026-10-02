lint:
	golangci-lint run

snapshot:
	goreleaser --rm-dist --snapshot

APP := syno-cli
PACKAGE := ./cmd/syno-cli
DIST := dist
LDFLAGS := -s -w

# Cross-build targets. linux/amd64 is the Synology x86_64 target.
PLATFORMS := \
	linux/amd64 linux/386 linux/arm64 linux/arm \
	darwin/amd64 darwin/arm64 \
	windows/amd64 windows/386 windows/arm64

.PHONY: build build-all linux mac windows local clean-dist

# Build one target. Examples:
#   make build GOOS=linux GOARCH=amd64
#   make build GOOS=windows GOARCH=amd64
build:
	@test -n "$(GOOS)" || (echo "GOOS is required, e.g. make build GOOS=linux GOARCH=amd64" && exit 1)
	@test -n "$(GOARCH)" || (echo "GOARCH is required, e.g. make build GOOS=linux GOARCH=amd64" && exit 1)
	@mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/$(APP)-$(GOOS)-$(GOARCH)$(if $(filter windows,$(GOOS)),.exe,) $(PACKAGE)

build-all:
	@set -e; for platform in $(PLATFORMS); do \
		GOOS=$${platform%/*} GOARCH=$${platform#*/} $(MAKE) --no-print-directory build; \
	done

linux:
	@set -e; for arch in amd64 386 arm64 arm; do GOOS=linux GOARCH=$$arch $(MAKE) --no-print-directory build; done

mac:
	@set -e; for arch in amd64 arm64; do GOOS=darwin GOARCH=$$arch $(MAKE) --no-print-directory build; done

windows:
	@set -e; for arch in amd64 386 arm64; do GOOS=windows GOARCH=$$arch $(MAKE) --no-print-directory build; done

local:
	$(MAKE) --no-print-directory build GOOS=$(if $(GOOS),$(GOOS),$(shell go env GOOS)) GOARCH=$(if $(GOARCH),$(GOARCH),$(shell go env GOARCH))
	cp Dockerfile.release $(DIST)/Dockerfile
	cd $(DIST) && docker build -t syno-cli .

clean-dist:
	rm -rf $(DIST)

# Generate test certs
# https://github.com/FiloSottile/mkcert
gen-certs: test-data
	mkdir -p test-data
	cd test-data && CAROOT=. go run filippo.io/mkcert@v1.4.4 example.com


# Generate go code
generate:
	go generate ./...

test:
	go test -v ./...

.PHONY: generate test
