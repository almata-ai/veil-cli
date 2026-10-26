VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo 0.1.0)
LDFLAGS := -s -w -X main.version=$(VERSION)
PLATFORMS := darwin/arm64 darwin/amd64 linux/amd64 linux/arm64 windows/amd64

.PHONY: build test fmt vet dist clean
build:
	go build -ldflags "$(LDFLAGS)" -o veil .

test:
	go test ./...

fmt:
	gofmt -w .

vet:
	go vet ./...

# Cross-compile release binaries into dist/.
dist: clean
	@mkdir -p dist
	@for p in $(PLATFORMS); do \
	  os=$${p%/*}; arch=$${p#*/}; ext=; [ "$$os" = windows ] && ext=.exe; \
	  out=dist/veil-$(VERSION)-$$os-$$arch$$ext; \
	  echo "→ $$out"; \
	  GOOS=$$os GOARCH=$$arch go build -ldflags "$(LDFLAGS)" -o $$out . ; \
	done

clean:
	rm -rf dist veil
