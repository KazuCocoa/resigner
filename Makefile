.PHONY: all ci default clean test compress

GIT_COMMIT  := $(shell git describe --always --long --abbrev=12 --dirty)
GOFLAGS     ?= -trimpath -ldflags="-s -w -X main.VCSRevision=$(GIT_COMMIT)"
NATDIST     := $(shell go env GOHOSTOS GOHOSTARCH | paste -sd- -)

CGO_CFLAGS  := $(shell go env CGO_CFLAGS) -mmacos-version-min=10.15
CGO_LDFLAGS := $(shell go env CGO_LDFLAGS) -mmacos-version-min=10.15

SOURCES := $(shell find . -path ./vendor -prune -o -name '*.go' -print) go.mod go.sum

ARCHIVES := \
	build/darwin-amd64.tar.gz \
	build/darwin-arm64.tar.gz \
	build/linux-386.tar.gz \
	build/linux-amd64.tar.gz \
	build/windows-386.zip \
	build/windows-amd64.zip

default: resigner

all: \
	build/darwin-amd64/resigner \
	build/darwin-arm64/resigner \
	build/linux-386/resigner \
	build/linux-amd64/resigner \
	build/windows-386/resigner.exe \
	build/windows-amd64/resigner.exe

ci: all

compress: all $(ARCHIVES)

test:
	go test ./...

clean:
	rm -rf build

resigner: build/$(NATDIST)/resigner
	mkdir -p $(@D)
	cp "$<" "$@"

build/darwin-%/resigner: $(SOURCES)
	mkdir -p $(@D)
	GOOS=darwin GOARCH=$* CGO_ENABLED=1 \
	  CGO_CFLAGS="$(CGO_CFLAGS)" CGO_LDFLAGS="$(CGO_LDFLAGS)" \
	  go build $(GOFLAGS) -o "$@" ./cmd/resigner

build/linux-%/resigner: $(SOURCES)
	mkdir -p $(@D)
	GOOS=linux GOARCH=$* CGO_ENABLED=0 go build $(GOFLAGS) -o "$@" ./cmd/resigner

build/windows-%/resigner: $(SOURCES)
	mkdir -p $(@D)
	GOOS=windows GOARCH=$* CGO_ENABLED=0 go build $(GOFLAGS) -o "$@" ./cmd/resigner

build/windows-%/resigner.exe: build/windows-%/resigner
	cp "$<" "$@"

build/darwin-%.tar.gz: build/darwin-%/resigner
	tar -C build -czf "$@" "darwin-$*"

build/linux-%.tar.gz: build/linux-%/resigner
	tar -C build -czf "$@" "linux-$*"

build/windows-%.zip: build/windows-%/resigner.exe
	cd build && zip -rq "windows-$*.zip" "windows-$*"
