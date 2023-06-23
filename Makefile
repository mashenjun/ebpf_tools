CLANG ?= clang-14
STRIP ?= llvm-strip-14
OBJCOPY ?= llvm-objcopy-14
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)
REPODIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

IMAGE := ghcr.io/cilium/ebpf-builder
VERSION := 1666886595

container-build-bpf:
	docker run --rm \
		-v "${REPODIR}":/workspace -w /workspace \
		--env GOPROXY="https://goproxy.cn,direct" \
		--env CFLAGS="-fdebug-prefix-map=/ebpf=." \
		--env HOME="/tmp" \
		"${IMAGE}:${VERSION}" \
		make generate

container-shell:
	docker run --rm -it \
		-v "${REPODIR}":/workspace -w /workspace \
		--env GOPROXY="https://goproxy.cn,direct" \
		"${IMAGE}:${VERSION}"

generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate:
	go generate ./...

.PHONY: cgroup-finder
cgroup-finder:
	GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -o bin/cgroup-finder ./cgroup_finder
