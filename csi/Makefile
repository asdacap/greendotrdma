# The Go half of greendotrdma. `make proto` regenerates pkg/helperpb from the
# canonical ../crates/greendot-proto/proto/helper.proto (stubs are checked in;
# CI diffs them via `make proto && git diff --exit-code`).

GOFLAGS ?= -mod=mod

.PHONY: build test proto image sanity

build:
	go build ./...

test:
	go test ./...

proto:
	protoc --proto_path=../crates/greendot-proto/proto \
	  --go_out=pkg/helperpb --go_opt=paths=source_relative \
	  --go-grpc_out=pkg/helperpb --go-grpc_opt=paths=source_relative \
	  helper.proto

image:
	docker build -t greendot-csi:latest .

# csi-sanity against the controller backed by a stateful in-process fake
# helper. Node specs are skipped (they need real fabrics — the NixOS VM test
# covers that path); the spec skips are documented in sanity/sanity_test.go.
sanity:
	go test -tags sanity ./sanity -args \
	  -ginkgo.skip='Node Service|different source volume ID|should fail when the node does not exist'
