# One image serves both halves (--mode selects). The node half shells out to
# mkfs/blkid/resize2fs via k8s mount-utils, and to modprobe (kmod) / rdma
# (iproute2) to bring up the NVMe-oF fabric, so the runtime layer is debian
# with those tools — not distroless.
FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /greendot-csi ./cmd/greendot-csi

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    e2fsprogs xfsprogs util-linux mount ca-certificates kmod iproute2 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /greendot-csi /greendot-csi
ENTRYPOINT ["/greendot-csi"]
